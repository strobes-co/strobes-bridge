"""Persistent, reusable shell sessions on the bridge.

A *session* is a long-lived interactive shell that RETAINS state — working
directory, environment, exported credentials, an established `sudo`/`su`, a
running `ssh`/`nc` — across commands. Agents create a session once and reuse it,
instead of every command being a fresh, stateless subprocess.

Commands run request/response over the persistent shell: we write the command
followed by a unique END-MARKER that echoes the exit code, then read stdout until
the marker appears, returning the captured output + exit code. State persists
between calls because it is the SAME shell process.

Sessions are enumerated, created and deleted by id, so the platform can offer a
sessions view (list / create / delete) and agents can pick which established
foothold to run the next command in.

POSIX (Linux/macOS) via a PTY-backed shell. Windows sessions are a follow-up.
"""
import os
import re
import select
import shlex
import subprocess
import threading
import time
import uuid

# strip ANSI CSI (\e[...m, \e[?2004h) + OSC title/hyperlink (\e]...BEL) sequences
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[=>]")


def _strip_ansi(s):
    return _ANSI.sub("", s)


def _pick_shell(shell):
    """Prefer a clean bash (no rc/profile, plain prompt) so the transcript is
    parseable — the user's login shell (zsh with a themed prompt) pollutes output
    with escape codes and a multi-line prompt."""
    if shell:
        return [shell, "-i"]
    for b in ("/bin/bash", "/usr/bin/bash"):
        if os.path.exists(b):
            return [b, "--noprofile", "--norc", "-i"]
    return [os.environ.get("SHELL") or "/bin/sh", "-i"]

_IS_POSIX = os.name == "posix"
_SESSIONS = {}          # session_id -> _Session
_LOCK = threading.Lock()
_MAX_SESSIONS = 64
_IDLE_TTL = 60 * 60     # reap sessions idle > 1h


class _Session:
    def __init__(self, shell=None, cwd=None, label=""):
        import pty
        self.id = uuid.uuid4().hex[:12]
        self.label = label or ""
        self.shell = shell or os.environ.get("SHELL") or "/bin/bash"
        self.cwd = cwd or os.getcwd()
        self.created_at = time.time()
        self.last_used = self.created_at
        self.commands = 0
        self._lock = threading.Lock()
        self._master, slave = pty.openpty()
        argv = _pick_shell(shell)
        self.shell = argv[0]
        env = {**os.environ, "PS1": "", "PS2": "", "PROMPT": "", "TERM": "dumb",
               "PAGER": "cat", "GIT_PAGER": "cat"}
        # Confine the session's shell, not each command typed into it: the
        # sandbox and the proxy environment are inherited by everything the
        # session goes on to run, for as long as it lives.
        from strobes_shell_agent import sandbox as _sandbox
        argv, env = _sandbox.confine(" ".join(shlex.quote(a) for a in argv), env)
        self.proc = subprocess.Popen(
            argv, stdin=slave, stdout=slave, stderr=slave,
            cwd=self.cwd, start_new_session=True, env=env, close_fds=True)
        os.close(slave)
        # quiet the shell: empty prompt + no bracketed-paste markers, then drain
        try:
            os.write(self._master, b"PS1='' PS2='' PROMPT_COMMAND=''; "
                                   b"bind 'set enable-bracketed-paste off' 2>/dev/null; "
                                   b"stty -echo 2>/dev/null\n")
        except OSError:
            pass
        self._read_until("__STROBES_INIT_NEVER__", 0.6)   # drain banner/prompt

    def _read_until(self, marker, timeout):
        buf = b""
        deadline = time.time() + timeout
        mb = marker.encode()
        while time.time() < deadline:
            if self.proc.poll() is not None:
                try:
                    buf += os.read(self._master, 65536)
                except OSError:
                    pass
                break
            r, _, _ = select.select([self._master], [], [], 0.2)
            if r:
                try:
                    chunk = os.read(self._master, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
                if mb in buf:
                    break
        return buf

    def exec(self, command, timeout=60):
        with self._lock:
            self.last_used = time.time()
            self.commands += 1
            marker = "__STROBES_END_%s__" % uuid.uuid4().hex[:10]
            # run the command, then emit MARKER:<exit-code> on its own line
            payload = "%s\nprintf '\\n%s:%%s\\n' \"$?\"\n" % (command, marker)
            try:
                os.write(self._master, payload.encode())
            except OSError as e:
                return {"success": False, "error": "session write failed: %s" % e,
                        "session_dead": True}
            raw = self._read_until("%s:" % marker, timeout).decode("utf-8", "replace")
            return _parse_marked(raw, marker, command)

    def alive(self):
        return self.proc.poll() is None

    def kill(self):
        try:
            import signal
            os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass
        try:
            os.close(self._master)
        except Exception:
            pass

    def info(self):
        return {"session_id": self.id, "label": self.label, "shell": self.shell,
                "cwd": self.cwd, "created_at": self.created_at,
                "last_used": self.last_used, "commands": self.commands,
                "alive": self.alive()}


def _parse_marked(raw, marker, command):
    """Extract command output + exit code from the PTY transcript. The transcript
    echoes what we typed and ends with '<marker>:<code>'. We strip ANSI/OSC
    escapes, take everything between the echoed command and the marker, and drop
    the echoed command + the printf helper lines."""
    timed_out = (marker + ":") not in raw
    raw = _strip_ansi(raw).replace("\r", "")
    exit_code = None
    idx = raw.rfind(marker + ":")
    if idx != -1:
        tail = raw[idx + len(marker) + 1:]
        m = re.match(r"\s*(\d+)", tail)
        exit_code = int(m.group(1)) if m else None
        body = raw[:idx]
    else:
        body = raw
    cmd_first = (command.split("\n")[0]).strip()
    cleaned = []
    for ln in body.split("\n"):
        s = ln.strip()
        if not s:
            cleaned.append(ln)
            continue
        if s == cmd_first or s.startswith("printf ") or marker in s:
            continue
        cleaned.append(ln)
    output = "\n".join(cleaned).strip("\n")
    return {"success": (exit_code == 0) if exit_code is not None else (not timed_out),
            "output": output, "exit_code": exit_code, "timed_out": timed_out}


def _reap_idle():
    now = time.time()
    for sid, s in list(_SESSIONS.items()):
        if not s.alive() or (now - s.last_used) > _IDLE_TTL:
            try:
                s.kill()
            except Exception:
                pass
            _SESSIONS.pop(sid, None)


# ---- public API (called from the command dispatcher) ----------------------

def session_create(cwd=None, label="", shell=None):
    if not _IS_POSIX:
        return {"success": False, "error": "persistent sessions are POSIX-only for now"}
    with _LOCK:
        _reap_idle()
        if len(_SESSIONS) >= _MAX_SESSIONS:
            return {"success": False, "error": "session limit reached (%d)" % _MAX_SESSIONS}
        try:
            s = _Session(shell=shell, cwd=cwd, label=label)
        except Exception as e:  # noqa: BLE001
            return {"success": False, "error": "spawn failed: %s" % e}
        _SESSIONS[s.id] = s
        return {"success": True, **s.info()}


def session_list():
    with _LOCK:
        _reap_idle()
        return {"success": True, "sessions": [s.info() for s in _SESSIONS.values()]}


def session_exec(session_id, command, timeout=60):
    s = _SESSIONS.get(session_id)
    if s is None:
        return {"success": False, "error": "no such session: %s" % session_id}
    if not s.alive():
        _SESSIONS.pop(session_id, None)
        return {"success": False, "error": "session is dead", "session_dead": True}
    return s.exec(command or "", timeout=timeout)


def session_delete(session_id):
    with _LOCK:
        s = _SESSIONS.pop(session_id, None)
        if s is None:
            return {"success": False, "error": "no such session: %s" % session_id}
        s.kill()
        return {"success": True, "session_id": session_id, "deleted": True}
