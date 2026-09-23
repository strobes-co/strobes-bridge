"""Command execution and file I/O for the shell bridge agent."""

import asyncio
import base64
import hashlib
import os
import platform
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error
from urllib.parse import urlparse
from pathlib import Path
from typing import Optional

from strobes_shell_agent import pack

IS_WINDOWS = sys.platform == "win32"


# --------------------------------------------------------------------------- #
# Windows shell compatibility
#
# Commands reaching this daemon (from the platform's shell-precheck service,
# skill injection, etc.) are generated assuming a POSIX shell: `/dev/null`,
# single-quoted `-c '...'` python snippets, bare `python3`/`pip3`. cmd.exe (what
# asyncio.create_subprocess_shell uses on Windows) understands none of that:
#
#   - `/dev/null` is just a literal path, not a null device.
#   - single quotes are NOT a grouping character to cmd.exe — it only
#     recognises `"`. `python3 -c 'from x import y'` gets word-split into
#     separate argv tokens on every space, so `-c` only ever receives the
#     first token (`'from`) — Python then fails with "unterminated string
#     literal" on that lone fragment. This exact signature was observed on
#     every real Windows bridge sampled (2026-07 through 2026-09).
#   - `python3`/`pip3` don't exist as commands on Windows (no python3.exe),
#     so they either 404 outright or, worse, resolve to the Microsoft Store's
#     python.exe app-execution-alias stub, which prints an installer prompt
#     instead of running anything.
#
# Rather than trust every call site across the platform to know this, the
# bridge — the thing that actually knows it's running on Windows — rewrites
# recognised POSIX shapes into a form cmd.exe executes correctly, and always
# routes `python`/`pip` invocations through the sandbox pack's own bundled
# interpreter (pack.pack_python()) instead of whatever PATH happens to
# resolve, since that's the one interpreter guaranteed to actually be there.
# Unrecognised shapes (notably the PowerShell-wrapped commands the platform's
# Windows-aware code paths already send) are left untouched.
# --------------------------------------------------------------------------- #

_DEV_NULL_RE = re.compile(r"(?<![\w./\\-])/dev/null\b")

# `(python3|python) -c '<code>'` — a POSIX single-quoted string is fully
# literal (no escape processing at all, not even `\'`), so the code is simply
# everything up to the next `'`. Deliberately does NOT also match a
# double-quoted `-c` form: cmd.exe already groups double-quoted arguments
# correctly, so only the single-quoted shape (the one that gets word-split)
# needs rewriting.
_PY_DASH_C_SINGLE_RE = re.compile(r"\b(python3?)\b(\s+)-c(\s+)'([^']*)'")

# Bare interpreter invocation: the word python3/python/pip3/pip, not part of
# a longer identifier and not already an absolute path someone constructed.
_PY_TOKEN_RE = re.compile(r"(?<![\w./\\-])(python3?|pip3?)(?=\s|$)")


def _win_resolve_python() -> Optional[str]:
    """Absolute path to a real interpreter to substitute for bare `python`/
    `python3` on Windows. Prefers the sandbox pack's bundled standalone
    interpreter — it's guaranteed present and importable, unlike anything
    PATH might resolve to (a real install, nothing, or the Store stub).
    Falls back to whatever `python`/`py` resolves to on PATH if there's no
    pack, so this still degrades to the pre-pack behaviour rather than
    breaking a host with a normal Python install and no pack."""
    py = pack.pack_python()
    if py:
        return str(py)
    env_path = pack.build_env().get("PATH")
    for name in ("python", "py"):
        found = shutil.which(name, path=env_path)
        if found:
            return found
    return None


def _win_extract_dash_c(command: str) -> str:
    """Rewrite every single-quoted ``<py> -c '<code>'`` into ``<py>
    <tempfile>``, sidestepping cmd.exe's single-quote word-splitting
    entirely instead of trying to re-quote for it. The temp .py file is left
    behind (same tradeoff the platform's own Windows SDK bootstrap already
    makes for its probe/boot scripts) — negligible litter in %TEMP%, and
    deleting it would need a second round-trip this command doesn't have."""

    def _sub(match: "re.Match[str]") -> str:
        code = match.group(4)
        fd, path = tempfile.mkstemp(suffix=".py", prefix="strobes_c_")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(code)
        return f"{match.group(1)}{match.group(2)}{path}"

    return _PY_DASH_C_SINGLE_RE.sub(_sub, command)


def _win_resolve_interpreter_tokens(command: str, python_path: str) -> str:
    """Replace bare `python3`/`python`/`pip3`/`pip` tokens with an absolute,
    guaranteed-real interpreter invocation. `pip`/`pip3` become `"<py>" -m
    pip` rather than a separately-resolved pip executable — same interpreter,
    no second resolution step, works even for a pack with no Scripts/pip
    shim on PATH."""
    quoted = f'"{python_path}"' if " " in python_path else python_path

    def _sub(match: "re.Match[str]") -> str:
        token = match.group(1)
        return f"{quoted} -m pip" if token.startswith("pip") else quoted

    return _PY_TOKEN_RE.sub(_sub, command)


def windows_shell_compat(command: str) -> str:
    """Best-effort rewrite of a POSIX-shaped command into one cmd.exe runs
    correctly. Deliberately conservative: only touches the specific shapes
    documented above (`/dev/null`, single-quoted `-c`, bare python/pip
    tokens); anything else — including the platform's own PowerShell-wrapped
    Windows commands — passes through unchanged. Never raises: on any
    resolution failure this returns the command untouched rather than
    guessing, since a wrong guess (e.g. an empty interpreter path) is worse
    than the original, already-understood failure mode."""
    if command.lstrip().lower().startswith("powershell"):
        return command
    try:
        command = _DEV_NULL_RE.sub("NUL", command)
        command = _win_extract_dash_c(command)
        python_path = _win_resolve_python()
        if python_path:
            command = _win_resolve_interpreter_tokens(command, python_path)
        return command
    except Exception:
        return command


# Detached-process flags used by the background executor. CREATE_NEW_PROCESS_GROUP
# lets ``taskkill /T`` reach the whole tree; DETACHED_PROCESS frees it from the
# daemon's console so it outlives a daemon restart.
_WIN_DETACHED_FLAGS = 0x00000200 | 0x00000008  # CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS

# How long a *finished* background job is retained (output + registry entry)
# after termination so late polls / read_tail still succeed. Swept on the next
# bg_start. 1h mirrors the platform's per-row lifetime.
_BG_FINISHED_TTL_S = 3600


async def execute_shell_command(
    command: str,
    timeout: int = 60,
    cwd: Optional[str] = None,
) -> dict:
    """Execute a shell command inside the egress-scoped sandbox.

    The sandbox is the only execution path: see :mod:`sandbox`. Host execution
    is kept below as ``_execute_shell_command_host`` for tests and tooling that
    explicitly want it, but the bridge never reaches for it — running a command
    unsandboxed would mean reporting a scope that is not being applied.
    """
    from strobes_shell_agent import sandbox
    return await sandbox.get_lane().run_shell(command, timeout=timeout, cwd=cwd)


async def _execute_shell_command_host(
    command: str,
    timeout: int = 60,
    cwd: Optional[str] = None,
) -> dict:
    """Legacy host-subprocess execution — no egress enforcement. Tests only."""
    start = time.monotonic()
    if cwd and not os.path.isdir(cwd):
        cwd = None
    if IS_WINDOWS:
        command = windows_shell_compat(command)

    popen_kwargs = {
        "stdout": asyncio.subprocess.PIPE,
        "stderr": asyncio.subprocess.PIPE,
        "cwd": cwd,
        # Prepend the sandbox pack (CLI tools + standalone python) to PATH so the
        # agent's nmap/nuclei/python etc. resolve to the pack. No-op if no pack.
        "env": pack.build_env(),
    }
    # New process group / job — lets us kill the whole tree on timeout.
    if IS_WINDOWS:
        popen_kwargs["creationflags"] = 0x00000200  # CREATE_NEW_PROCESS_GROUP
    else:
        popen_kwargs["start_new_session"] = True

    try:
        proc = await asyncio.create_subprocess_shell(command, **popen_kwargs)
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
            duration_ms = int((time.monotonic() - start) * 1000)
            return {
                "success": proc.returncode == 0,
                "stdout": stdout.decode(errors="replace"),
                "stderr": stderr.decode(errors="replace"),
                "exit_code": proc.returncode,
                "duration_ms": duration_ms,
            }
        except asyncio.TimeoutError:
            _kill_proc_group(proc)
            try:
                await asyncio.wait_for(proc.wait(), timeout=2)
            except asyncio.TimeoutError:
                pass
            duration_ms = int((time.monotonic() - start) * 1000)
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Command timed out after {timeout}s",
                "exit_code": -1,
                "duration_ms": duration_ms,
                "error": "timeout",
            }
    except Exception as e:
        duration_ms = int((time.monotonic() - start) * 1000)
        return {
            "success": False,
            "stdout": "",
            "stderr": str(e),
            "exit_code": -1,
            "duration_ms": duration_ms,
            "error": str(e),
        }


def _kill_proc_group(proc):
    """Kill the process and any children it spawned."""
    if proc.returncode is not None:
        return
    if IS_WINDOWS:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return
    # Brief grace period, then SIGKILL.
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


# ---------------------------------------------------------------------------
# Background jobs
#
# The platform's bg-shell daemon polls, so the bridge must launch a command
# DETACHED and answer start / poll / cancel. All OS differences live here in
# Python (process-group flags, tree-kill) — the platform never generates a
# shell launcher. Output streams to files in a per-task tempdir so polls read
# incrementally without touching the child's pipes.
# ---------------------------------------------------------------------------

# task_id -> {"proc": Popen, "workdir": Path, "deadline": float|None,
#             "finished_at": float|None}
_BG_JOBS: dict = {}


def _bg_root() -> Path:
    root = Path(tempfile.gettempdir()) / "strobes-bg"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _kill_bg_proc(proc: "subprocess.Popen") -> None:
    """Kill a detached background process and its whole tree, cross-OS."""
    if proc.poll() is not None:
        return
    if IS_WINDOWS:
        try:
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                capture_output=True,
                timeout=10,
            )
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return
    time.sleep(0.3)
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def _sweep_finished_jobs() -> None:
    now = time.monotonic()
    for tid in list(_BG_JOBS.keys()):
        job = _BG_JOBS.get(tid)
        if not job:
            continue
        fin = job.get("finished_at")
        if fin is not None and (now - fin) > _BG_FINISHED_TTL_S:
            shutil.rmtree(job["workdir"], ignore_errors=True)
            _BG_JOBS.pop(tid, None)


def bg_start(
    task_id: str,
    command: str,
    cwd: Optional[str] = None,
    timeout: int = 0,
) -> dict:
    """Launch ``command`` detached and return immediately.

    Returns ``{success, task_id, pid, workdir}``. stdout/stderr stream to files
    under a per-task tempdir; poll with :func:`bg_poll`.
    """
    if not task_id or not command:
        return {"success": False, "error": "task_id and command are required"}
    _sweep_finished_jobs()
    if task_id in _BG_JOBS:
        return {"success": False, "error": f"task {task_id} already exists"}
    if cwd and not os.path.isdir(cwd):
        cwd = None

    workdir = _bg_root() / str(task_id)
    workdir.mkdir(parents=True, exist_ok=True)
    out_f = open(workdir / "stdout", "wb")
    err_f = open(workdir / "stderr", "wb")

    # Background jobs carry the long-running scan traffic, so they are confined
    # exactly like foreground ones: the sandbox wrapper becomes the argv, and
    # the proxy environment rides along to every child it spawns.
    from strobes_shell_agent import sandbox as _sandbox
    try:
        argv, env = _sandbox.confine(command)
    except _sandbox.SandboxUnavailable as e:
        out_f.close(); err_f.close()
        return {"success": False, "error": str(e)}

    popen_kwargs = {
        "stdout": out_f,
        "stderr": err_f,
        "stdin": subprocess.DEVNULL,
        "cwd": cwd,
        "env": env,
    }
    if IS_WINDOWS:
        popen_kwargs["creationflags"] = _WIN_DETACHED_FLAGS
    else:
        # New session → the child leads its own process group so we can
        # signal the whole tree on cancel/timeout.
        popen_kwargs["start_new_session"] = True

    try:
        proc = subprocess.Popen(argv, **popen_kwargs)
    except Exception as e:
        out_f.close()
        err_f.close()
        shutil.rmtree(workdir, ignore_errors=True)
        return {"success": False, "error": str(e)}

    _BG_JOBS[task_id] = {
        "proc": proc,
        "workdir": workdir,
        "out_f": out_f,
        "err_f": err_f,
        "deadline": (time.monotonic() + timeout) if timeout and timeout > 0 else None,
        "finished_at": None,
    }
    return {
        "success": True,
        "task_id": task_id,
        "pid": proc.pid,
        "workdir": str(workdir),
    }


def _read_from(path: Path, offset: int) -> tuple[str, int]:
    """Return (new_text_since_offset, total_size)."""
    try:
        if not path.exists():
            return "", 0
        total = path.stat().st_size
        with open(path, "rb") as f:
            f.seek(max(0, int(offset)))
            data = f.read()
        return data.decode(errors="replace"), total
    except OSError:
        return "", 0


def bg_poll(task_id: str, offset: int = 0) -> dict:
    """Poll a background job. Returns status + stdout bytes since ``offset``."""
    job = _BG_JOBS.get(task_id)
    if not job:
        # Unknown or already swept — the platform treats this as lost/gone.
        return {"success": True, "found": False, "running": False, "exit_code": None}

    proc = job["proc"]
    rc = proc.poll()

    # Belt-and-braces daemon-side timeout (the platform also cancels via its
    # own per-row deadline). Prevents orphans if the platform disconnects.
    timed_out = False
    if rc is None and job["deadline"] is not None and time.monotonic() > job["deadline"]:
        _kill_bg_proc(proc)
        rc = proc.poll()
        timed_out = True

    running = rc is None
    new_stdout, total = _read_from(job["workdir"] / "stdout", offset)

    if not running and job.get("finished_at") is None:
        job["finished_at"] = time.monotonic()
        for k in ("out_f", "err_f"):
            try:
                job[k].close()
            except Exception:
                pass

    return {
        "success": True,
        "found": True,
        "running": running,
        "exit_code": (124 if timed_out and rc is None else rc),
        "timed_out": timed_out,
        "stdout": new_stdout,
        "stdout_size": total,
        "pid": proc.pid,
    }


def bg_cancel(task_id: str) -> dict:
    """Kill a background job and clean up its workdir."""
    job = _BG_JOBS.pop(task_id, None)
    if not job:
        return {"success": True, "found": False}
    _kill_bg_proc(job["proc"])
    for k in ("out_f", "err_f"):
        try:
            job[k].close()
        except Exception:
            pass
    shutil.rmtree(job["workdir"], ignore_errors=True)
    return {"success": True, "found": True}


async def execute_code(
    language: str,
    code: str,
    timeout: int = 60,
    cwd: Optional[str] = None,
) -> dict:
    """Execute code by writing to a temp file and running with the appropriate interpreter."""
    lang = language.lower()

    if lang in ("python", "python3"):
        suffix = ".py"
        # Use the pack's standalone interpreter (has boto3/reportlab/curl_cffi/… baked
        # in) when a pack is present; otherwise fall back to the host's python3.
        interpreter = shlex.quote(pack.python_interpreter())
    elif lang in ("node", "javascript", "js"):
        suffix = ".js"
        interpreter = "node"
    elif lang in ("typescript", "ts"):
        suffix = ".ts"
        interpreter = "npx ts-node"
    elif lang in ("bash", "sh", "shell"):
        # Execute directly as shell command
        return await execute_shell_command(code, timeout=timeout, cwd=cwd)
    else:
        return {
            "success": False,
            "stdout": "",
            "stderr": f"Unsupported language: {language}",
            "exit_code": -1,
            "duration_ms": 0,
        }

    # Use the default tempdir; cwd may not exist or may be unwritable.
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=suffix, delete=False, encoding="utf-8"
    ) as f:
        f.write(code)
        temp_path = f.name

    # The command may run as a different account than the bridge (the
    # packet-filter lane), in which case it cannot read what we just wrote.
    from strobes_shell_agent import sandbox as _sandbox
    _sandbox.adopt_path(temp_path)

    try:
        # Quote the interpreter + script path for the target shell. shlex.quote is
        # POSIX-only: on Windows it emits SINGLE quotes, which cmd.exe cannot parse
        # ("The filename, directory name, or volume label syntax is incorrect"),
        # so code execution silently failed on every Windows bridge. Use double
        # quotes (cmd-compatible) on Windows, shlex.quote on POSIX.
        if os.name == "nt":
            _interp = pack.python_interpreter()
            command = f'"{_interp}" "{temp_path}"'
        else:
            command = f"{interpreter} {shlex.quote(temp_path)}"
        result = await execute_shell_command(
            command,
            timeout=timeout,
            cwd=cwd if cwd and os.path.isdir(cwd) else None,
        )
        return result
    finally:
        try:
            os.unlink(temp_path)
        except OSError:
            pass


def read_file(path: str) -> dict:
    """Read a file and return its content."""
    try:
        p = Path(path).expanduser().resolve()
        if not p.exists():
            return {"success": False, "error": f"File not found: {path}"}
        if not p.is_file():
            return {"success": False, "error": f"Not a file: {path}"}

        size = p.stat().st_size
        # Limit to 1MB text read
        if size > 1_048_576:
            content = p.read_bytes()[:1_048_576].decode(errors="replace")
            return {
                "success": True,
                "content": content,
                "truncated": True,
                "size": size,
            }

        return {
            "success": True,
            "content": p.read_text(errors="replace"),
            "size": size,
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def write_file(path: str, content: str, mode: str = "overwrite") -> dict:
    """Write content to a file."""
    try:
        p = Path(path).expanduser().resolve()
        p.parent.mkdir(parents=True, exist_ok=True)

        if mode == "append":
            with open(p, "a") as f:
                f.write(content)
        else:
            p.write_text(content)

        return {"success": True, "path": str(p), "size": p.stat().st_size}
    except Exception as e:
        return {"success": False, "error": str(e)}


def list_files(directory: str = ".", pattern: Optional[str] = None, recursive: bool = False) -> dict:
    """List files in a directory."""
    try:
        p = Path(directory).expanduser().resolve()
        if not p.exists():
            return {"success": False, "error": f"Directory not found: {directory}"}
        if not p.is_dir():
            return {"success": False, "error": f"Not a directory: {directory}"}

        if pattern:
            if recursive:
                matches = list(p.rglob(pattern))
            else:
                matches = list(p.glob(pattern))
            files = [
                {
                    "name": str(m.relative_to(p)),
                    "type": "dir" if m.is_dir() else "file",
                    "size": m.stat().st_size if m.is_file() else 0,
                }
                for m in sorted(matches)[:500]
            ]
        else:
            files = [
                {
                    "name": item.name,
                    "type": "dir" if item.is_dir() else "file",
                    "size": item.stat().st_size if item.is_file() else 0,
                }
                for item in sorted(p.iterdir())[:500]
            ]

        return {"success": True, "directory": str(p), "files": files}
    except Exception as e:
        return {"success": False, "error": str(e)}


_ALLOWED_URL_SCHEMES = ("https", "http")


def _reject_bad_scheme(url: str) -> Optional[dict]:
    """Only fetch/PUT https(+http) presigned URLs — never file://, ftp://, etc.
    Defence-in-depth: the command channel is trusted, but this closes local-file
    read / SSRF if a URL ever comes from untrusted input."""
    if urlparse(url).scheme not in _ALLOWED_URL_SCHEMES:
        return {"success": False, "error": f"refused URL scheme in: {url[:60]}"}
    return None


def file_pull(path: str, url: str, sha256: Optional[str] = None,
              timeout: int = 300) -> dict:
    """Download a workspace file onto this machine from a presigned S3 URL.

    Replaces the old base64-over-WebSocket ``file_upload``: the platform mints a
    one-time presigned GET, the daemon streams it straight to disk. No 10 MB
    frame cap, no base64 inflation. Fails loudly (no fallback) if the fetch or
    the optional integrity check does not succeed.
    """
    bad = _reject_bad_scheme(url)
    if bad:
        return bad
    try:
        p = Path(path).expanduser().resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        req = urllib.request.Request(url, method="GET")
        h = hashlib.sha256()
        size = 0
        tmp = p.with_name(p.name + ".strobes-part")
        with urllib.request.urlopen(req, timeout=timeout) as r, open(tmp, "wb") as f:
            while True:
                chunk = r.read(1024 * 256)
                if not chunk:
                    break
                f.write(chunk)
                h.update(chunk)
                size += len(chunk)
        digest = h.hexdigest()
        if sha256 and digest.lower() != sha256.lower():
            try:
                tmp.unlink()
            except OSError:
                pass
            return {"success": False,
                    "error": f"sha256 mismatch: got {digest}, expected {sha256}"}
        os.replace(tmp, p)
        return {"success": True, "path": str(p), "size": size, "sha256": digest}
    except urllib.error.HTTPError as e:
        return {"success": False, "error": f"HTTP {e.code} fetching presigned URL: {e.reason}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def file_push(path: str, url: str, content_type: str = "application/octet-stream",
              timeout: int = 300) -> dict:
    """Upload a file from this machine to a presigned S3 URL (one-time PUT).

    Replaces the old base64 ``file_download``: the platform mints a presigned
    PUT and reads the object back with its own credentials afterwards, so there
    is no per-frame size ceiling and nothing is base64-encoded over the wire.
    """
    bad = _reject_bad_scheme(url)
    if bad:
        return bad
    try:
        p = Path(path).expanduser().resolve()
        if not p.exists():
            return {"success": False, "error": f"File not found: {path}"}
        if not p.is_file():
            return {"success": False, "error": f"Not a file: {path}"}
        data = p.read_bytes()
        sha256 = hashlib.sha256(data).hexdigest()
        req = urllib.request.Request(url, data=data, method="PUT")
        req.add_header("Content-Type", content_type)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            code = r.status
        return {"success": True, "path": str(p), "size": len(data),
                "sha256": sha256, "status": code}
    except urllib.error.HTTPError as e:
        return {"success": False, "error": f"HTTP {e.code} on presigned PUT: {e.reason}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def get_env_info() -> dict:
    """Get environment information about the machine."""
    info = {
        "os": platform.system(),
        "os_version": platform.version(),
        "arch": platform.machine(),
        "hostname": platform.node(),
        "python": platform.python_version(),
        "cwd": os.getcwd(),
        "user": os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
    }

    # Check for common tools, honouring the sandbox pack's bin/ dir if present.
    env_path = pack.build_env().get("PATH")
    tools = {}
    python_tool = "python" if sys.platform == "win32" else "python3"
    for tool in [python_tool, "node", "npm", "git", "docker", "nmap", "curl", "wget",
                 "nuclei", "httpx", "subfinder", "ffuf", "gobuster"]:
        tools[tool] = shutil.which(tool, path=env_path) is not None
    info["tools"] = tools
    info["pack"] = pack.status()

    return {"success": True, **info}
