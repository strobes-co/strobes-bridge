"""Command execution and file I/O for the shell bridge agent."""

import asyncio
import base64
import os
import platform
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional

from strobes_shell_agent import pack

IS_WINDOWS = sys.platform == "win32"

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
    """Execute a shell command via subprocess. Spawns in its own process group
    so a timeout kills any child processes the command may have started."""
    start = time.monotonic()
    if cwd and not os.path.isdir(cwd):
        cwd = None

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

    popen_kwargs = {
        "stdout": out_f,
        "stderr": err_f,
        "stdin": subprocess.DEVNULL,
        "cwd": cwd,
        "env": pack.build_env(),
        "shell": True,
    }
    if IS_WINDOWS:
        popen_kwargs["creationflags"] = _WIN_DETACHED_FLAGS
    else:
        # New session → the child leads its own process group so we can
        # signal the whole tree on cancel/timeout.
        popen_kwargs["start_new_session"] = True

    try:
        proc = subprocess.Popen(command, **popen_kwargs)
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

    try:
        # shlex-quote the path so spaces / special chars are safe.
        result = await execute_shell_command(
            f"{interpreter} {shlex.quote(temp_path)}",
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


def upload_file(path: str, content_b64: str) -> dict:
    """Upload a file (base64-encoded content)."""
    try:
        p = Path(path).expanduser().resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        data = base64.b64decode(content_b64)
        p.write_bytes(data)
        return {"success": True, "path": str(p), "size": len(data)}
    except Exception as e:
        return {"success": False, "error": str(e)}


def download_file(path: str) -> dict:
    """Download a file (returns base64-encoded content).

    The WebSocket max frame is 10MB and base64 inflates by ~33%, so the
    raw file limit is set so the encoded payload still fits.
    """
    try:
        p = Path(path).expanduser().resolve()
        if not p.exists():
            return {"success": False, "error": f"File not found: {path}"}
        if not p.is_file():
            return {"success": False, "error": f"Not a file: {path}"}

        # Leave 256 KB headroom for the JSON envelope.
        RAW_LIMIT = 7_700_000
        size = p.stat().st_size
        if size > RAW_LIMIT:
            return {
                "success": False,
                "error": f"File too large: {size} bytes (max {RAW_LIMIT} bytes after base64 inflation)",
            }

        content = base64.b64encode(p.read_bytes()).decode()
        return {"success": True, "content_b64": content, "size": size}
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
    for tool in ["python3", "node", "npm", "git", "docker", "nmap", "curl", "wget",
                 "nuclei", "httpx", "subfinder", "ffuf", "gobuster"]:
        tools[tool] = shutil.which(tool, path=env_path) is not None
    info["tools"] = tools
    info["pack"] = pack.status()

    return {"success": True, **info}
