"""Command execution and file I/O for the shell bridge agent."""

import asyncio
import base64
import os
import platform
import shlex
import shutil
import signal
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional

IS_WINDOWS = sys.platform == "win32"


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
        interpreter = "python3"
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

    # Check for common tools
    tools = {}
    for tool in ["python3", "node", "npm", "git", "docker", "nmap", "curl", "wget",
                 "nuclei", "httpx", "subfinder", "ffuf", "gobuster"]:
        tools[tool] = shutil.which(tool) is not None
    info["tools"] = tools

    return {"success": True, **info}
