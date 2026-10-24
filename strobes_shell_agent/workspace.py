"""``~/.strobes/workspace`` on a machine that cannot mount it.

On a cloud sandbox the workspace is an S3 Files mount: the agent opens a path
and the bytes are already there, because AWS mounted the bucket prefix into the
session. A bridge host cannot have that. It is a customer's own machine, often
behind their firewall, with no route into our VPC and no business getting one --
NFSv4.2 over TLS to a mount target is not available and should not be.

So the same PATH is provided a different way: the directory is real local disk,
filled from the workspace on connect and read back afterwards, using the
one-time presigned transfers ``executor.file_pull`` / ``file_push`` already
implement. The agent cannot tell the difference, which is the entire point --
every SKILL.md, prompt and code site names ``~/.strobes/workspace`` and none of
them knows which surface they are on.

What is deliberately NOT here
-----------------------------

A file watcher, or any attempt to push on write. Two reasons. A push needs a
presigned URL, which only the backend can mint, so the daemon cannot initiate
one anyway; and a watcher on a customer's machine that uploads whatever appears
in a directory is a data-exfiltration shape we should not build. The backend
asks what changed (:func:`workspace_scan`) and then hands back URLs for the
files it wants. The machine never decides on its own what leaves it.

Idempotence is load-bearing. A bridge reconnects often -- a laptop closing its
lid is a reconnect -- and re-downloading an unchanged 200 MB capture every time
would make the feature worse than the tools it replaces. :func:`workspace_pull`
compares checksums first and skips what already matches.
"""

from __future__ import annotations

import hashlib
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

#: The one path the agent knows. Identical on every execution surface: a mount
#: on a cloud sandbox, ordinary disk here.
WORKSPACE_DIRNAME = os.path.join(".strobes", "workspace")

#: Refuse a single file larger than this. A bridge is somebody's laptop, not a
#: server, and a runaway manifest should not fill their disk. Generous enough
#: for a pcap or a memory dump; the cap exists so the failure is a clear error
#: rather than a full filesystem.
MAX_FILE_BYTES = 2 * 1024 * 1024 * 1024


def _home() -> Path:
    """The home commands see, which is not always the bridge's own.

    In the packet-filter lane commands run as a separate account with its own
    home; a workspace placed in the bridge's home would be a directory the
    agent's ``~/.strobes/workspace`` never names, and often cannot even enter.
    """
    from . import sandbox

    return Path(sandbox.command_home())


#: Per-workspace homes, so one bridge serving many workspaces keeps each one's
#: files apart. The platform runs every command for workspace W with
#: HOME=<home>/.strobes/homes/W, so ``~/.strobes/workspace`` there is W's own.
#: Advertised to the platform as the ``workspace_homes`` feature.
HOMES_DIRNAME = os.path.join(".strobes", "homes")


def _workspace_home(workspace_id: Optional[str]) -> Optional[Path]:
    """``<home>/.strobes/homes/<id>`` for a well-formed id, else None."""
    if not workspace_id:
        return None
    import uuid

    try:
        ws = str(uuid.UUID(str(workspace_id)))
    except (TypeError, ValueError):
        return None
    return _home() / HOMES_DIRNAME / ws


def _ensure_workspace_home(home: Path) -> None:
    """Create the home and link every other entry of the real home into it,
    so the user's own keys, config and tools are still there under HOME."""
    real = _home()
    (home / WORKSPACE_DIRNAME).mkdir(parents=True, exist_ok=True)
    _adopt_within(real, home / WORKSPACE_DIRNAME)
    for entry in real.iterdir():
        if entry.name == ".strobes":
            continue
        link = home / entry.name
        if not os.path.lexists(link):
            try:
                os.symlink(entry, link)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Descriptor-relative filesystem access
# ---------------------------------------------------------------------------
#
# In the packet-filter lane the workspace belongs to the account commands run
# as, while this daemon -- usually root -- reads and writes it. Anything done by
# PATH there is a race the agent can win: swap a component for a symlink
# between a check and the open, and root reads /etc/shadow into the workspace
# upload, writes a pulled file through a planted link, or chowns /etc to the
# scan account. So every operation walks the tree with descriptors: each
# component is opened relative to the previous one with O_NOFOLLOW, a symlink
# anywhere makes the open fail rather than be followed, files are created with
# O_EXCL and renamed within their directory (a rename never follows the
# destination), and ownership is handed over with fchown on the descriptor.
#
# The one path still taken by name is the home itself; its parent (e.g.
# /var/lib) is not writable by the account, so it cannot be replaced.

_FD_SAFE = (os.open in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW")
            and hasattr(os, "O_DIRECTORY"))
_O_DIR = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
_O_FILE = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)


def _parts(rel: str) -> Optional[List[str]]:
    """Relative path components, or None for anything that could leave the dir."""
    rel = (rel or "").replace("\\", "/")
    if not rel or rel.startswith("/") or "\x00" in rel:
        return None
    parts = [p for p in rel.split("/") if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts):
        return None
    return parts


def _owner() -> Optional[int]:
    from . import sandbox

    return sandbox._command_uid()


def _open_home() -> int:
    return os.open(str(_home()), _O_DIR)


def _open_chain(base_fd: int, parts: List[str], create: bool = False,
                owner: Optional[int] = None) -> int:
    """Open ``parts`` below ``base_fd`` without following any symlink."""
    fd = os.dup(base_fd)
    try:
        for part in parts:
            try:
                nfd = os.open(part, _O_DIR, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, 0o755, dir_fd=fd)
                nfd = os.open(part, _O_DIR, dir_fd=fd)
            if create and owner is not None:
                os.fchown(nfd, owner, -1)
            os.close(fd)
            fd = nfd
        return fd
    except BaseException:
        os.close(fd)
        raise


def _root_parts(workspace_id: Optional[str]) -> List[str]:
    """Components from the home to the workspace root."""
    ws = _workspace_home(workspace_id)
    base = [] if ws is None else [".strobes", "homes", ws.name]
    return base + [".strobes", "workspace"]


def _ensure_root_fd(workspace_id: Optional[str]) -> int:
    """Create (as needed) and open the workspace root; link the real home's
    entries into a per-workspace home so the user's own files stay reachable."""
    owner = _owner()
    home_fd = _open_home()
    try:
        if owner is not None:
            os.fchown(home_fd, owner, -1)
        ws = _workspace_home(workspace_id)
        if ws is not None:
            wsh = _open_chain(home_fd, [".strobes", "homes", ws.name], True, owner)
            try:
                real = str(_home())
                for name in os.listdir(home_fd):
                    if name == ".strobes":
                        continue
                    try:
                        os.stat(name, dir_fd=wsh, follow_symlinks=False)
                    except FileNotFoundError:
                        try:
                            os.symlink(os.path.join(real, name), name, dir_fd=wsh)
                        except OSError:
                            pass
            finally:
                os.close(wsh)
        return _open_chain(home_fd, _root_parts(workspace_id), True, owner)
    finally:
        os.close(home_fd)


def _open_file_in(root_fd: int, parts: List[str]) -> int:
    """Open a regular, singly-linked file below ``root_fd``; else raise."""
    import stat as _stat

    parent = _open_chain(root_fd, parts[:-1])
    try:
        fd = os.open(parts[-1], _O_FILE, dir_fd=parent)
    finally:
        os.close(parent)
    st = os.fstat(fd)
    if not _stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        os.close(fd)
        raise PermissionError("not a regular, singly-linked file")
    return fd


def _sha256_fd(fd: int) -> str:
    h = hashlib.sha256()
    with os.fdopen(os.dup(fd), "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _download(url: str, timeout: int):
    """Chunks of a presigned GET. Isolated so the transfer can be stubbed."""
    import urllib.request

    with urllib.request.urlopen(url, timeout=timeout) as r:  # noqa: S310
        yield from iter(lambda: r.read(256 * 1024), b"")


def _upload(url: str, data: bytes, content_type: str, timeout: int) -> int:
    """A presigned PUT; returns the HTTP status."""
    import urllib.request

    req = urllib.request.Request(url, data=data, method="PUT")
    req.add_header("Content-Type", content_type)
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
        return r.status


def _pull_into(root_fd: int, parts: List[str], url: str, want: Optional[str],
               timeout: int) -> Dict[str, Any]:
    """Download ``url`` to ``parts`` below ``root_fd``: temp file + rename."""
    import secrets

    from .executor import _reject_bad_scheme

    bad = _reject_bad_scheme(url)
    if bad:
        return bad
    owner = _owner()
    parent = _open_chain(root_fd, parts[:-1], True, owner)
    tmp = f".{parts[-1]}.{secrets.token_hex(6)}.strobes-part"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o644, dir_fd=parent)
        try:
            h = hashlib.sha256()
            size = 0
            for chunk in _download(url, timeout):
                size += len(chunk)
                if size > MAX_FILE_BYTES:
                    raise ValueError("file exceeds the workspace size limit")
                h.update(chunk)
                view = memoryview(chunk)
                while view:
                    view = view[os.write(fd, view):]
            if want and h.hexdigest() != want:
                raise ValueError("sha256 mismatch")
            if owner is not None:
                os.fchown(fd, owner, -1)
        finally:
            os.close(fd)
        os.rename(tmp, parts[-1], src_dir_fd=parent, dst_dir_fd=parent)
        return {"success": True, "size": size}
    except Exception as e:  # noqa: BLE001
        try:
            os.unlink(tmp, dir_fd=parent)
        except OSError:
            pass
        return {"success": False, "error": str(e)}
    finally:
        os.close(parent)


def _scan_fd(dir_fd: int, prefix: str, out: List[Dict[str, Any]],
             include_sha256: bool) -> None:
    import stat as _stat

    for name in sorted(os.listdir(dir_fd)):
        try:
            st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        except OSError:
            continue
        rel = f"{prefix}{name}"
        if _stat.S_ISDIR(st.st_mode):
            try:
                sub = os.open(name, _O_DIR, dir_fd=dir_fd)
            except OSError:
                continue
            try:
                _scan_fd(sub, rel + "/", out, include_sha256)
            finally:
                os.close(sub)
        elif _stat.S_ISREG(st.st_mode) and st.st_nlink == 1:
            entry: Dict[str, Any] = {"path": rel, "size": st.st_size, "mtime": st.st_mtime}
            if include_sha256 and st.st_size <= MAX_FILE_BYTES:
                try:
                    fd = _open_file_in(dir_fd, [name])
                    try:
                        entry["sha256"] = _sha256_fd(fd)
                    finally:
                        os.close(fd)
                except OSError:
                    continue
            out.append(entry)


def _push_from(root_fd: int, parts: List[str], url: str, content_type: str,
               timeout: int) -> Dict[str, Any]:
    import urllib.error

    from .executor import _reject_bad_scheme

    bad = _reject_bad_scheme(url)
    if bad:
        return bad
    try:
        fd = _open_file_in(root_fd, parts)
    except FileNotFoundError:
        return {"success": False, "error": "not a file on this machine"}
    except OSError as e:
        return {"success": False, "error": f"refusing this file: {e}"}
    try:
        if os.fstat(fd).st_size > MAX_FILE_BYTES:
            return {"success": False, "error": "file exceeds the workspace size limit"}
        with os.fdopen(os.dup(fd), "rb") as fh:
            data = fh.read()
        status = _upload(url, data, content_type, timeout)
        return {"success": True, "size": len(data), "status": status}
    except urllib.error.HTTPError as e:
        return {"success": False, "error": f"HTTP {e.code} on presigned PUT: {e.reason}"}
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": str(e)}
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------
# Windows: transfers run AS the sandbox account
# ---------------------------------------------------------------------------
#
# Windows has no O_NOFOLLOW/dir_fd, and once the sandbox account may write the
# workspace (it must, to save output) it can plant directory junctions there --
# any user with write access can. A bridge that then read or wrote workspace
# files with its own rights could be steered through them. So on Windows the
# bridge never does: pulls and pushes run as small programs in the sandbox
# lane, as the sandbox account, and can only reach what that account could
# reach anyway (the bridge still does the network transfer itself). The scan
# only stats, skips reparse points and never opens a file.

def _windows_sid() -> Optional[str]:
    """The sandbox account's SID when commands run as it, else None."""
    if sys.platform != "win32":
        return None
    from . import procsandbox, winsandbox

    if procsandbox.detect_backend() != procsandbox.WINDOWS:
        return None
    state = winsandbox.load_state() or {}
    return state.get("sid")


_LANE_MARK = "__STROBES_WS__"

#: Most a Windows push carries: the bytes come back through the lane's output.
LANE_READ_MAX = 64 * 1024 * 1024

# Network transfers stay with the bridge (its own traffic is not subject to the
# engagement's egress scope; the sandbox account's is, so a scoped allowlist
# would block storage). Only the file operations inside the workspace run as
# the sandbox account.

_LANE_PLACE = """
import os, shutil
root, rel, src = {root!r}, {rel!r}, {src!r}
dest = os.path.realpath(os.path.join(root, rel))
if not dest.startswith(os.path.realpath(root) + os.sep):
    raise SystemExit("outside the workspace")
os.makedirs(os.path.dirname(dest), exist_ok=True)
tmp = dest + ".strobes-part"
shutil.copyfile(src, tmp)
os.replace(tmp, dest)
print({mark!r} + "ok")
"""

_LANE_READ = """
import base64, os
root, rel = {root!r}, {rel!r}
src = os.path.realpath(os.path.join(root, rel))
if not src.startswith(os.path.realpath(root) + os.sep) or not os.path.isfile(src):
    raise SystemExit("not a file in the workspace")
if os.path.getsize(src) > {limit}:
    raise SystemExit("file too large for a Windows workspace push")
print({mark!r} + "ok" + base64.b64encode(open(src, "rb").read()).decode())
"""


def _lane_pull(root: str, rel: str, url: str, timeout: int) -> Dict[str, Any]:
    import tempfile

    from . import sandbox

    fd, tmp = tempfile.mkstemp(prefix="strobes-ws-")
    try:
        with os.fdopen(fd, "wb") as f:
            for chunk in _download(url, timeout):
                f.write(chunk)
        sandbox.adopt_path(tmp)  # read access for the sandbox account only
        return _run_in_lane(_LANE_PLACE.format(root=root, rel=rel, src=tmp, mark=_LANE_MARK),
                            timeout + 30)
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": str(e)}
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _lane_push(root: str, rel: str, url: str, content_type: str, timeout: int) -> Dict[str, Any]:
    import base64

    out = _run_in_lane(_LANE_READ.format(root=root, rel=rel, limit=LANE_READ_MAX,
                                          mark=_LANE_MARK), timeout + 30, keep_output=True)
    if not out.get("success"):
        return out
    try:
        data = base64.b64decode(out["payload"])
        return {"success": True, "status": _upload(url, data, content_type, timeout)}
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": str(e)}


def _run_in_lane(code: str, timeout: int, keep_output: bool = False) -> Dict[str, Any]:
    import asyncio

    from .executor import execute_code

    out = asyncio.run(execute_code("python", code, timeout=timeout))
    stdout = out.get("stdout") or ""
    i = stdout.find(_LANE_MARK + "ok")
    if i >= 0:
        res: Dict[str, Any] = {"success": True}
        if keep_output:
            res["payload"] = stdout[i + len(_LANE_MARK) + 2:].split()[0] if stdout[i + len(_LANE_MARK) + 2:].strip() else ""
        return res
    return {"success": False,
            "error": (out.get("stderr") or out.get("error") or "transfer failed").strip()[-300:]}


def _scan_windows(root: Path) -> List[Dict[str, Any]]:
    """List regular files without following links or junctions, nor opening any."""
    import stat as _stat

    reparse = getattr(_stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    out: List[Dict[str, Any]] = []
    stack = [(root, "")]
    while stack:
        d, prefix = stack.pop()
        try:
            entries = list(os.scandir(d))
        except OSError:
            continue
        for e in entries:
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                continue
            if e.is_symlink() or getattr(st, "st_file_attributes", 0) & reparse:
                continue
            rel = f"{prefix}{e.name}"
            if _stat.S_ISDIR(st.st_mode):
                stack.append((Path(e.path), rel + "/"))
            elif _stat.S_ISREG(st.st_mode):
                out.append({"path": rel, "size": st.st_size, "mtime": st.st_mtime})
    return sorted(out, key=lambda f: f["path"])


def workspace_root(workspace_id: Optional[str] = None) -> Path:
    """``~/.strobes/workspace`` as commands see it, resolved -- the workspace's
    own when ``workspace_id`` is given, the shared one otherwise."""
    home = _workspace_home(workspace_id)
    return ((home or _home()) / WORKSPACE_DIRNAME).resolve()


def _adopt_within(base: Path, path: Path) -> None:
    """Hand ``path`` and each directory between ``base`` and it to the identity
    commands run as. A no-op where that is the bridge's own user."""
    from . import sandbox

    try:
        rel = path.relative_to(base)
    except ValueError:
        return
    current = base
    sandbox.adopt_path(str(current))
    for part in rel.parts:
        current = current / part
        sandbox.adopt_path(str(current))


def _single_link(path: Path) -> bool:
    """False for a file with other hard links.

    The workspace belongs to the account commands run as, while the bridge
    reads it to push files back. A hard link planted there to a file only the
    bridge can read would otherwise be uploaded on its behalf; symlinks are
    refused for the same reason.
    """
    try:
        return path.stat().st_nlink == 1
    except OSError:
        return False


def _safe_target(rel_path: str, workspace_id: Optional[str] = None) -> Optional[Path]:
    """Resolve ``rel_path`` inside the workspace, or None if it escapes.

    The boundary that the mount gets from its access point's root directory,
    enforced here in code because there is no access point on this machine. A
    manifest entry is data from the network: ``../../.ssh/authorized_keys`` is
    a perfectly well-formed relative path, and joining it naively would write
    outside the workspace onto a customer's machine.

    Checked after resolution, not by inspecting the string, so ``..`` segments,
    absolute paths and symlinked parents are all covered by the same test.
    """
    root = workspace_root(workspace_id)
    candidate = (root / rel_path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        log.warning("workspace: refusing path outside the workspace: %r", rel_path)
        return None
    if candidate == root:
        return None
    return candidate


def _sha256(path: Path) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def workspace_ensure(workspace_id: Optional[str] = None) -> Dict[str, Any]:
    """Create the workspace directory, and report where it is.

    Called at connect, alongside the skills linking, so the path exists before
    an agent's first line of code runs. An agent that writes to a directory it
    expected to exist and finds ENOENT reports "the workspace is broken",
    which is indistinguishable from the feature being absent.
    """
    ws_home = _workspace_home(workspace_id)
    if _FD_SAFE:
        try:
            os.close(_ensure_root_fd(workspace_id))
            return {"success": True, "path": str(workspace_root(workspace_id))}
        except OSError as e:
            return {"success": False, "error": f"cannot create the workspace: {e}"}
    try:
        if ws_home is not None:
            _ensure_workspace_home(ws_home)
            sid = _windows_sid()
            if sid:
                from . import winsandbox

                winsandbox.grant_modify_access(str(ws_home / WORKSPACE_DIRNAME), sid)
            return {"success": True, "path": str(ws_home / WORKSPACE_DIRNAME)}
        home = _home()
        root = home / WORKSPACE_DIRNAME
        root.mkdir(parents=True, exist_ok=True)
        _adopt_within(home, root)
        sid = _windows_sid()
        if sid:
            from . import winsandbox

            winsandbox.grant_modify_access(str(root), sid)
        return {"success": True, "path": str(root)}
    except OSError as e:
        return {"success": False, "error": f"cannot create the workspace: {e}"}


def workspace_pull(files: List[Dict[str, Any]], timeout: int = 300,
                   workspace_id: Optional[str] = None) -> Dict[str, Any]:
    """Fetch workspace files onto this machine.

    ``files`` is ``[{"path": "reports/a.pdf", "url": <presigned GET>,
    "sha256": <optional>}]``. Paths are relative to the workspace root; the URL
    is one-time and minted by the backend.

    An entry whose local copy already matches ``sha256`` is SKIPPED, not
    re-downloaded. Without that a reconnect re-pulls the whole workspace, and
    a bridge reconnects whenever the machine sleeps.

    Never raises: a partial pull is reported per file. One unreachable URL must
    not cost the other files, because the agent may only need one of them.
    """
    from .executor import file_pull

    if _FD_SAFE:
        return _workspace_pull_fd(files, timeout, workspace_id)

    ensured = workspace_ensure(workspace_id)
    if not ensured.get("success"):
        return {"success": False, "error": ensured.get("error"), "pulled": 0}

    sid = _windows_sid()
    pulled, skipped, failed = 0, 0, []
    for entry in files or []:
        rel = (entry or {}).get("path") or ""
        url = (entry or {}).get("url") or ""
        want = (entry or {}).get("sha256")
        target = _safe_target(rel, workspace_id)
        if target is None or not url:
            failed.append({"path": rel, "error": "invalid path or url"})
            continue

        if sid:
            from .executor import _reject_bad_scheme

            bad = _reject_bad_scheme(url)
            result = bad or _lane_pull(str(workspace_root(workspace_id)), rel, url, timeout)
            if result.get("success"):
                pulled += 1
            else:
                failed.append({"path": rel, "error": result.get("error")})
            continue

        if want and target.is_file() and _sha256(target) == want:
            skipped += 1
            continue

        try:
            target.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            failed.append({"path": rel, "error": f"cannot create parent: {e}"})
            continue

        result = file_pull(str(target), url, want, timeout)
        if result.get("success"):
            _adopt_within(workspace_root(workspace_id), target)
            pulled += 1
        else:
            failed.append({"path": rel, "error": result.get("error")})

    return {
        "success": not failed,
        "path": str(workspace_root(workspace_id)),
        "pulled": pulled,
        "skipped": skipped,
        "failed": failed,
    }


def workspace_scan(include_sha256: bool = True,
                   workspace_id: Optional[str] = None) -> Dict[str, Any]:
    """What is in the workspace on this machine, for the backend to diff.

    Returns one entry per file: relative path, size, mtime and (by default) a
    checksum. The backend compares against what it holds and mints presigned
    PUTs only for what actually differs, so an unchanged workspace uploads
    nothing.

    ``include_sha256=False`` skips hashing for a cheap size/mtime-only pass --
    worth having, because hashing a directory of large captures is not free and
    mtime alone is enough to rule most files out.
    """
    root = workspace_root(workspace_id)
    if _FD_SAFE:
        out_fd: List[Dict[str, Any]] = []
        try:
            home_fd = _open_home()
            try:
                rfd = _open_chain(home_fd, _root_parts(workspace_id))
            finally:
                os.close(home_fd)
        except OSError:
            return {"success": True, "path": str(root), "files": []}
        try:
            _scan_fd(rfd, "", out_fd, include_sha256)
        finally:
            os.close(rfd)
        return {"success": True, "path": str(root), "files": out_fd}
    if not root.is_dir():
        return {"success": True, "path": str(root), "files": []}
    if _windows_sid():
        return {"success": True, "path": str(root), "files": _scan_windows(root)}

    out: List[Dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink() or not _single_link(path):
            # Symlinks are skipped deliberately: following one would upload
            # whatever it points at, which on a customer's machine is an
            # arbitrary-file-read dressed up as a workspace sync.
            continue
        try:
            stat = path.stat()
            entry: Dict[str, Any] = {
                "path": str(path.relative_to(root)).replace(os.sep, "/"),
                "size": stat.st_size,
                "mtime": stat.st_mtime,
            }
            if include_sha256 and stat.st_size <= MAX_FILE_BYTES:
                entry["sha256"] = _sha256(path)
            out.append(entry)
        except OSError:
            continue
    return {"success": True, "path": str(root), "files": out}


def workspace_push(files: List[Dict[str, Any]], timeout: int = 300,
                   workspace_id: Optional[str] = None) -> Dict[str, Any]:
    """Send named workspace files back, each to a presigned PUT.

    ``files`` is ``[{"path": ..., "url": <presigned PUT>, "content_type": ...}]``.
    The backend names what it wants; this never chooses for itself -- see the
    module docstring on why the machine does not decide what leaves it.
    """
    from .executor import file_push

    if _FD_SAFE:
        return _workspace_push_fd(files, timeout, workspace_id)

    sid = _windows_sid()
    pushed, failed = 0, []
    for entry in files or []:
        rel = (entry or {}).get("path") or ""
        url = (entry or {}).get("url") or ""
        target = _safe_target(rel, workspace_id)
        if target is None or not url:
            failed.append({"path": rel, "error": "invalid path or url"})
            continue
        if sid:
            from .executor import _reject_bad_scheme

            bad = _reject_bad_scheme(url)
            result = bad or _lane_push(
                str(workspace_root(workspace_id)), rel, url,
                (entry or {}).get("content_type") or "application/octet-stream", timeout)
            if result.get("success"):
                pushed += 1
            else:
                failed.append({"path": rel, "error": result.get("error")})
            continue
        if not target.is_file():
            failed.append({"path": rel, "error": "not a file on this machine"})
            continue
        if not _single_link(target):
            failed.append({"path": rel, "error": "refusing a file with other hard links"})
            continue
        result = file_push(
            str(target), url, (entry or {}).get("content_type") or "application/octet-stream", timeout
        )
        if result.get("success"):
            pushed += 1
        else:
            failed.append({"path": rel, "error": result.get("error")})

    return {"success": not failed, "pushed": pushed, "failed": failed}


def _workspace_pull_fd(files, timeout, workspace_id) -> Dict[str, Any]:
    try:
        root_fd = _ensure_root_fd(workspace_id)
    except OSError as e:
        return {"success": False, "error": f"cannot create the workspace: {e}", "pulled": 0}
    pulled, skipped, failed = 0, 0, []
    try:
        for entry in files or []:
            rel = (entry or {}).get("path") or ""
            url = (entry or {}).get("url") or ""
            want = (entry or {}).get("sha256")
            parts = _parts(rel)
            if parts is None or not url:
                failed.append({"path": rel, "error": "invalid path or url"})
                continue
            if want:
                try:
                    fd = _open_file_in(root_fd, parts)
                    try:
                        if _sha256_fd(fd) == want:
                            skipped += 1
                            continue
                    finally:
                        os.close(fd)
                except OSError:
                    pass
            try:
                result = _pull_into(root_fd, parts, url, want, timeout)
            except OSError as e:
                result = {"success": False, "error": f"refusing this path: {e}"}
            if result.get("success"):
                pulled += 1
            else:
                failed.append({"path": rel, "error": result.get("error")})
    finally:
        os.close(root_fd)
    return {"success": not failed, "path": str(workspace_root(workspace_id)),
            "pulled": pulled, "skipped": skipped, "failed": failed}


def _workspace_push_fd(files, timeout, workspace_id) -> Dict[str, Any]:
    try:
        home_fd = _open_home()
        try:
            root_fd = _open_chain(home_fd, _root_parts(workspace_id))
        finally:
            os.close(home_fd)
    except OSError as e:
        return {"success": False, "pushed": 0,
                "failed": [{"path": "*", "error": f"no workspace: {e}"}]}
    pushed, failed = 0, []
    try:
        for entry in files or []:
            rel = (entry or {}).get("path") or ""
            url = (entry or {}).get("url") or ""
            parts = _parts(rel)
            if parts is None or not url:
                failed.append({"path": rel, "error": "invalid path or url"})
                continue
            result = _push_from(root_fd, parts, url,
                                (entry or {}).get("content_type") or "application/octet-stream",
                                timeout)
            if result.get("success"):
                pushed += 1
            else:
                failed.append({"path": rel, "error": result.get("error")})
    finally:
        os.close(root_fd)
    return {"success": not failed, "pushed": pushed, "failed": failed}
