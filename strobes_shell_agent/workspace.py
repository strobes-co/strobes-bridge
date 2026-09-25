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


def workspace_root() -> Path:
    """``~/.strobes/workspace``, resolved."""
    return (Path.home() / WORKSPACE_DIRNAME).resolve()


def _safe_target(rel_path: str) -> Optional[Path]:
    """Resolve ``rel_path`` inside the workspace, or None if it escapes.

    The boundary that the mount gets from its access point's root directory,
    enforced here in code because there is no access point on this machine. A
    manifest entry is data from the network: ``../../.ssh/authorized_keys`` is
    a perfectly well-formed relative path, and joining it naively would write
    outside the workspace onto a customer's machine.

    Checked after resolution, not by inspecting the string, so ``..`` segments,
    absolute paths and symlinked parents are all covered by the same test.
    """
    root = workspace_root()
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


def workspace_ensure() -> Dict[str, Any]:
    """Create the workspace directory, and report where it is.

    Called at connect, alongside the skills linking, so the path exists before
    an agent's first line of code runs. An agent that writes to a directory it
    expected to exist and finds ENOENT reports "the workspace is broken",
    which is indistinguishable from the feature being absent.
    """
    root = Path.home() / WORKSPACE_DIRNAME
    try:
        root.mkdir(parents=True, exist_ok=True)
        return {"success": True, "path": str(root)}
    except OSError as e:
        return {"success": False, "error": f"cannot create {root}: {e}"}


def workspace_pull(files: List[Dict[str, Any]], timeout: int = 300) -> Dict[str, Any]:
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

    ensured = workspace_ensure()
    if not ensured.get("success"):
        return {"success": False, "error": ensured.get("error"), "pulled": 0}

    pulled, skipped, failed = 0, 0, []
    for entry in files or []:
        rel = (entry or {}).get("path") or ""
        url = (entry or {}).get("url") or ""
        want = (entry or {}).get("sha256")
        target = _safe_target(rel)
        if target is None or not url:
            failed.append({"path": rel, "error": "invalid path or url"})
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
            pulled += 1
        else:
            failed.append({"path": rel, "error": result.get("error")})

    return {
        "success": not failed,
        "path": str(workspace_root()),
        "pulled": pulled,
        "skipped": skipped,
        "failed": failed,
    }


def workspace_scan(include_sha256: bool = True) -> Dict[str, Any]:
    """What is in the workspace on this machine, for the backend to diff.

    Returns one entry per file: relative path, size, mtime and (by default) a
    checksum. The backend compares against what it holds and mints presigned
    PUTs only for what actually differs, so an unchanged workspace uploads
    nothing.

    ``include_sha256=False`` skips hashing for a cheap size/mtime-only pass --
    worth having, because hashing a directory of large captures is not free and
    mtime alone is enough to rule most files out.
    """
    root = workspace_root()
    if not root.is_dir():
        return {"success": True, "path": str(root), "files": []}

    out: List[Dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
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


def workspace_push(files: List[Dict[str, Any]], timeout: int = 300) -> Dict[str, Any]:
    """Send named workspace files back, each to a presigned PUT.

    ``files`` is ``[{"path": ..., "url": <presigned PUT>, "content_type": ...}]``.
    The backend names what it wants; this never chooses for itself -- see the
    module docstring on why the machine does not decide what leaves it.
    """
    from .executor import file_push

    pushed, failed = 0, []
    for entry in files or []:
        rel = (entry or {}).get("path") or ""
        url = (entry or {}).get("url") or ""
        target = _safe_target(rel)
        if target is None or not url:
            failed.append({"path": rel, "error": "invalid path or url"})
            continue
        if not target.is_file():
            failed.append({"path": rel, "error": "not a file on this machine"})
            continue
        result = file_push(
            str(target), url, (entry or {}).get("content_type") or "application/octet-stream", timeout
        )
        if result.get("success"):
            pushed += 1
        else:
            failed.append({"path": rel, "error": result.get("error")})

    return {"success": not failed, "pushed": pushed, "failed": failed}
