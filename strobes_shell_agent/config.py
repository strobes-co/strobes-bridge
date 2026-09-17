"""Configuration and persistent state for the shell agent.

Loads settings from (in priority order):
1. CLI flags (--url, --api-key, etc.)
2. Environment variables (STROBES_URL, STROBES_API_KEY, etc.)
3. .env file in current directory or ~/.strobes-shell-agent/.env
4. ~/.strobes-shell-agent/config.json (for persistent bridge_id only)
"""

import json
import os
import uuid
from pathlib import Path

from dotenv import load_dotenv

CONFIG_DIR = Path.home() / ".strobes-shell-agent"
CONFIG_FILE = CONFIG_DIR / "config.json"

# Load .env from cwd first, then from config dir
load_dotenv(dotenv_path=Path.cwd() / ".env", override=False)
load_dotenv(dotenv_path=CONFIG_DIR / ".env", override=False)


def get_or_create_bridge_id() -> str:
    """Get the persistent bridge_id, creating one on first run."""
    # Check env first
    env_id = os.environ.get("STROBES_BRIDGE_ID")
    if env_id:
        return env_id
    # Fall back to config file
    config = _load_config()
    if "bridge_id" not in config:
        config["bridge_id"] = str(uuid.uuid4())
        _save_config(config)
    return config["bridge_id"]


def get_env(key: str, default: str = "") -> str:
    """Get a config value from environment."""
    return os.environ.get(key, default)


# --- Execution sandbox / network egress control ---------------------------
# Every AI-issued command runs inside an OS sandbox whose only permitted network
# destination is the bridge's egress proxy, which applies the policy below. The
# initial scope comes from the environment or the CLI; the platform can replace
# it at runtime via ``sandbox_configure``.

def _split_list(raw: str) -> list:
    """Parse a comma/space/newline-separated env list of hosts/IPs/CIDRs."""
    if not raw:
        return []
    return [chunk for chunk in raw.replace(",", " ").split() if chunk.strip()]


def network_policy_env() -> dict:
    """Read the initial egress policy from the environment.

    Returns a plain dict so :mod:`config` stays free of a dependency on
    :mod:`netpolicy`; ``sandbox`` turns it into a ``NetworkPolicy``.

    Open by default: an unconfigured bridge must not break every command it is
    handed. Metadata and link-local stay denied regardless — that carve-out is
    what keeps an SSRF from becoming stolen cloud credentials.
    """
    return {
        "allow": _split_list(os.environ.get("STROBES_NET_ALLOW", "")),
        "deny": _split_list(os.environ.get("STROBES_NET_DENY", "")),
        "default_egress": (
            "deny" if os.environ.get("STROBES_NET_DEFAULT", "allow").strip().lower() == "deny"
            else "allow"
        ),
        "block_metadata": os.environ.get(
            "STROBES_NET_BLOCK_METADATA", "1"
        ).strip().lower() not in ("0", "false", "no"),
    }


def _load_config() -> dict:
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _save_config(config: dict):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2))
