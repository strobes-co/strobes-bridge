# Strobes Shell Agent

A lightweight daemon that connects your machine to the [Strobes](https://strobes.co) platform, enabling AI agents to execute commands remotely — without SSH, firewall rules, or inbound ports.

Think of it as "Local Browser" but for shell access: the agent runs on your machine, connects **outbound** to Strobes via WebSocket, and the AI agent sends commands through that tunnel.

```
┌──────────────────────┐          WebSocket          ┌──────────────────────┐
│   Strobes Platform   │◄──── outbound connection ───│  Your Machine        │
│                      │                              │                      │
│  AI Agent calls      │   ── shell_execute ───►      │  strobes-shell-agent │
│  workspace_execute   │   ◄── stdout/stderr ──       │  (this daemon)       │
│  _shell_command()    │                              │                      │
└──────────────────────┘                              └──────────────────────┘
```

## Why?

| | SSH Shell | Shell Agent (Bridge) |
|---|---|---|
| **Setup** | Need hostname, port, SSH keys, firewall rules | Just run the daemon |
| **Network** | Platform connects _to_ your machine (inbound) | Daemon connects _to_ platform (outbound) |
| **Credentials** | SSH keys stored on platform | API key only |
| **Firewall** | Port 22 must be open inbound | Only outbound HTTPS needed |
| **NAT/VPN** | Needs port forwarding or VPN | Works behind NAT, VPN, anything |

## Quick Start

### 1. Create a Bridge Shell in Strobes

Go to **AI > Shells > Create Shell**, select **Bridge** type, and note the `bridge_id`.

### 2. Get your API Key

Go to **Settings > API Keys** and copy your key.

### 3. Install the agent

**Option A: One-line install (recommended)** — downloads the binary (sandbox pack
embedded: nmap/nuclei/… run offline), walks you through setup, and registers a service
that starts on boot.

```bash
# Linux / macOS
curl -fsSL https://raw.githubusercontent.com/strobes-co/strobes-bridge/main/install.sh | bash
```
```powershell
# Windows (PowerShell)
irm https://raw.githubusercontent.com/strobes-co/strobes-bridge/main/install.ps1 | iex
```

Non-interactive (CI/automation): set `STROBES_URL`, `STROBES_API_KEY`, `STROBES_ORG_ID`
in the environment first. Manage the service afterwards:

| | Linux (systemd) | macOS (launchd) | Windows (task) |
|---|---|---|---|
| start/stop | `systemctl --user start\|stop co.strobes.shell-agent` | `launchctl load\|unload -w ~/Library/LaunchAgents/co.strobes.shell-agent.plist` | `Start\|Stop-ScheduledTask -TaskName StrobesShellAgent` |
| verify tools | `strobes-shell-agent selftest` | same | same |
| uninstall | `install.sh \| bash -s -- --uninstall` | same | `$env:STROBES_UNINSTALL='1'; irm …/install.ps1 \| iex` |

**Option B: Pre-built binary (manual, no Python needed)**

Download from [Releases](https://github.com/strobes-co/strobes-bridge/releases):

```bash
# Linux
curl -L -o strobes-shell-agent https://github.com/strobes-co/strobes-agent-shell/releases/latest/download/strobes-shell-agent-linux-amd64
chmod +x strobes-shell-agent

# macOS (Apple Silicon)
curl -L -o strobes-shell-agent https://github.com/strobes-co/strobes-agent-shell/releases/latest/download/strobes-shell-agent-macos-arm64
chmod +x strobes-shell-agent

# Run
./strobes-shell-agent connect \
  --url https://app.strobes.co \
  --api-key sk-your-api-key \
  --org-id your-org-uuid \
  --bridge-id your-bridge-id \
  --name "my-server"
```

**Option B: Using .env file**

```bash
# Download the binary (see above), then:
cat > .env << EOF
STROBES_URL=https://app.strobes.co
STROBES_API_KEY=sk-your-api-key
STROBES_ORG_ID=your-org-uuid
STROBES_BRIDGE_ID=your-bridge-id
STROBES_SHELL_NAME=my-server
EOF

./strobes-shell-agent connect
```

**Option C: Docker**

```bash
cat > .env << EOF
STROBES_URL=https://app.strobes.co
STROBES_API_KEY=sk-your-api-key
STROBES_ORG_ID=your-org-uuid
STROBES_BRIDGE_ID=your-bridge-id
STROBES_SHELL_NAME=my-server
EOF

docker run --rm --env-file .env ghcr.io/strobes-co/strobes-agent-shell:latest connect
```

**Option D: Docker Compose**

```bash
cp .env.example .env
# Edit .env with your values
docker compose up -d
```

**Option E: From source (development)**

```bash
git clone https://github.com/strobes-co/strobes-agent-shell.git
cd strobes-agent-shell
pip install .
strobes-shell-agent connect --url https://app.strobes.co --api-key sk-xxx --org-id xxx
```

### 4. Attach to a Workspace

In Strobes, go to your workspace settings and attach the bridge shell. All AI agent code execution in that workspace now routes through your machine.

## Configuration

All options can be set via CLI flags, environment variables, or a `.env` file.

| CLI Flag | Env Variable | Required | Description |
|---|---|---|---|
| `--url` | `STROBES_URL` | Yes | Strobes platform URL |
| `--api-key` | `STROBES_API_KEY` | Yes | API key from Settings |
| `--org-id` | `STROBES_ORG_ID` | Yes | Organization UUID |
| `--bridge-id` | `STROBES_BRIDGE_ID` | No | Auto-generated on first run |
| `--name` | `STROBES_SHELL_NAME` | No | Display name (defaults to hostname) |
| `--cwd` | `STROBES_CWD` | No | Working directory for commands |
| `-v` | `STROBES_VERBOSE` | No | Enable debug logging |
| — | `STROBES_PACK_PATH` | No | Point at a specific pre-extracted pack |
| — | `STROBES_PACK_DIR` | No | Pack lookup/extract dir (default `~/.strobes-shell-agent/pack`) |
| — | `STROBES_PACK_DISABLE` | No | Set to `1` to ignore the pack and use only host tools |
| — | `STROBES_PACK_URL` | No | Optional: fetch a pack if none is bundled (not used by default) |

The `.env` file is loaded from the current directory or `~/.strobes-shell-agent/.env`.

### Pre-installed security tools (sandbox pack)

So the agent can run a full pentest toolkit **without you installing anything**, a
self-contained **sandbox pack** — a relocatable Python runtime + CLI tools + templates —
ships **inside the artifact**. The shipped binary/image bundle the **internal-ad** toolset:

- **Web/CLI:** `nmap` (+`ncat`/`nping`), `nuclei` (with the full **nuclei-templates**),
  `httpx`, `ffuf`, `gobuster`, `subfinder`, `dnsx`.
- **Internal / Active Directory:** `nxc` (NetExec), impacket (`secretsdump.py`,
  `GetUserSPNs.py`, `ntlmrelayx.py`, …), `certipy`, `bloodhound-python`, `mitm6`, `Coercer`,
  `smbmap`, `bloodyAD`, `ldapdomaindump`, `lsassy`, **Responder**, **enum4linux-ng**.
- **Python:** `boto3`, `reportlab`, `curl_cffi`, `cryptography`, … (the pack's own interpreter).

- **Standalone binary:** the pack is **embedded in the executable**. On first run it self-extracts
  once to `~/.strobes-shell-agent/pack` and is reused after. One file, nothing else to download.
- **Docker image:** the pack is **baked into the image** at build time (`STROBES_PACK_DIR=/opt/strobes-pack`).

**Default is fully offline — no runtime download, no external URL.** Commands the agent sends
resolve transparently to the pack's tools and interpreter (`NMAPDIR` and nuclei templates wired
automatically); if no pack is present it falls back to host-installed tools. Verify anytime with:

```bash
strobes-shell-agent selftest      # runs nmap + nuclei(+templates) + python offline
```

Coverage: Linux x86_64/aarch64 (nmap runs on any Linux incl. Alpine), macOS, Windows.
See [`sandbox_pack/README.md`](sandbox_pack/README.md).

- **Air-gapped:** already covered — the pack travels inside the binary/image. (Or point
  `STROBES_PACK_PATH` at a pre-extracted pack.)
- **Opt out:** set `STROBES_PACK_DISABLE=1` to use only host-installed tools.
- **Optional download:** setting `STROBES_PACK_URL` lets a from-source install fetch a pack; this
  is **not** used by default and never required for the binary or Docker image.
- **nmap note:** connect scans (`-sT`) work everywhere; SYN/OS-detection need root/`cap_net_raw`
  (and the Npcap driver on Windows).

### Example .env

```env
STROBES_URL=https://app.strobes.co
STROBES_API_KEY=sk-xxxxxxxxxxxx
STROBES_ORG_ID=your-org-uuid
STROBES_SHELL_NAME=prod-server
```

## What it supports

The AI agent can use these existing tools transparently through the bridge:

- **`workspace_execute_shell_command`** — Run any shell command (`nmap`, `curl`, `nuclei`, etc.)
- **`workspace_execute_code`** — Execute Python, JavaScript, or bash code
- **File operations** — Read, write, list, upload, and download files
- **Environment discovery** — OS, architecture, installed tools

No new tools are needed — the existing Strobes agent tools route through the bridge automatically when a bridge shell is attached.

## How it works

1. The daemon connects to Strobes via WebSocket (`wss://your-instance/ws/{org_id}/shell-bridge/`)
2. Authenticates with your API key
3. Sends an `identify` message with machine metadata
4. Waits for commands from the platform
5. Executes commands via subprocess, returns stdout/stderr/exit_code
6. Auto-reconnects with exponential backoff on disconnect
7. Periodic ping/pong keepalive (every 30s)

## Docker

### Build locally

```bash
docker build -t strobes/shell-agent .
```

### Run

```bash
docker run --rm --env-file .env strobes/shell-agent connect
```

### Docker Compose

```yaml
services:
  shell-agent:
    image: ghcr.io/strobes-co/strobes-agent-shell:latest
    env_file: .env
    restart: unless-stopped
    volumes:
      - ./workspace:/workspace  # Optional: mount files into the agent
```

## Development

```bash
git clone https://github.com/strobes-co/strobes-agent-shell.git
cd strobes-agent-shell
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run locally
strobes-shell-agent connect --url http://localhost:8001 --api-key sk-xxx --org-id xxx -v
```

## Commands

```bash
# Connect to Strobes (main command)
strobes-shell-agent connect [OPTIONS]

# Connect and detach into the background (UNIX only)
strobes-shell-agent connect --daemon [OPTIONS]

# Check whether the daemonised agent is running
strobes-shell-agent status

# Stop the daemonised agent
strobes-shell-agent stop

# Register as a system service (auto-starts on boot, auto-restarts on crash)
strobes-shell-agent install-service [OPTIONS]
strobes-shell-agent uninstall-service

# Show the persistent bridge ID for this machine
strobes-shell-agent show-id

# Show version
strobes-shell-agent --version
```

## Run as a daemon (UNIX)

For ad-hoc background runs you can detach the process from the terminal:

```bash
strobes-shell-agent connect \
  --url https://app.strobes.co \
  --api-key sk-xxx \
  --org-id YOUR-ORG \
  --name "my-server" \
  --daemon
```

- PID file → `~/.strobes-shell-agent/agent.pid`
- Log file → `~/.strobes-shell-agent/agent.log`
- Manage with `strobes-shell-agent status` / `stop`.

`--daemon` is not the right tool for production — it doesn't survive reboots
and isn't supervised. For that, install as a system service (next section).

## Run as a system service (recommended for servers)

`install-service` registers the agent with the platform's native service
manager so it starts on boot and is restarted automatically if it crashes.

### macOS (launchd)

```bash
strobes-shell-agent install-service \
  --url https://app.strobes.co \
  --api-key sk-xxx \
  --org-id YOUR-ORG \
  --name "my-laptop"
```

This writes `~/Library/LaunchAgents/co.strobes.shell-agent.plist` with
`KeepAlive=true` and `RunAtLoad=true`, and loads it via `launchctl`. Logs:

- stdout → `~/Library/Logs/strobes-shell-agent.out.log`
- stderr → `~/Library/Logs/strobes-shell-agent.err.log`

Stop / remove:

```bash
strobes-shell-agent uninstall-service
```

### Linux (systemd)

```bash
# Per-user service (default for non-root):
strobes-shell-agent install-service \
  --url https://app.strobes.co \
  --api-key sk-xxx \
  --org-id YOUR-ORG \
  --name "my-server"

systemctl --user status co.strobes.shell-agent.service
journalctl --user -u co.strobes.shell-agent.service -f

# System-wide (auto-detected when run as root):
sudo strobes-shell-agent install-service \
  --url https://app.strobes.co --api-key sk-xxx --org-id YOUR-ORG --scope system

sudo systemctl status co.strobes.shell-agent
```

The generated unit uses `Restart=always` + `RestartSec=5` so the agent
recovers from any crash, and `After=network-online.target` so it waits for
the network at boot.

Remove with `strobes-shell-agent uninstall-service` (add `--scope system`
if it was installed system-wide).

> User-scope systemd units only run while the user is logged in unless you
> enable linger: `sudo loginctl enable-linger $USER`.

### Windows

`install-service` is not implemented for Windows. Use one of:

```powershell
# Option A: NSSM (Non-Sucking Service Manager)
nssm install StrobesShellAgent "C:\path\to\strobes-shell-agent.exe" `
  connect --url https://app.strobes.co --api-key sk-xxx --org-id YOUR-ORG

# Option B: Task Scheduler — create a task that runs at logon and
# restarts the program on failure.
```

## Reliability

- **Auto-reconnect**: exponential backoff (1s → 60s cap) on any disconnect.
  Wake-up is immediate when the socket closes — the ping interval no longer
  delays reconnection.
- **Process-tree kill on timeout**: when a shell command times out the
  agent kills the whole process group, so any child processes the command
  spawned also die.
- **Graceful shutdown**: SIGINT / SIGTERM interrupts the current backoff
  immediately; no waiting up to 60s to exit.
- **Cross-platform**: tested on macOS (host) and Linux (Docker); Windows
  binary is built and smoke-tested in CI.

## Security

- The daemon only accepts commands from the authenticated Strobes platform
- Commands execute with the permissions of the user running the daemon
- No inbound ports are opened — all connections are outbound
- API key authentication via the existing Strobes credentials system
- Consider running in a Docker container or as a limited user for isolation

## License

Proprietary - Strobes Security
