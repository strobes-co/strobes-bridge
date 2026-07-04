# Strobes Shell Bridge Agent - one-line installer (Windows).
#
#   irm https://raw.githubusercontent.com/strobes-co/strobes-bridge/main/install.ps1 | iex
#
# Downloads the prebuilt .exe (sandbox pack embedded - nmap/nuclei/... run offline),
# installs it, walks you through setup, writes a .env, and registers a Scheduled Task
# that runs at logon and restarts on failure (Windows has no native service for a
# console app; the task is the "service").
#
# Non-interactive: set $env:STROBES_URL / $env:STROBES_API_KEY / $env:STROBES_ORG_ID first.
# Uninstall:  set $env:STROBES_UNINSTALL="1" before piping, or run: .\install.ps1 -Uninstall
[CmdletBinding()]
param([switch]$Uninstall, [switch]$NoService)

$ErrorActionPreference = "Stop"
$Repo      = "strobes-co/strobes-bridge"
$Asset     = "strobes-shell-agent-windows-amd64.exe"

# Where to fetch the .exe from. When this installer is served by a Strobes tenant
# (AI -> Shells -> one-line install), the tenant's install-script proxy rewrites
# the token below to its own same-origin download endpoint, so the executable is
# pulled from the tenant too (no GitHub dependency; works behind proxies that
# block GitHub). Left as the token when fetched from GitHub raw -> use Releases.
$DownloadBase = "__STROBES_DOWNLOAD_BASE__"
if ($DownloadBase -like "*__STROBES_DOWNLOAD_BASE__*") { $DownloadBase = "" }
$TaskName  = "StrobesShellAgent"
$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\StrobesShellAgent"
$Target     = Join-Path $InstallDir "strobes-shell-agent.exe"
$ConfigDir  = Join-Path $env:USERPROFILE ".strobes-shell-agent"

function Info($m){ Write-Host $m -ForegroundColor Cyan }
function Ok($m){ Write-Host $m -ForegroundColor Green }
function Fail($m){ Write-Host "error: $m" -ForegroundColor Red; exit 1 }

if ($env:STROBES_UNINSTALL -eq "1") { $Uninstall = $true }

if ($Uninstall) {
  Info "Removing Strobes Shell Agent..."
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
  if (Test-Path $InstallDir) { Remove-Item -Recurse -Force $InstallDir }
  Ok "Uninstalled."
  return
}

# --- download --------------------------------------------------------------
if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null }
if ($DownloadBase) {
  # Tenant proxy: {tenant}/api/v1/organizations/{org}/ai/bridge/download/?asset=...
  $sep = if ($DownloadBase.Contains("?")) { "&" } else { "?" }
  $Url = "${DownloadBase}${sep}asset=$Asset"
} else {
  $Url = "https://github.com/$Repo/releases/latest/download/$Asset"
}
Info "Downloading $Asset..."
try { Invoke-WebRequest -Uri $Url -OutFile $Target -UseBasicParsing } catch { Fail "download failed: $Url" }
Ok "Installed: $Target"

# add install dir to the user PATH
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$InstallDir*") {
  [Environment]::SetEnvironmentVariable("Path", "$userPath;$InstallDir", "User")
  $env:Path = "$env:Path;$InstallDir"
  Info "Added $InstallDir to your PATH (restart terminals to pick it up)."
}

if ($NoService) {
  Ok "`nBinary installed."
  Write-Host "   Run:  strobes-shell-agent connect --url <URL> --api-key <KEY> --org-id <ORG> --name <NAME>"
  Write-Host "   Verify tools:  strobes-shell-agent selftest"
  return
}

# --- interactive setup -----------------------------------------------------
Info "`nSetup (from Strobes: AI -> Shells -> Create Shell [Bridge], and Settings -> API Keys):"
$u = $env:STROBES_URL;        if (-not $u) { $u = Read-Host "  Strobes URL [https://app.strobes.co]" }
if (-not $u) { $u = "https://app.strobes.co" }
$k = $env:STROBES_API_KEY;    if (-not $k) { $sec = Read-Host "  API key" -AsSecureString
  $k = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)) }
$o = $env:STROBES_ORG_ID;     if (-not $o) { $o = Read-Host "  Organization ID" }
$n = $env:STROBES_SHELL_NAME; if (-not $n) { $n = Read-Host "  Shell name [$env:COMPUTERNAME]" }
if (-not $n) { $n = $env:COMPUTERNAME }
if (-not $u -or -not $k -or -not $o) { Fail "URL, API key and Org ID are required" }

# --- write .env (keeps the secret off the task command line) ---------------
if (-not (Test-Path $ConfigDir)) { New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null }
@"
STROBES_URL=$u
STROBES_API_KEY=$k
STROBES_ORG_ID=$o
STROBES_SHELL_NAME=$n
"@ | Set-Content -Path (Join-Path $ConfigDir ".env") -Encoding ASCII
# config.py loads ~/.strobes-shell-agent/.env, so the task just runs `connect`.

# --- register the Scheduled Task ("service") -------------------------------
Info "Registering scheduled task '$TaskName' (runs at logon, restarts on failure)..."
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
$action   = New-ScheduledTaskAction -Execute $Target -Argument "connect"
$trigger  = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
              -StartWhenAvailable -RestartInterval (New-TimeSpan -Minutes 1) -RestartCount 999
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
  -Description "Strobes Shell Bridge Agent" -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

Ok "`nInstalled and running as a scheduled task."
Write-Host "   Verify tools:  strobes-shell-agent selftest"
Write-Host "   Start/stop:    Start-ScheduledTask -TaskName $TaskName  /  Stop-ScheduledTask -TaskName $TaskName"
Write-Host "   Status:        Get-ScheduledTask -TaskName $TaskName"
Write-Host "   Uninstall:     irm .../install.ps1 | iex   with `$env:STROBES_UNINSTALL='1'"
