#Requires -Version 5.1
<#
.SYNOPSIS
    VPN Panel — Quickstart installer for Windows.
.DESCRIPTION
    Reads deploy/quickstart.env and orchestrates the full cascade installation.
    If WSL (Windows Subsystem for Linux) is available, delegates all work to
    deploy/quickstart.sh running inside WSL — this is the recommended path.
    Without WSL, generates the Ansible config files locally and prints
    instructions for running the remaining steps from a Linux machine.
.PARAMETER EnvFile
    Path to the quickstart config file. Defaults to deploy\quickstart.env.
.PARAMETER NoWsl
    Skip WSL detection and generate config files only (for CI or custom setups).
.EXAMPLE
    .\deploy\quickstart.ps1
.EXAMPLE
    .\deploy\quickstart.ps1 -EnvFile C:\myconfig\quickstart.env
#>
param(
    [string]$EnvFile = "",
    [switch]$NoWsl
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot   = Split-Path -Parent $ScriptDir
$DefaultEnv = Join-Path $ScriptDir "quickstart.env"

if (-not $EnvFile) { $EnvFile = $DefaultEnv }

# ── Helpers ─────────────────────────────────────────────────────────────────

function Write-Step  { param([string]$msg) Write-Host "`n━━━ $msg " -ForegroundColor Cyan }
function Write-Ok    { param([string]$msg) Write-Host "  [✓] $msg" -ForegroundColor Green }
function Write-Info  { param([string]$msg) Write-Host "  [•] $msg" -ForegroundColor Blue }
function Write-Warn  { param([string]$msg) Write-Host "  [!] $msg" -ForegroundColor Yellow }
function Write-Fail  { param([string]$msg) Write-Error "  [✗] $msg" }

function Read-EnvFile {
    param([string]$Path)
    $vars = @{}
    Get-Content $Path | Where-Object { $_ -match '^\s*[A-Z_]+=.*' -and $_ -notmatch '^\s*#' } | ForEach-Object {
        $parts = $_ -split '=', 2
        $key   = $parts[0].Trim()
        $value = if ($parts.Count -gt 1) { $parts[1].Trim() } else { '' }
        $vars[$key] = $value
    }
    return $vars
}

function Get-EnvValue {
    param([hashtable]$Vars, [string]$Key, [string]$Default = '')
    if ($Vars.ContainsKey($Key) -and $Vars[$Key] -ne '') { return $Vars[$Key] }
    return $Default
}

function Test-WslAvailable {
    try { $null = Get-Command wsl -ErrorAction Stop; return $true } catch { return $false }
}

# ── Load and validate config ─────────────────────────────────────────────────

if (-not (Test-Path $EnvFile)) {
    Write-Fail "Config not found: $EnvFile`n  Copy deploy\quickstart.env.example to deploy\quickstart.env and fill it in."
}

Write-Host "`nVPN Panel — Quickstart (Windows)" -ForegroundColor Green
Write-Info "Reading config from: $EnvFile"

$cfg = Read-EnvFile -Path $EnvFile

$ServerAIp       = Get-EnvValue $cfg 'SERVER_A_IP'
$SshKey          = Get-EnvValue $cfg 'SSH_KEY'
$PanelToken      = Get-EnvValue $cfg 'PANEL_SECRET_TOKEN'
$ServerADomain   = Get-EnvValue $cfg 'SERVER_A_DOMAIN'
$ServerBIp       = Get-EnvValue $cfg 'SERVER_B_IP'
$ServerBDomain   = Get-EnvValue $cfg 'SERVER_B_DOMAIN'
$SshUser         = Get-EnvValue $cfg 'SSH_USER' 'root'
$ServerBSshKey   = Get-EnvValue $cfg 'SERVER_B_SSH_KEY' $SshKey
$BotToken        = Get-EnvValue $cfg 'TELEGRAM_BOT_TOKEN'
$AdminIds        = Get-EnvValue $cfg 'TELEGRAM_ADMIN_IDS'
$BotUsername     = Get-EnvValue $cfg 'TELEGRAM_BOT_USERNAME'
$RealityName     = Get-EnvValue $cfg 'REALITY_SERVER_NAME' 'www.microsoft.com'

if (-not $ServerAIp)   { Write-Fail "SERVER_A_IP is required" }
if (-not $SshKey)      { Write-Fail "SSH_KEY is required" }
if (-not $PanelToken)  { Write-Fail "PANEL_SECRET_TOKEN is required" }
if ($PanelToken -eq 'replace-with-long-random-token') {
    Write-Fail "PANEL_SECRET_TOKEN is still the placeholder.`n  Generate one with: openssl rand -base64 32  (in WSL or Git Bash)"
}

$ServerAHost = if ($ServerADomain) { $ServerADomain } else { $ServerAIp }
$ServerBHost = if ($ServerBDomain) { $ServerBDomain } elseif ($ServerBIp) { $ServerBIp } else { '' }
$TwoServer   = $ServerBIp -ne ''
$BotEnabled  = $BotToken -ne ''

Write-Info "Server A (panel + ingress): $ServerAIp$(if ($ServerADomain) { " ($ServerADomain)" })"
if ($TwoServer) { Write-Info "Server B (relay):           $ServerBIp$(if ($ServerBDomain) { " ($ServerBDomain)" })" }
if ($BotEnabled) { Write-Info "Telegram bot:               @$BotUsername" }

# ── Attempt WSL delegation ───────────────────────────────────────────────────

if (-not $NoWsl -and (Test-WslAvailable)) {
    Write-Step "WSL detected — delegating to quickstart.sh"
    Write-Info "Running deploy/quickstart.sh inside WSL ..."

    $WslRepoRoot = wsl wslpath -u $RepoRoot.Replace('\', '/')
    $WslEnvFile  = wsl wslpath -u $EnvFile.Replace('\', '/')

    $exitCode = 0
    try {
        wsl bash -c "cd '$WslRepoRoot' && QS_ENV='$WslEnvFile' bash deploy/quickstart.sh"
        $exitCode = $LASTEXITCODE
    } catch {
        $exitCode = 1
    }

    if ($exitCode -ne 0) {
        Write-Fail "quickstart.sh exited with code $exitCode"
    }
    exit 0
}

# ── Fallback: generate config files only ────────────────────────────────────

Write-Step "Generating Ansible config files locally"
Write-Warn "WSL not found (or -NoWsl specified). Generating Ansible files and printing next steps."
Write-Warn "Run the full installer from a Linux machine or enable WSL."

$AnsibleDir = Join-Path $ScriptDir "ansible"

# inventory/hosts.yml
$InvDir = Join-Path $AnsibleDir "inventory"
if (-not (Test-Path $InvDir)) { New-Item -ItemType Directory -Path $InvDir | Out-Null }
$HostsContent = @"
all:
  hosts:
    vpn-panel:
      ansible_host: $ServerAIp
      ansible_user: $SshUser
      ansible_ssh_private_key_file: $SshKey
"@
Set-Content -Path (Join-Path $InvDir "hosts.yml") -Value $HostsContent -Encoding utf8
Write-Ok "inventory/hosts.yml"

# group_vars/all.yml
$VarsDir = Join-Path $AnsibleDir "group_vars"
if (-not (Test-Path $VarsDir)) { New-Item -ItemType Directory -Path $VarsDir | Out-Null }

$AllYml = @"
# Generated by quickstart.ps1
vpn_panel_server_name: "$ServerAHost"
vpn_panel_public_host: "$ServerAIp"
vpn_panel_fallback_host: "$(if ($ServerBIp) { $ServerBIp } else { $ServerAIp })"
vpn_panel_wg_endpoint_host: "$ServerAHost"
vpn_panel_xray_client_server: "$ServerAHost"
vpn_panel_xray_client_reality_server_name: "$RealityName"
vpn_panel_xray_client_reality_public_key: "FILL_AFTER_KEY_GENERATION"
vpn_panel_xray_client_reality_short_id: "FILL_AFTER_KEY_GENERATION"
vpn_panel_xray_validate_command: "/usr/local/bin/xray run -test -config {config_path}"
vpn_panel_xray_reload_command: "/bin/systemctl restart xray"
$(if ($BotEnabled) { "vpn_panel_bot_enabled: true`nvpn_panel_bot_username: `"$BotUsername`"" })
"@
Set-Content -Path (Join-Path $VarsDir "all.yml") -Value $AllYml -Encoding utf8
Write-Ok "group_vars/all.yml"

# group_vars/all.secrets.yml
$SecretsLines = @("# Generated by quickstart.ps1 — keep this file private", "panel_secret_token: `"$PanelToken`"")
if ($BotEnabled) {
    $SecretsLines += "telegram_bot_token: `"$BotToken`""
    $SecretsLines += "telegram_panel_token: `"$PanelToken`""
    if ($AdminIds) {
        $SecretsLines += "vpn_panel_admin_user_ids:"
        foreach ($id in ($AdminIds -split ',')) {
            $SecretsLines += "  - $($id.Trim())"
        }
    }
}
Set-Content -Path (Join-Path $VarsDir "all.secrets.yml") -Value ($SecretsLines -join "`n") -Encoding utf8
Write-Ok "group_vars/all.secrets.yml"

# ── Print next steps ─────────────────────────────────────────────────────────

Write-Host ""
Write-Host "Ansible config files are ready. To complete the installation:" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Option A — Install WSL (recommended for Windows):" -ForegroundColor White
Write-Host "    1. Run: wsl --install  (restart if needed)"
Write-Host "    2. Run this script again: .\deploy\quickstart.ps1"
Write-Host ""
Write-Host "  Option B — Use a Linux machine or CI runner:" -ForegroundColor White
Write-Host "    1. Copy the whole repository to a Linux host."
Write-Host "    2. Run: QS_ENV=deploy/quickstart.env bash deploy/quickstart.sh"
Write-Host ""
Write-Host "  Option C — Continue manually:" -ForegroundColor White
Write-Host "    The Ansible files are already generated. Run:"
Write-Host "    .\deploy\run.ps1 -TargetHost $ServerAIp -SshKey $SshKey"
Write-Host "    Then install Xray and place configs manually (see QUICKSTART.md)."
Write-Host ""
