#Requires -Version 5.1
<#
.SYNOPSIS
    CorpVPN quickstart for Windows: runs deploy/quickstart.sh inside WSL.
.DESCRIPTION
    The installer drives Ansible, which does not run natively on Windows, so the
    work happens in WSL (any Linux distribution with bash, ssh and
    ansible-playbook). This wrapper only checks the prerequisites and hands over.
    Configuration lives in deploy\quickstart.env (see quickstart.env.example).
.PARAMETER EnvFile
    Path to the quickstart config file. Defaults to deploy\quickstart.env.
.EXAMPLE
    .\deploy\quickstart.ps1
.EXAMPLE
    .\deploy\quickstart.ps1 -EnvFile C:\configs\corpvpn.env
#>
param(
    [string]$EnvFile = ""
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot  = Split-Path -Parent $ScriptDir
if (-not $EnvFile) { $EnvFile = Join-Path $ScriptDir "quickstart.env" }

function Stop-WithMessage {
    param([string]$Message)
    Write-Host "[x] $Message" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $EnvFile)) {
    Stop-WithMessage "Config not found: $EnvFile`n    Copy deploy\quickstart.env.example to deploy\quickstart.env and fill it in."
}

$wsl = Get-Command wsl -ErrorAction SilentlyContinue
if (-not $wsl) {
    Write-Host "[x] WSL is not installed." -ForegroundColor Red
    Write-Host ""
    Write-Host "    The installer needs bash, ssh and Ansible. Either:"
    Write-Host "      1. run 'wsl --install', restart, install ansible in the distribution"
    Write-Host "         (sudo apt install ansible), then run this script again; or"
    Write-Host "      2. copy the repository to a Linux or macOS machine and run"
    Write-Host "         ./deploy/quickstart.sh there."
    exit 1
}

$WslRepoRoot = (& wsl wslpath -u ($RepoRoot -replace '\\', '/')).Trim()
$WslEnvFile  = (& wsl wslpath -u ((Resolve-Path $EnvFile).Path -replace '\\', '/')).Trim()
if (-not $WslRepoRoot -or -not $WslEnvFile) {
    Stop-WithMessage "WSL could not translate the repository path; is a distribution installed and running?"
}

& wsl bash -lc "command -v ansible-playbook >/dev/null" | Out-Null
if ($LASTEXITCODE -ne 0) {
    Stop-WithMessage "ansible-playbook not found in WSL. Install it there first: sudo apt install ansible"
}

Write-Host "[*] Running deploy/quickstart.sh in WSL ..." -ForegroundColor Cyan
& wsl bash -lc "cd '$WslRepoRoot' && QS_ENV='$WslEnvFile' bash deploy/quickstart.sh"
exit $LASTEXITCODE
