[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [Alias("Host")]
    [string]$TargetHost,

    [Parameter(Mandatory = $true)]
    [string]$SshKey,

    [string]$SshUser = "root",
    [string]$VarsFile = "",
    [string]$SecretsFile = "",

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ExtraArgs
)

$RootDir = Split-Path -Parent $PSScriptRoot
$PlaybookDir = Join-Path $RootDir "deploy\ansible"
$Playbook = Join-Path $PlaybookDir "site.yml"

if (-not $VarsFile) {
    $VarsFile = Join-Path $PlaybookDir "group_vars\all.yml"
}

if (-not $SecretsFile) {
    $SecretsFile = Join-Path $PlaybookDir "group_vars\all.secrets.yml"
}

if (-not (Get-Command ansible-playbook -ErrorAction SilentlyContinue)) {
    throw "ansible-playbook is required"
}

if (-not (Test-Path -LiteralPath $SshKey)) {
    throw "SSH key not found: $SshKey"
}

$Command = @(
    "ansible-playbook",
    $Playbook,
    "-i", "$TargetHost,",
    "-u", $SshUser,
    "--private-key", $SshKey
)

if (Test-Path -LiteralPath $SecretsFile) {
    $Command += @("-e", "@$SecretsFile")
}
else {
    Write-Warning "Secrets file not found: $SecretsFile"
}

if (Test-Path -LiteralPath $VarsFile) {
    $Command += @("-e", "@$VarsFile")
}
else {
    Write-Warning "Vars file not found: $VarsFile"
}

if ($ExtraArgs) {
    $Command += $ExtraArgs
}

& $Command[0] $Command[1..($Command.Length - 1)]
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
