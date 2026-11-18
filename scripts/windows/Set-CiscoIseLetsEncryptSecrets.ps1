<#
.SYNOPSIS
    Stores the secrets for CiscoIseLetsEncrypt in .NET user secrets of the CURRENT Windows user.
.DESCRIPTION
    Run this as the account the scheduled task runs as, e.g.:
        runas /user:EXAMPLE\svc-iseacme "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Program Files\CiscoIseLetsEncrypt\Set-CiscoIseLetsEncryptSecrets.ps1"
    The secrets are written to %APPDATA%\Microsoft\UserSecrets\<id>\secrets.json of that user.
    Values are entered hidden and passed to the program on stdin (never on the command line).
    Leave a value empty to keep the existing one.
.EXAMPLE
    .\Set-CiscoIseLetsEncryptSecrets.ps1
.EXAMPLE
    .\Set-CiscoIseLetsEncryptSecrets.ps1 -Keys 'DnsProxy:Token'
#>
[CmdletBinding()]
param(
    [string] $ExePath = (Join-Path $PSScriptRoot 'CiscoIseLetsEncrypt.exe'),
    [ValidateSet('Ise:Username', 'Ise:Password', 'DnsProxy:Token', 'Radius:Secret', 'Backup:Password')]
    [string[]] $Keys = @('Ise:Username', 'Ise:Password', 'DnsProxy:Token', 'Radius:Secret', 'Backup:Password')
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path $ExePath)) { throw "CiscoIseLetsEncrypt.exe not found: $ExePath" }

Write-Host "Storing secrets for Windows user $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
foreach ($key in $Keys) {
    if ($key -eq 'Ise:Username') {
        $value = Read-Host "Value for $key (empty = keep)"
    }
    else {
        $secure = Read-Host "Value for $key (hidden, empty = keep)" -AsSecureString
        $value = [Net.NetworkCredential]::new('', $secure).Password
    }
    if ([string]::IsNullOrWhiteSpace($value)) {
        Write-Host "  $key unchanged"
        continue
    }
    $value | & $ExePath -SetSecret $key
    $value = $null
    if ($LASTEXITCODE -ne 0) { throw "Storing $key failed (exit code $LASTEXITCODE)" }
}
