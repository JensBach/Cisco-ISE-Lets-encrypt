<#
.SYNOPSIS
    Registers a daily Windows scheduled task that runs Invoke-CiscoIseLetsEncrypt.ps1.
.DESCRIPTION
    Run as administrator. The task runs as a dedicated service account (whether or not it is logged on),
    because the secrets are stored in that account's .NET user secrets.
    -User SYSTEM runs the task as Local System (no password); the secrets must then be stored as SYSTEM.
    The account needs "Log on as a batch job" (granted automatically by Task Scheduler for local admins;
    otherwise via GPO / secpol.msc) and modify rights on the log folder.
.EXAMPLE
    .\Register-CiscoIseLetsEncryptTask.ps1 -User 'EXAMPLE\svc-iseacme' -At 03:15
.EXAMPLE
    .\Register-CiscoIseLetsEncryptTask.ps1 -User SYSTEM -At 03:15
.EXAMPLE
    .\Register-CiscoIseLetsEncryptTask.ps1 -Unregister
#>
[CmdletBinding(DefaultParameterSetName = 'Register')]
param(
    [Parameter(ParameterSetName = 'Register', Mandatory)]
    [string] $User,
    [Parameter(ParameterSetName = 'Register')]
    [datetime] $At = '03:15',
    [Parameter(ParameterSetName = 'Register')]
    [string] $InstallDirectory = $PSScriptRoot,
    [Parameter(ParameterSetName = 'Register')]
    [string] $ConfigFile = (Join-Path $PSScriptRoot 'jobs.psd1'),
    [string] $TaskName = 'CiscoIseLetsEncrypt',
    [string] $TaskPath = '\',
    [Parameter(ParameterSetName = 'Unregister', Mandatory)]
    [switch] $Unregister
)

$ErrorActionPreference = 'Stop'

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script as administrator.'
}

if ($Unregister) {
    Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false
    Write-Host "Task $TaskPath$TaskName removed."
    return
}

$script = Join-Path $InstallDirectory 'Invoke-CiscoIseLetsEncrypt.ps1'
foreach ($f in $script, $ConfigFile, (Join-Path $InstallDirectory 'CiscoIseLetsEncrypt.exe')) {
    if (-not (Test-Path $f)) { throw "Not found: $f" }
}

$isSystem = $User -in 'SYSTEM', 'NT AUTHORITY\SYSTEM', 'LocalSystem', 'S-1-5-18'
if (-not $isSystem) {
    $credential = Get-Credential -UserName $User -Message "Password for the task account $User"
}

$action = New-ScheduledTaskAction -Execute 'powershell.exe' -WorkingDirectory $InstallDirectory `
    -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$script`" -ConfigFile `"$ConfigFile`""
# A random delay spreads the load on Let's Encrypt, as recommended for ACME clients.
$trigger = New-ScheduledTaskTrigger -Daily -At $At -RandomDelay (New-TimeSpan -Minutes 30)
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 2) `
    -MultipleInstances IgnoreNew -RestartCount 2 -RestartInterval (New-TimeSpan -Minutes 30)

$common = @{
    TaskName = $TaskName; TaskPath = $TaskPath; Action = $action; Trigger = $trigger; Settings = $settings; Force = $true
    Description = 'Renews Cisco ISE system certificates with Let''s Encrypt (CiscoIseLetsEncrypt).'
}
if ($isSystem) {
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask @common -Principal $taskPrincipal | Out-Null
    $runAs = 'Local System'
}
else {
    Register-ScheduledTask @common -User $credential.UserName -Password $credential.GetNetworkCredential().Password -RunLevel Limited | Out-Null
    $runAs = $credential.UserName
}

Write-Host "Task $TaskPath$TaskName registered: daily at $($At.ToString('HH:mm')) (+0-30 min) as $runAs."
Write-Host "Test it now with:  Start-ScheduledTask -TaskName '$TaskName'"
