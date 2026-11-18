<#
.SYNOPSIS
    Runs all CiscoIseLetsEncrypt jobs from jobs.psd1. This is what the scheduled task starts.
.DESCRIPTION
    Each job runs CiscoIseLetsEncrypt.exe with CommonArguments + the job's Arguments.
    The output is written to a transcript in LogDirectory, and old logs are removed.
    Exit code: 0 = all jobs OK (or nothing to do), 1 = at least one job failed, 2 = invalid configuration/arguments.
.EXAMPLE
    .\Invoke-CiscoIseLetsEncrypt.ps1 -DryRun
.EXAMPLE
    .\Invoke-CiscoIseLetsEncrypt.ps1 -Job EAP
#>
[CmdletBinding()]
param(
    [string] $ConfigFile = (Join-Path $PSScriptRoot 'jobs.psd1'),
    # Run only the named job(s).
    [string[]] $Job,
    # Pass -DryRun to every job: run the checks and show what would be done, without changes.
    [switch] $DryRun
)

$ErrorActionPreference = 'Stop'
$config = Import-PowerShellDataFile -Path $ConfigFile
$exe = if ($config.ExePath) { $config.ExePath } else { Join-Path $PSScriptRoot 'CiscoIseLetsEncrypt.exe' }
$logDir = if ($config.LogDirectory) { $config.LogDirectory } else { Join-Path $PSScriptRoot 'logs' }
$retention = if ($config.LogRetentionDays) { [int]$config.LogRetentionDays } else { 90 }

New-Item -ItemType Directory -Path $logDir -Force | Out-Null
$transcript = Join-Path $logDir ("task-{0:yyyyMMdd-HHmmss}.log" -f (Get-Date))
Start-Transcript -Path $transcript | Out-Null

$worst = 0
try {
    if (-not (Test-Path $exe)) { throw "CiscoIseLetsEncrypt.exe not found: $exe" }
    $jobs = @($config.Jobs | Where-Object { -not $Job -or $_.Name -in $Job })
    if ($jobs.Count -eq 0) { throw "No jobs to run (config: $ConfigFile, filter: $Job)" }

    foreach ($j in $jobs) {
        $arguments = @($config.CommonArguments) + @($j.Arguments) + @('-LogDirectory', $logDir)
        if ($DryRun) { $arguments += '-DryRun' }
        Write-Host "===== Job $($j.Name): CiscoIseLetsEncrypt $($arguments -join ' ')"
        & $exe @arguments 2>&1 | ForEach-Object { Write-Host $_ }
        $code = $LASTEXITCODE
        Write-Host "===== Job $($j.Name) finished with exit code $code"
        if ($code -gt $worst) { $worst = $code }
    }
}
catch {
    Write-Host "ERROR: $($_.Exception.Message)"
    $worst = 2
}
finally {
    Get-ChildItem -Path $logDir -File -Filter 'task-*.log' |
        Where-Object LastWriteTime -lt (Get-Date).AddDays(-$retention) |
        Remove-Item -Force -ErrorAction SilentlyContinue
    Stop-Transcript | Out-Null
}
exit $worst
