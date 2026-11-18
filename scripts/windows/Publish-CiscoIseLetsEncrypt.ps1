<#
.SYNOPSIS
    Builds CiscoIseLetsEncrypt as a self-contained single-file Windows executable.
.DESCRIPTION
    The output does not need an installed .NET runtime. Copy the output folder (or run the script
    directly on the server) to e.g. C:\Program Files\CiscoIseLetsEncrypt.
.EXAMPLE
    .\Publish-CiscoIseLetsEncrypt.ps1 -Output 'C:\Program Files\CiscoIseLetsEncrypt'
#>
[CmdletBinding()]
param(
    [string] $Output = (Join-Path $PSScriptRoot '..\..\publish\win-x64'),
    [ValidateSet('win-x64', 'win-arm64')]
    [string] $Runtime = 'win-x64'
)

$ErrorActionPreference = 'Stop'
$project = Join-Path $PSScriptRoot '..\..\src\CiscoIseLetsEncrypt\CiscoIseLetsEncrypt.csproj'

dotnet publish $project -c Release -r $Runtime --self-contained true `
    -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o $Output
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed with exit code $LASTEXITCODE" }

Copy-Item (Join-Path $PSScriptRoot '*.ps1'), (Join-Path $PSScriptRoot 'jobs.example.psd1') $Output -Exclude 'Publish-*.ps1' -Force
Write-Host "Published: $(Join-Path $Output 'CiscoIseLetsEncrypt.exe') (+ scripts)"
Write-Host "Next: copy jobs.example.psd1 to jobs.psd1 in $Output and adjust it (see WINDOWS-TASK-SCHEDULER.md)."
