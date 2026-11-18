<#
.SYNOPSIS
    Template DNS hook for CiscoIseLetsEncrypt -DnsScript (DNS providers other than the ACME DNS Proxy).
.DESCRIPTION
    Called by the program:
      script.ps1 -Action Create -RecordName _acme-challenge.eap.example.com -Value <txt-value>
      script.ps1 -Action Delete -RecordName _acme-challenge.eap.example.com
    Exit code 0 = success, anything else (or an uncaught error) fails the run. Output is written to the log (-Verbose).
    Copy this file and fill in the two functions for your provider. Secrets should come from environment
    variables or a credential store, not from the command line.
#>
param(
    [Parameter(Mandatory)][ValidateSet('Create', 'Delete')][string]$Action,
    [Parameter(Mandatory)][string]$RecordName,
    [string]$Value
)

$ErrorActionPreference = 'Stop'

function New-TxtRecord([string]$Name, [string]$Text) {
    # Example (Windows DNS Server):
    #   Add-DnsServerResourceRecord -ZoneName 'example.com' -Txt -Name ($Name -replace '\.example\.com$') `
    #       -DescriptiveText $Text -TimeToLive 00:01:00
    # Example (generic REST API):
    #   Invoke-RestMethod -Method Post -Uri 'https://dns.example/api/records' -Headers @{ Authorization = "Bearer $env:DNS_API_TOKEN" } `
    #       -Body (@{ type = 'TXT'; name = $Name; content = $Text } | ConvertTo-Json) -ContentType 'application/json'
    throw "New-TxtRecord is not implemented for your DNS provider."
}

function Remove-TxtRecord([string]$Name) {
    # Example (Windows DNS Server):
    #   Remove-DnsServerResourceRecord -ZoneName 'example.com' -RRType Txt -Name ($Name -replace '\.example\.com$') -Force
    throw "Remove-TxtRecord is not implemented for your DNS provider."
}

switch ($Action) {
    'Create' {
        if (-not $Value) { throw '-Value is required for Create.' }
        New-TxtRecord -Name $RecordName -Text $Value
    }
    'Delete' { Remove-TxtRecord -Name $RecordName }
}
