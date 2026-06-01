#requires -Version 5.1
<#
.SYNOPSIS
    Runs the Windows CIS-aligned audit from a packaged Microsoft Intune deployment.
.DESCRIPTION
    Place this launcher and Invoke-WindowsCisAudit.ps1 in the same Win32 app package. The launcher
    writes a dated HTML report locally. Intune can run the package in the device context, commonly
    LocalSystem, so no interactive prompt or stored credential is required.
#>
[CmdletBinding()]
param(
    [string]$ReportDirectory = 'C:\',
    [ValidateSet('L1', 'L2')]
    [string]$MaximumProfile = 'L2',
    [string]$ConfigurationPath,
    [switch]$IncludeEvidence
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$auditScript = Join-Path -Path $PSScriptRoot -ChildPath 'Invoke-WindowsCisAudit.ps1'
if (-not (Test-Path -LiteralPath $auditScript -PathType Leaf)) {
    throw "The endpoint audit script must be deployed beside this launcher: $auditScript"
}

if (-not (Test-Path -LiteralPath $ReportDirectory -PathType Container)) {
    New-Item -ItemType Directory -Path $ReportDirectory -Force | Out-Null
}

$reportPath = Join-Path -Path $ReportDirectory -ChildPath ("cis-benchmark-report-of-{0:yyyyMMdd-HHmmss}.html" -f (Get-Date))
$auditParameters = @{
    OutputPath = $reportPath
    Format = 'HTML'
    MaximumProfile = $MaximumProfile
}
if ($ConfigurationPath) { $auditParameters.ConfigurationPath = $ConfigurationPath }
if ($IncludeEvidence) { $auditParameters.IncludeEvidence = $true }

& $auditScript @auditParameters
Write-Host "Intune audit report: $reportPath"
