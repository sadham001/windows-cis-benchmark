#requires -Version 5.1
<#
.SYNOPSIS
    Runs the Windows CIS-aligned audit against multiple Windows computers through PowerShell remoting.
.DESCRIPTION
    Connects to each requested computer over WinRM, copies the read-only endpoint audit into a
    temporary remote directory, runs it remotely, and downloads each report. Credentials are
    accepted as PSCredential objects or requested interactively with Get-Credential. Passwords are
    never written to disk, embedded in scripts, or included in reports.
#>
[CmdletBinding(DefaultParameterSetName = 'Names')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Names')]
    [string[]]$ComputerName,
    [Parameter(Mandatory = $true, ParameterSetName = 'List')]
    [string]$ComputerListPath,
    [string]$ReportDirectory = (Join-Path -Path (Get-Location) -ChildPath ("cis-benchmark-remote-reports-{0:yyyyMMdd-HHmmss}" -f (Get-Date))),
    [ValidateSet('Prompt', 'CurrentUser')]
    [string]$CredentialMode = 'Prompt',
    [System.Management.Automation.PSCredential]$Credential,
    [ValidateSet('Default', 'Kerberos', 'Negotiate')]
    [string]$Authentication = 'Default',
    [switch]$UseSSL,
    [int]$Port,
    [ValidateSet('HTML', 'JSON', 'Both')]
    [string]$Format = 'HTML',
    [ValidateSet('L1', 'L2')]
    [string]$MaximumProfile = 'L2',
    [string]$ConfigurationPath,
    [switch]$IncludeEvidence
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$auditScript = Join-Path -Path $PSScriptRoot -ChildPath 'Invoke-WindowsCisAudit.ps1'
if (-not (Test-Path -LiteralPath $auditScript -PathType Leaf)) { throw "Audit script not found: $auditScript" }
if ($ConfigurationPath -and -not (Test-Path -LiteralPath $ConfigurationPath -PathType Leaf)) { throw "Configuration overlay not found: $ConfigurationPath" }

if ($PSCmdlet.ParameterSetName -eq 'List') {
    if (-not (Test-Path -LiteralPath $ComputerListPath -PathType Leaf)) { throw "Computer list not found: $ComputerListPath" }
    $ComputerName = @(Get-Content -LiteralPath $ComputerListPath | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') })
}
$targets = @($ComputerName | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Sort-Object -Unique)
if ($targets.Count -eq 0) { throw 'No target computer names were supplied.' }

if ($CredentialMode -eq 'Prompt' -and -not $Credential) {
    $Credential = Get-Credential -Message 'Enter the administrative or service-account credential used only for remote WinRM sessions.'
}
if ($CredentialMode -eq 'Prompt' -and -not $Credential) { throw 'A credential is required when -CredentialMode Prompt is selected.' }
if ($CredentialMode -eq 'CurrentUser' -and $Credential) {
    throw 'Do not provide -Credential when -CredentialMode CurrentUser is selected.'
}

if (-not (Test-Path -LiteralPath $ReportDirectory -PathType Container)) {
    New-Item -ItemType Directory -Path $ReportDirectory -Force | Out-Null
}
$resolvedReportDirectory = [System.IO.Path]::GetFullPath($ReportDirectory)
$executionResults = New-Object System.Collections.Generic.List[object]

foreach ($target in $targets) {
    $session = $null
    $remoteDirectory = "C:\Windows\Temp\WindowsCisAudit-{0}" -f ([guid]::NewGuid().ToString('N'))
    try {
        Write-Host "Connecting to $target ..."
        $sessionParameters = @{ ComputerName = $target; Authentication = $Authentication; ErrorAction = 'Stop' }
        if ($CredentialMode -eq 'Prompt') { $sessionParameters.Credential = $Credential }
        if ($UseSSL) { $sessionParameters.UseSSL = $true }
        if ($Port) { $sessionParameters.Port = $Port }
        $session = New-PSSession @sessionParameters

        Invoke-Command -Session $session -ScriptBlock { param($Path) New-Item -ItemType Directory -Path $Path -Force | Out-Null } -ArgumentList $remoteDirectory
        Copy-Item -LiteralPath $auditScript -Destination (Join-Path $remoteDirectory 'Invoke-WindowsCisAudit.ps1') -ToSession $session -Force
        $remoteOverlay = $null
        if ($ConfigurationPath) {
            $remoteOverlay = Join-Path $remoteDirectory 'configuration.overlay.json'
            Copy-Item -LiteralPath $ConfigurationPath -Destination $remoteOverlay -ToSession $session -Force
        }

        $safeTarget = $target -replace '[^A-Za-z0-9_.-]', '_'
        $remoteHtmlPath = Join-Path $remoteDirectory ("cis-benchmark-report-of-{0}-{1:yyyyMMdd-HHmmss}.html" -f $safeTarget, (Get-Date))
        Invoke-Command -Session $session -ScriptBlock {
            param($ScriptPath, $OutputPath, $RequestedFormat, $Profile, $OverlayPath, $WithEvidence)
            $parameters = @{ OutputPath = $OutputPath; Format = $RequestedFormat; MaximumProfile = $Profile }
            if ($OverlayPath) { $parameters.ConfigurationPath = $OverlayPath }
            if ($WithEvidence) { $parameters.IncludeEvidence = $true }
            & $ScriptPath @parameters
        } -ArgumentList (Join-Path $remoteDirectory 'Invoke-WindowsCisAudit.ps1'), $remoteHtmlPath, $Format, $MaximumProfile, $remoteOverlay, ([bool]$IncludeEvidence)

        $downloaded = New-Object System.Collections.Generic.List[string]
        if ($Format -in @('HTML', 'Both')) {
            $localHtml = Join-Path $resolvedReportDirectory ([System.IO.Path]::GetFileName($remoteHtmlPath))
            Copy-Item -LiteralPath $remoteHtmlPath -Destination $localHtml -FromSession $session -Force
            $downloaded.Add($localHtml) | Out-Null
        }
        if ($Format -in @('JSON', 'Both')) {
            $remoteJson = [System.IO.Path]::ChangeExtension($remoteHtmlPath, '.json')
            $localJson = Join-Path $resolvedReportDirectory ([System.IO.Path]::GetFileName($remoteJson))
            Copy-Item -LiteralPath $remoteJson -Destination $localJson -FromSession $session -Force
            $downloaded.Add($localJson) | Out-Null
        }
        $executionResults.Add([pscustomobject]@{ ComputerName = $target; Status = 'Success'; Reports = ($downloaded -join '; '); Error = '' }) | Out-Null
        Write-Host "Completed $target"
    } catch {
        $executionResults.Add([pscustomobject]@{ ComputerName = $target; Status = 'Failed'; Reports = ''; Error = $_.Exception.Message }) | Out-Null
        Write-Warning "Audit failed for ${target}: $($_.Exception.Message)"
    } finally {
        if ($session) {
            Invoke-Command -Session $session -ScriptBlock { param($Path) Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue } -ArgumentList $remoteDirectory -ErrorAction SilentlyContinue
            Remove-PSSession -Session $session -ErrorAction SilentlyContinue
        }
    }
}

$summaryPath = Join-Path $resolvedReportDirectory 'remote-execution-summary.csv'
$executionResults | Export-Csv -LiteralPath $summaryPath -NoTypeInformation -Encoding UTF8
$successCount = @($executionResults | Where-Object Status -eq 'Success').Count
$failureCount = @($executionResults | Where-Object Status -eq 'Failed').Count
Write-Host "Remote audit complete: Success=$successCount; Failed=$failureCount"
Write-Host "Execution summary: $summaryPath"
if ($failureCount -gt 0) { exit 1 }
