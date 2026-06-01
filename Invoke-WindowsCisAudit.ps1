#requires -Version 5.1
<#
.SYNOPSIS
    Runs a read-only, version-aware Windows security configuration audit and exports an HTML report.
.DESCRIPTION
    Evaluates a practical baseline of CIS-aligned Windows endpoint settings. This project does not
    redistribute CIS benchmark documents and is not an official CIS assessment tool. Use the report
    as an engineering aid and validate requirements against the licensed benchmark applicable to
    your organization.
#>
[CmdletBinding()]
param(
    [string]$OutputPath = ("C:\cis-benchmark-report-of-{0:yyyyMMdd-HHmmss}.html" -f (Get-Date)),
    [ValidateSet('HTML', 'JSON', 'Both')]
    [string]$Format = 'HTML',
    [ValidateSet('L1', 'L2')]
    [string]$MaximumProfile = 'L2',
    [string]$ConfigurationPath,
    [switch]$IncludeEvidence,
    [switch]$OpenReport
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:Results = New-Object System.Collections.Generic.List[object]
$script:ProfileRank = @{ L1 = 1; L2 = 2 }

function ConvertTo-HtmlEncoded {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function ConvertTo-EvidenceText {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '(not set)' }
    if ($Value -is [System.Array]) { return ($Value -join ', ') }
    return [string]$Value
}

function Get-RegistryValueSafe {
    param([string]$Path, [string]$Name)
    try {
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        return [pscustomobject]@{ Exists = $true; Value = $item.$Name; Error = $null }
    } catch [System.Management.Automation.ItemNotFoundException] {
        return [pscustomobject]@{ Exists = $false; Value = $null; Error = $null }
    } catch {
        if ($_.Exception.Message -match 'does not exist|cannot find') {
            return [pscustomobject]@{ Exists = $false; Value = $null; Error = $null }
        }
        return [pscustomobject]@{ Exists = $false; Value = $null; Error = $_.Exception.Message }
    }
}

function Get-WindowsProfile {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $cv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $productName = [string]$cv.ProductName
    $isServer = ([string]$os.ProductType -ne '1') -or ($productName -match 'Server')
    $build = [int]$os.BuildNumber
    $release = if ($cv.PSObject.Properties.Name -contains 'DisplayVersion') { [string]$cv.DisplayVersion } elseif ($cv.PSObject.Properties.Name -contains 'ReleaseId') { [string]$cv.ReleaseId } else { '' }
    $family = if ($isServer) {
        switch ($build) {
            { $_ -ge 26100 } { 'Windows Server 2025'; break }
            { $_ -ge 20348 } { 'Windows Server 2022'; break }
            { $_ -ge 17763 } { 'Windows Server 2019'; break }
            { $_ -ge 14393 } { 'Windows Server 2016'; break }
            default { 'Windows Server (legacy or unrecognized)' }
        }
    } else {
        switch ($build) {
            { $_ -ge 22000 } { 'Windows 11'; break }
            { $_ -ge 10240 } { 'Windows 10'; break }
            default { 'Windows Client (legacy or unrecognized)' }
        }
    }
    [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        ProductName = $productName
        Family = $family
        Edition = [string]$os.Caption
        Release = $release
        Build = $build
        Version = [string]$os.Version
        Architecture = [string]$os.OSArchitecture
        IsServer = $isServer
        IsDomainController = ([string]$os.ProductType -eq '2')
    }
}

function Get-Capabilities {
    param([object]$WindowsProfile)
    [ordered]@{
        Registry = $true
        SecEdit = [bool](Get-Command secedit.exe -ErrorAction SilentlyContinue)
        Firewall = [bool](Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue)
        Defender = [bool](Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)
        BitLocker = [bool](Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)
        SmbServer = [bool](Get-Command Get-SmbServerConfiguration -ErrorAction SilentlyContinue)
        AuditPolicy = [bool](Get-Command auditpol.exe -ErrorAction SilentlyContinue)
        ClientOnly = -not $WindowsProfile.IsServer
        ServerOnly = [bool]$WindowsProfile.IsServer
    }
}

function Add-AuditResult {
    param(
        [string]$Id, [string]$Title, [string]$Category,
        [ValidateSet('L1','L2')][string]$Profile = 'L1',
        [ValidateSet('Pass','Fail','NotApplicable','Manual','Error')][string]$Status,
        [string]$Expected, [AllowNull()][object]$Actual,
        [string]$Recommendation, [string]$Reason = '', [string]$Source = 'Built-in CIS-aligned baseline'
    )
    if ($script:ProfileRank[$Profile] -gt $script:ProfileRank[$MaximumProfile]) { return }
    $script:Results.Add([pscustomobject]@{
        Id = $Id; Title = $Title; Category = $Category; Profile = $Profile; Status = $Status
        Expected = $Expected; Actual = (ConvertTo-EvidenceText $Actual); Recommendation = $Recommendation
        Reason = $Reason; Source = $Source
    })
}

function Test-RegistryControl {
    param([hashtable]$Control)
    $common = $Control.Common
    if ($Control.ContainsKey('AppliesTo') -and -not (& $Control.AppliesTo $script:WindowsProfile)) {
        Add-AuditResult @common -Status NotApplicable -Actual '(not applicable)' -Reason 'This control is outside the detected operating-system role.'
        return
    }
    $found = Get-RegistryValueSafe -Path $Control.Path -Name $Control.Name
    if ($found.Error) {
        Add-AuditResult @common -Status Error -Actual $found.Error -Reason 'Unable to read the registry value.'
        return
    }
    $passed = & $Control.Test $found.Exists $found.Value
    $actual = if ($found.Exists) { $found.Value } else { '(not set)' }
    Add-AuditResult @common -Status $(if ($passed) { 'Pass' } else { 'Fail' }) -Actual $actual -Reason $(if ($found.Exists) { "Registry: $($Control.Path)\\$($Control.Name)" } else { "Registry value is not configured: $($Control.Path)\\$($Control.Name)" })
}

function New-CommonControl {
    param([string]$Id,[string]$Title,[string]$Category,[string]$Profile,[string]$Expected,[string]$Recommendation)
    @{ Id=$Id; Title=$Title; Category=$Category; Profile=$Profile; Expected=$Expected; Recommendation=$Recommendation }
}

function Get-SecurityPolicy {
    if (-not $script:Capabilities.SecEdit) { return $null }
    $tempFile = Join-Path $env:TEMP ("windows-audit-{0}.inf" -f [guid]::NewGuid())
    try {
        & secedit.exe /export /cfg $tempFile /quiet | Out-Null
        $data = @{}
        foreach ($line in (Get-Content -LiteralPath $tempFile -ErrorAction Stop)) {
            if ($line -match '^\s*([^;][^=]+?)\s*=\s*(.*?)\s*$') { $data[$matches[1].Trim()] = $matches[2].Trim() }
        }
        return $data
    } finally {
        Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
    }
}

function Test-SecurityPolicyControls {
    $controls = @(
        @{ Id='WB-ACCT-001'; Title='Password history is retained'; Key='PasswordHistorySize'; Expected='24 or more remembered passwords'; Test={param($v) [int]$v -ge 24}; Recommendation='Configure password history to remember at least 24 passwords.'; Profile='L1' },
        @{ Id='WB-ACCT-002'; Title='Maximum password age is limited'; Key='MaximumPasswordAge'; Expected='365 days or fewer, but greater than 0'; Test={param($v) [int]$v -gt 0 -and [int]$v -le 365}; Recommendation='Set a non-zero maximum password age that matches your approved benchmark and identity policy.'; Profile='L1' },
        @{ Id='WB-ACCT-003'; Title='Minimum password length is configured'; Key='MinimumPasswordLength'; Expected='14 or more characters'; Test={param($v) [int]$v -ge 14}; Recommendation='Set the minimum password length to at least 14 characters.'; Profile='L1' },
        @{ Id='WB-ACCT-004'; Title='Password complexity is enabled'; Key='PasswordComplexity'; Expected='1 (enabled)'; Test={param($v) [int]$v -eq 1}; Recommendation='Enable password complexity requirements.'; Profile='L1' },
        @{ Id='WB-ACCT-005'; Title='Account lockout threshold is configured'; Key='LockoutBadCount'; Expected='Between 1 and 10 invalid attempts'; Test={param($v) [int]$v -ge 1 -and [int]$v -le 10}; Recommendation='Configure an account lockout threshold of 10 or fewer invalid attempts.'; Profile='L1' },
        @{ Id='WB-ACCT-006'; Title='Account lockout duration is configured'; Key='LockoutDuration'; Expected='15 minutes or more'; Test={param($v) [int]$v -ge 15}; Recommendation='Configure an account lockout duration of at least 15 minutes.'; Profile='L1' }
    )
    if (-not $script:Capabilities.SecEdit) {
        foreach ($c in $controls) { Add-AuditResult -Id $c.Id -Title $c.Title -Category 'Account Policies' -Profile $c.Profile -Status NotApplicable -Expected $c.Expected -Actual '(secedit unavailable)' -Recommendation $c.Recommendation -Reason 'The local security policy export utility is unavailable.' }
        return
    }
    try { $policy = Get-SecurityPolicy } catch {
        foreach ($c in $controls) { Add-AuditResult -Id $c.Id -Title $c.Title -Category 'Account Policies' -Profile $c.Profile -Status Error -Expected $c.Expected -Actual $_.Exception.Message -Recommendation $c.Recommendation -Reason 'Unable to export local security policy. Run with sufficient rights.' }
        return
    }
    foreach ($c in $controls) {
        if ($script:ProfileRank[$c.Profile] -gt $script:ProfileRank[$MaximumProfile]) { continue }
        $actual = if ($policy.ContainsKey($c.Key)) { $policy[$c.Key] } else { '(not set)' }
        $pass = $policy.ContainsKey($c.Key) -and (& $c.Test $actual)
        Add-AuditResult -Id $c.Id -Title $c.Title -Category 'Account Policies' -Profile $c.Profile -Status $(if($pass){'Pass'}else{'Fail'}) -Expected $c.Expected -Actual $actual -Recommendation $c.Recommendation -Reason "Local security policy key: $($c.Key)"
    }
}

function Test-FirewallControls {
    if (-not $script:Capabilities.Firewall) {
        Add-AuditResult -Id 'WB-FW-001' -Title 'Windows Firewall profiles are enabled' -Category 'Firewall' -Status NotApplicable -Expected 'Domain, Private, and Public profiles enabled' -Actual '(Get-NetFirewallProfile unavailable)' -Recommendation 'Enable Windows Firewall for all applicable profiles.' -Reason 'Firewall cmdlets are unavailable on this operating-system installation.'
        return
    }
    try {
        $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
        foreach ($profile in $profiles) {
            Add-AuditResult -Id ("WB-FW-{0}" -f $profile.Name.ToUpperInvariant()) -Title ("Windows Firewall {0} profile is enabled" -f $profile.Name) -Category 'Firewall' -Status $(if($profile.Enabled){'Pass'}else{'Fail'}) -Expected 'Enabled' -Actual $profile.Enabled -Recommendation ("Enable the Windows Firewall {0} profile." -f $profile.Name) -Reason 'Active firewall policy store.'
        }
    } catch {
        Add-AuditResult -Id 'WB-FW-001' -Title 'Windows Firewall profiles are enabled' -Category 'Firewall' -Status Error -Expected 'Domain, Private, and Public profiles enabled' -Actual $_.Exception.Message -Recommendation 'Run with permission to inspect firewall policy.' -Reason 'Unable to query the active firewall policy store.'
    }
}

function Test-DefenderControls {
    $items = @(
        @{ Id='WB-AV-001'; Title='Microsoft Defender antivirus is enabled'; Property='AntivirusEnabled'; Recommendation='Enable Microsoft Defender Antivirus or verify the organization-approved antivirus product.' },
        @{ Id='WB-AV-002'; Title='Microsoft Defender real-time protection is enabled'; Property='RealTimeProtectionEnabled'; Recommendation='Enable Microsoft Defender real-time protection.' },
        @{ Id='WB-AV-003'; Title='Microsoft Defender antispyware is enabled'; Property='AntispywareEnabled'; Recommendation='Enable Microsoft Defender antispyware protection.' }
    )
    if (-not $script:Capabilities.Defender) {
        foreach ($item in $items) { Add-AuditResult -Id $item.Id -Title $item.Title -Category 'Microsoft Defender' -Status NotApplicable -Expected 'True' -Actual '(Defender cmdlets unavailable)' -Recommendation $item.Recommendation -Reason 'Microsoft Defender cmdlets may be absent when another security product or a minimal server installation is used.' }
        return
    }
    try { $status = Get-MpComputerStatus } catch {
        foreach ($item in $items) { Add-AuditResult -Id $item.Id -Title $item.Title -Category 'Microsoft Defender' -Status Error -Expected 'True' -Actual $_.Exception.Message -Recommendation $item.Recommendation -Reason 'Unable to query Microsoft Defender status.' }
        return
    }
    foreach ($item in $items) {
        $actual = $status.($item.Property)
        Add-AuditResult -Id $item.Id -Title $item.Title -Category 'Microsoft Defender' -Status $(if($actual){'Pass'}else{'Fail'}) -Expected 'True' -Actual $actual -Recommendation $item.Recommendation -Reason ("Get-MpComputerStatus property: {0}" -f $item.Property)
    }
}

function Test-SmbControls {
    if (-not $script:Capabilities.SmbServer) {
        Add-AuditResult -Id 'WB-SMB-001' -Title 'SMBv1 server protocol is disabled' -Category 'Network Security' -Status NotApplicable -Expected 'False' -Actual '(SMB server cmdlets unavailable)' -Recommendation 'Disable SMBv1 if the SMB server feature is used.' -Reason 'SMB server cmdlets are unavailable.'
        return
    }
    try {
        $smb = Get-SmbServerConfiguration
        Add-AuditResult -Id 'WB-SMB-001' -Title 'SMBv1 server protocol is disabled' -Category 'Network Security' -Status $(if(-not $smb.EnableSMB1Protocol){'Pass'}else{'Fail'}) -Expected 'False' -Actual $smb.EnableSMB1Protocol -Recommendation 'Disable SMBv1 server protocol.' -Reason 'Get-SmbServerConfiguration property: EnableSMB1Protocol.'
        Add-AuditResult -Id 'WB-SMB-002' -Title 'SMB server signing is required' -Category 'Network Security' -Status $(if($smb.RequireSecuritySignature){'Pass'}else{'Fail'}) -Expected 'True' -Actual $smb.RequireSecuritySignature -Recommendation 'Require SMB server security signatures.' -Reason 'Get-SmbServerConfiguration property: RequireSecuritySignature.'
    } catch {
        Add-AuditResult -Id 'WB-SMB-001' -Title 'SMB server configuration can be inspected' -Category 'Network Security' -Status Error -Expected 'SMB configuration readable' -Actual $_.Exception.Message -Recommendation 'Run with permission to inspect SMB server configuration.' -Reason 'Unable to query SMB server configuration.'
    }
}

function Test-ServiceControl {
    param([string]$Id,[string]$Name,[string]$Title,[string]$Profile='L1')
    if ($script:ProfileRank[$Profile] -gt $script:ProfileRank[$MaximumProfile]) { return }
    try {
        $svc = Get-Service -Name $Name -ErrorAction Stop
        $startMode = (Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $Name)).StartMode
        Add-AuditResult -Id $Id -Title $Title -Category 'Services' -Profile $Profile -Status $(if($startMode -eq 'Disabled'){'Pass'}else{'Fail'}) -Expected 'Disabled' -Actual ("StartMode={0}; Status={1}" -f $startMode,$svc.Status) -Recommendation ("Disable the {0} service unless it is explicitly required and risk-accepted." -f $Name) -Reason 'Service is installed.'
    } catch {
        Add-AuditResult -Id $Id -Title $Title -Category 'Services' -Profile $Profile -Status Pass -Expected 'Disabled or not installed' -Actual '(service not installed)' -Recommendation ("Keep the {0} service disabled or uninstalled unless required." -f $Name) -Reason 'Service is not installed.'
    }
}

function Test-BitLockerControl {
    if (-not $script:Capabilities.BitLocker) {
        Add-AuditResult -Id 'WB-BL-001' -Title 'Operating-system volume encryption is reviewed' -Category 'Data Protection' -Profile 'L2' -Status Manual -Expected 'Organization-approved encryption enabled' -Actual '(BitLocker cmdlets unavailable)' -Recommendation 'Verify operating-system volume encryption using the organization-approved technology.' -Reason 'BitLocker cmdlets are unavailable; encryption may require a manual or third-party product review.'
        return
    }
    try {
        $volumes = @(Get-BitLockerVolume | Where-Object VolumeType -eq 'OperatingSystem')
        if ($volumes.Count -eq 0) { throw 'No operating-system BitLocker volume was returned.' }
        foreach ($volume in $volumes) {
            Add-AuditResult -Id 'WB-BL-001' -Title 'Operating-system volume uses BitLocker encryption' -Category 'Data Protection' -Profile 'L2' -Status $(if($volume.ProtectionStatus -eq 'On'){'Pass'}else{'Fail'}) -Expected 'ProtectionStatus=On' -Actual ("MountPoint={0}; ProtectionStatus={1}; VolumeStatus={2}" -f $volume.MountPoint,$volume.ProtectionStatus,$volume.VolumeStatus) -Recommendation 'Enable BitLocker protection for the operating-system volume according to organizational recovery-key policy.' -Reason 'Operating-system volume returned by Get-BitLockerVolume.'
        }
    } catch {
        Add-AuditResult -Id 'WB-BL-001' -Title 'Operating-system volume encryption is reviewed' -Category 'Data Protection' -Profile 'L2' -Status Manual -Expected 'Organization-approved encryption enabled' -Actual $_.Exception.Message -Recommendation 'Verify operating-system volume encryption manually.' -Reason 'BitLocker status could not be determined automatically.'
    }
}

function Add-ManualControls {
    Add-AuditResult -Id 'WB-MAN-001' -Title 'Enterprise identity, privileged access, and group membership review' -Category 'Manual Review' -Status Manual -Expected 'Reviewed against approved access model' -Actual 'Requires domain and organizational context' -Recommendation 'Review local and domain privileged groups, service accounts, and emergency access accounts.' -Reason 'Effective identity governance cannot be established from local configuration alone.'
    Add-AuditResult -Id 'WB-MAN-002' -Title 'Approved benchmark mapping review' -Category 'Manual Review' -Status Manual -Expected 'Validated against the licensed benchmark for this OS family and organizational profile' -Actual $script:WindowsProfile.Family -Recommendation 'Compare this engineering report with the currently licensed CIS Benchmark release and your organization-specific exceptions.' -Reason 'This script intentionally does not redistribute CIS benchmark content.'
    Add-AuditResult -Id 'WB-MAN-003' -Title 'Audit policy coverage review' -Category 'Manual Review' -Profile 'L2' -Status Manual -Expected 'Advanced audit policy matches organizational requirements' -Actual $(if($script:Capabilities.AuditPolicy){'auditpol.exe is available'}else{'auditpol.exe is unavailable'}) -Recommendation 'Export advanced audit policy with auditpol.exe and compare it with your approved baseline, including domain-applied policy.' -Reason 'Audit subcategory names and requirements vary by OS language, role, and approved benchmark profile.'
}

function Apply-ConfigurationOverlay {
    if (-not $ConfigurationPath) { return }
    if (-not (Test-Path -LiteralPath $ConfigurationPath)) { throw "Configuration overlay not found: $ConfigurationPath" }
    $overlay = Get-Content -LiteralPath $ConfigurationPath -Raw | ConvertFrom-Json
    if ($overlay.PSObject.Properties.Name -notcontains 'manualControls') { return }
    foreach ($control in $overlay.manualControls) {
        Add-AuditResult -Id ([string]$control.id) -Title ([string]$control.title) -Category 'Organization Overlay' -Profile $(if($control.profile){[string]$control.profile}else{'L1'}) -Status Manual -Expected ([string]$control.expected) -Actual 'Requires organization-specific review' -Recommendation ([string]$control.recommendation) -Reason 'Added by the organization configuration overlay.' -Source "Overlay: $ConfigurationPath"
    }
}

function Export-AuditHtml {
    param([string]$Path,[object[]]$Results,[object]$Metadata)
    $counts = @{}; foreach($status in 'Pass','Fail','Manual','NotApplicable','Error') { $counts[$status] = @($Results | Where-Object Status -eq $status).Count }
    $rows = foreach ($r in $Results) {
        $evidence = if($IncludeEvidence){"<details><summary>Evidence</summary><pre>$(ConvertTo-HtmlEncoded $r.Reason)</pre></details>"}else{''}
        "<tr data-status='$(ConvertTo-HtmlEncoded $r.Status)' data-category='$(ConvertTo-HtmlEncoded $r.Category)'><td><span class='badge $($r.Status)'>$($r.Status)</span></td><td><strong>$(ConvertTo-HtmlEncoded $r.Id)</strong><br><small>$(ConvertTo-HtmlEncoded $r.Profile)</small></td><td><strong>$(ConvertTo-HtmlEncoded $r.Title)</strong><br><small>$(ConvertTo-HtmlEncoded $r.Category)</small></td><td>$(ConvertTo-HtmlEncoded $r.Expected)</td><td>$(ConvertTo-HtmlEncoded $r.Actual)$evidence</td><td>$(ConvertTo-HtmlEncoded $r.Recommendation)</td></tr>"
    }
    $capabilityRows = foreach($key in $Metadata.Capabilities.Keys){"<tr><td>$(ConvertTo-HtmlEncoded $key)</td><td>$(ConvertTo-HtmlEncoded $Metadata.Capabilities[$key])</td></tr>"}
    $html = @"
<!doctype html><html><head><meta charset="utf-8"><title>Windows Security Audit - $(ConvertTo-HtmlEncoded $Metadata.Windows.ComputerName)</title>
<style>
:root{font-family:Segoe UI,Arial,sans-serif;color:#172033;background:#f4f7fb}body{margin:0}.wrap{max-width:1500px;margin:auto;padding:24px}header{background:#102a43;color:white;padding:26px;border-radius:12px}h1{margin:0 0 8px}.notice{background:#fff5d6;border-left:5px solid #c88700;padding:14px;margin:18px 0}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin:18px 0}.card{background:white;border-radius:10px;padding:14px;box-shadow:0 2px 8px #d9e2ec}.num{font-size:28px;font-weight:700}.toolbar{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0}select,input{padding:9px;border:1px solid #bcccdc;border-radius:6px}table{width:100%;border-collapse:collapse;background:white;font-size:13px}th,td{text-align:left;padding:10px;border-bottom:1px solid #e3e8ee;vertical-align:top}th{background:#eaf0f6;position:sticky;top:0}.badge{display:inline-block;padding:3px 7px;border-radius:12px;font-weight:700}.Pass{background:#d8f3dc;color:#12602b}.Fail,.Error{background:#ffe0e0;color:#a11}.Manual{background:#fff0c2;color:#7a5100}.NotApplicable{background:#e6e8eb;color:#4b5563}small{color:#61758a}pre{white-space:pre-wrap}footer{margin:22px 0;color:#52667a}.grid{display:grid;grid-template-columns:2fr 1fr;gap:18px}@media(max-width:900px){.grid{display:block}}
</style></head><body><div class="wrap"><header><h1>Windows Security Configuration Audit</h1><div>$(ConvertTo-HtmlEncoded $Metadata.Windows.ComputerName) · $(ConvertTo-HtmlEncoded $Metadata.Windows.Family) · build $(ConvertTo-HtmlEncoded $Metadata.Windows.Build) · generated $(ConvertTo-HtmlEncoded $Metadata.GeneratedAt)</div></header>
<div class="notice"><strong>Scope notice:</strong> This is a read-only, CIS-aligned engineering assessment. It is not an official CIS certification tool and does not replace the licensed CIS Benchmark, domain policy analysis, or a risk review.</div>
<div class="cards"><div class="card"><div class="num">$($Results.Count)</div>Total checks</div><div class="card"><div class="num">$($counts.Pass)</div>Passed</div><div class="card"><div class="num">$($counts.Fail)</div>Failed</div><div class="card"><div class="num">$($counts.Manual)</div>Manual</div><div class="card"><div class="num">$($counts.NotApplicable)</div>N/A</div><div class="card"><div class="num">$($counts.Error)</div>Errors</div></div>
<div class="grid"><section><h2>Results</h2><div class="toolbar"><input id="search" placeholder="Search controls" oninput="filterRows()"><select id="status" onchange="filterRows()"><option value="">All statuses</option><option>Pass</option><option>Fail</option><option>Manual</option><option>NotApplicable</option><option>Error</option></select></div><table id="results"><thead><tr><th>Status</th><th>Control</th><th>Check</th><th>Expected</th><th>Actual</th><th>Recommendation</th></tr></thead><tbody>$($rows -join "`n")</tbody></table></section>
<aside><h2>Endpoint</h2><table><tr><td>Product</td><td>$(ConvertTo-HtmlEncoded $Metadata.Windows.ProductName)</td></tr><tr><td>Edition</td><td>$(ConvertTo-HtmlEncoded $Metadata.Windows.Edition)</td></tr><tr><td>Release</td><td>$(ConvertTo-HtmlEncoded $Metadata.Windows.Release)</td></tr><tr><td>Version</td><td>$(ConvertTo-HtmlEncoded $Metadata.Windows.Version)</td></tr><tr><td>Architecture</td><td>$(ConvertTo-HtmlEncoded $Metadata.Windows.Architecture)</td></tr><tr><td>Server</td><td>$(ConvertTo-HtmlEncoded $Metadata.Windows.IsServer)</td></tr><tr><td>Domain controller</td><td>$(ConvertTo-HtmlEncoded $Metadata.Windows.IsDomainController)</td></tr></table><h2>Detected capabilities</h2><table>$($capabilityRows -join "`n")</table></aside></div>
<footer>Generated by Invoke-WindowsCisAudit.ps1. Review failed, manual, and error results with the endpoint owner and the applicable licensed benchmark.</footer></div><script>function filterRows(){const q=document.getElementById('search').value.toLowerCase(),s=document.getElementById('status').value;document.querySelectorAll('#results tbody tr').forEach(r=>{r.style.display=((!s||r.dataset.status===s)&&(!q||r.innerText.toLowerCase().includes(q)))?'':'none'})}</script></body></html>
"@
    $parent = Split-Path -Parent $Path
    if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    [System.IO.File]::WriteAllText($Path,$html,[System.Text.UTF8Encoding]::new($false))
}

# Registry-based checks use compact, reviewable definitions. Missing values fail unless a check explicitly permits absence.
$script:WindowsProfile = Get-WindowsProfile
$script:Capabilities = Get-Capabilities -WindowsProfile $script:WindowsProfile
$registryControls = @(
    @{ Common=(New-CommonControl 'WB-UAC-001' 'Admin Approval Mode is enabled for the built-in Administrator' 'User Account Control' 'L1' '1' 'Enable UAC Admin Approval Mode for the built-in Administrator account.'); Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='FilterAdministratorToken'; Test={param($e,$v) $e -and [int]$v -eq 1} },
    @{ Common=(New-CommonControl 'WB-UAC-002' 'UAC prompts for elevation on the secure desktop' 'User Account Control' 'L1' '1' 'Enable secure-desktop elevation prompts.'); Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='PromptOnSecureDesktop'; Test={param($e,$v) $e -and [int]$v -eq 1} },
    @{ Common=(New-CommonControl 'WB-UAC-003' 'UAC detects application installations' 'User Account Control' 'L1' '1' 'Enable application-installation detection for UAC.'); Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='EnableInstallerDetection'; Test={param($e,$v) $e -and [int]$v -eq 1} },
    @{ Common=(New-CommonControl 'WB-NET-001' 'Anonymous SID enumeration is restricted' 'Network Security' 'L1' '1' 'Restrict anonymous SID and account enumeration.'); Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name='RestrictAnonymousSAM'; Test={param($e,$v) $e -and [int]$v -eq 1} },
    @{ Common=(New-CommonControl 'WB-NET-002' 'LAN Manager hash storage is disabled' 'Network Security' 'L1' '1' 'Prevent storage of LAN Manager password hashes.'); Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name='NoLMHash'; Test={param($e,$v) $e -and [int]$v -eq 1} },
    @{ Common=(New-CommonControl 'WB-NET-003' 'NTLM minimum session security requires NTLMv2 and 128-bit encryption' 'Network Security' 'L1' 'At least 537395200 (0x20080000)' 'Require NTLMv2 session security and 128-bit encryption for NTLM SSP clients.'); Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Name='NTLMMinClientSec'; Test={param($e,$v) $e -and (([int64]$v -band 0x20080000) -eq 0x20080000)} },
    @{ Common=(New-CommonControl 'WB-RDP-001' 'Remote Desktop requires Network Level Authentication' 'Remote Desktop' 'L1' '1' 'Require Network Level Authentication for Remote Desktop connections.'); Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='UserAuthentication'; Test={param($e,$v) $e -and [int]$v -eq 1} },
    @{ Common=(New-CommonControl 'WB-RDP-002' 'Remote Desktop security layer requires TLS' 'Remote Desktop' 'L2' '2' 'Require TLS for Remote Desktop connections.'); Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='SecurityLayer'; Test={param($e,$v) $e -and [int]$v -eq 2} },
    @{ Common=(New-CommonControl 'WB-PS-001' 'PowerShell script block logging is enabled' 'Logging' 'L2' '1' 'Enable PowerShell script block logging and forward logs to the approved collection platform.'); Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Name='EnableScriptBlockLogging'; Test={param($e,$v) $e -and [int]$v -eq 1} },
    @{ Common=(New-CommonControl 'WB-PS-002' 'PowerShell transcription is enabled' 'Logging' 'L2' '1' 'Enable PowerShell transcription with a protected output destination.'); Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'; Name='EnableTranscripting'; Test={param($e,$v) $e -and [int]$v -eq 1} },
    @{ Common=(New-CommonControl 'WB-AUTO-001' 'AutoRun is disabled' 'System Hardening' 'L1' '1' 'Disable AutoRun commands.'); Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name='NoAutorun'; Test={param($e,$v) $e -and [int]$v -eq 1} },
    @{ Common=(New-CommonControl 'WB-AUTO-002' 'AutoPlay is disabled for all drives' 'System Hardening' 'L1' '255' 'Disable AutoPlay for all drives.'); Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name='NoDriveTypeAutoRun'; Test={param($e,$v) $e -and [int]$v -eq 255} },
    @{ Common=(New-CommonControl 'WB-LLMNR-001' 'Multicast name resolution is disabled' 'Network Security' 'L1' '0' 'Turn off multicast name resolution (LLMNR).'); Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; Name='EnableMulticast'; Test={param($e,$v) $e -and [int]$v -eq 0} },
    @{ Common=(New-CommonControl 'WB-SMART-001' 'Microsoft Defender SmartScreen is enabled' 'System Hardening' 'L1' '1' 'Enable Microsoft Defender SmartScreen for Explorer.'); Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name='EnableSmartScreen'; Test={param($e,$v) $e -and [int]$v -eq 1}; AppliesTo={param($p) -not $p.IsServer} },
    @{ Common=(New-CommonControl 'WB-WDIGEST-001' 'WDigest plaintext credential caching is disabled' 'Credential Protection' 'L1' '0 or not set' 'Disable WDigest plaintext credential caching.'); Path='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'; Name='UseLogonCredential'; Test={param($e,$v) (-not $e) -or [int]$v -eq 0} },
    @{ Common=(New-CommonControl 'WB-PRINT-001' 'Print Spooler client connections are not accepted' 'Services' 'L2' '2' 'Disable Print Spooler client connections on systems that do not require printing.'); Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers'; Name='RegisterSpoolerRemoteRpcEndPoint'; Test={param($e,$v) $e -and [int]$v -eq 2} }
)

foreach($control in $registryControls) { Test-RegistryControl $control }
Test-SecurityPolicyControls
Test-FirewallControls
Test-DefenderControls
Test-SmbControls
Test-ServiceControl -Id 'WB-SVC-001' -Name 'RemoteRegistry' -Title 'Remote Registry service is disabled'
Test-ServiceControl -Id 'WB-SVC-002' -Name 'TlntSvr' -Title 'Telnet service is disabled'
Test-ServiceControl -Id 'WB-SVC-003' -Name 'SNMP' -Title 'SNMP service is disabled' -Profile 'L2'
Test-BitLockerControl
Add-ManualControls
Apply-ConfigurationOverlay

$metadata = [pscustomobject]@{ GeneratedAt=(Get-Date).ToString('o'); ScriptVersion='1.1.0'; MaximumProfile=$MaximumProfile; Windows=$script:WindowsProfile; Capabilities=$script:Capabilities }
$resolvedOutput = [System.IO.Path]::GetFullPath($OutputPath)
if ($Format -in @('HTML','Both')) { Export-AuditHtml -Path $resolvedOutput -Results $script:Results.ToArray() -Metadata $metadata }
if ($Format -in @('JSON','Both')) {
    $jsonPath = if($Format -eq 'JSON' -and [IO.Path]::GetExtension($resolvedOutput) -eq '.json'){$resolvedOutput}else{[IO.Path]::ChangeExtension($resolvedOutput,'.json')}
    $jsonParent = Split-Path -Parent $jsonPath
    if ($jsonParent -and -not (Test-Path -LiteralPath $jsonParent)) { New-Item -ItemType Directory -Path $jsonParent -Force | Out-Null }
    @{ Metadata=$metadata; Results=$script:Results.ToArray() } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
}
if ($OpenReport -and $Format -in @('HTML','Both')) { Start-Process $resolvedOutput }
$summary = $script:Results | Group-Object Status | ForEach-Object { "{0}={1}" -f $_.Name,$_.Count }
Write-Host ("Audit complete: {0}" -f ($summary -join '; '))
if ($Format -in @('HTML','Both')) { Write-Host "HTML report: $resolvedOutput" }
if ($Format -in @('JSON','Both')) { Write-Host "JSON report: $jsonPath" }
