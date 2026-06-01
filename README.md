# Windows CIS-Aligned Security Audit

`Invoke-WindowsCisAudit.ps1` is a read-only Windows PowerShell 5.1 audit script that detects the endpoint's Windows family and available security-management functionality, evaluates a practical set of security controls, and exports a filterable HTML report. It optionally exports machine-readable JSON for centralized processing.

> **Important:** This project is an engineering aid, not an official CIS product or certification tool. It does not redistribute CIS Benchmark documents. Download the licensed benchmark applicable to your Windows release from CIS and validate this script's findings, profile selection, and any organizational exceptions against that document.

## Supported operating-system detection

The script identifies client and server editions by build number and reports the detected SKU, release, build, architecture, server role, and available audit capabilities. Its version mapping recognizes:

| Family | Detected build range |
| --- | --- |
| Windows 10 | `10240` through `21999` |
| Windows 11 | `22000` and later client builds |
| Windows Server 2016 | `14393` through `17762` server builds |
| Windows Server 2019 | `17763` through `20347` server builds |
| Windows Server 2022 | `20348` through `26099` server builds |
| Windows Server 2025 | `26100` and later server builds |

## What it checks

The built-in baseline covers common Level 1 and Level 2 security areas:

- Local password and account-lockout policy through `secedit.exe`.
- User Account Control and application-installation elevation behavior.
- Windows Firewall state for the active Domain, Private, and Public profiles.
- Microsoft Defender antivirus, antispyware, and real-time-protection state when Defender cmdlets exist.
- SMBv1 and SMB server-signing configuration when SMB server cmdlets exist.
- Remote Desktop Network Level Authentication and TLS policy.
- Credential and network protections such as WDigest plaintext caching, LAN Manager hash storage, NTLM session security, anonymous SID enumeration, and LLMNR.
- AutoRun, AutoPlay, SmartScreen on applicable client editions, PowerShell logging, selected services, and BitLocker operating-system-volume state.
- Explicit manual-review items for organization-specific identity governance, advanced audit-policy mapping, endpoint tooling, domain-applied policy, and licensed-benchmark validation.

Checks are intentionally capability-aware. For example, a minimal server installation without Defender or BitLocker cmdlets receives an explanatory `NotApplicable` or `Manual` result instead of a misleading failure.

## Run the audit

Open **Windows PowerShell as Administrator** and run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Invoke-WindowsCisAudit.ps1 -OutputPath C:\Reports\endpoint-audit.html -IncludeEvidence
```

Administrator access is recommended because several local security settings are not readable by standard users. The script only reads configuration and writes the requested report files; it does not remediate settings.

## Deploy through Microsoft Intune

The audit supports two Intune deployment approaches:

1. For a single-file Intune platform-script upload, deploy `Invoke-WindowsCisAudit.ps1` directly. Its default output path already writes the dated local HTML report shown below. To change that path for every deployed endpoint, edit the script's `-OutputPath` default before upload.
2. For an Intune Win32 app package, place `Invoke-WindowsCisAudit-Intune.ps1` beside `Invoke-WindowsCisAudit.ps1` and run the launcher in the device context. The separate launcher is non-interactive and exposes `-ReportDirectory`, allowing the package command to choose a local destination without editing the core audit script.

By default, the report is saved locally as:

```text
C:\cis-benchmark-report-of-yyyyMMdd-HHmmss.html
```

To save reports in another local directory, pass `-ReportDirectory`. The launcher creates the directory if necessary:

```powershell
.\Invoke-WindowsCisAudit-Intune.ps1 -ReportDirectory C:\ProgramData\CisBenchmarkReports -IncludeEvidence
```

For an Intune deployment, decide how reports will be collected after generation. The launcher deliberately writes locally and does not upload endpoint security evidence to an external service. Use an approved collection mechanism, such as your device-management workflow, a protected enterprise file destination, or a separate ingestion process.

## Audit multiple computers from one administration computer

Use `Invoke-WindowsCisAuditRemote.ps1` to run the endpoint audit across Windows endpoints and servers from a single authorized administration computer. The orchestrator uses PowerShell remoting over WinRM, copies the read-only endpoint script to a temporary remote directory, runs it, downloads the generated report, removes its remote temporary directory, and writes `remote-execution-summary.csv` with per-target success or failure details.

### Prerequisites

- Run the orchestrator from a trusted administration computer with Windows PowerShell 5.1.
- Enable and authorize PowerShell remoting on managed endpoints, including the applicable WinRM listener and firewall rules.
- Use an account that is permitted to establish remote sessions and read the audited settings. Prefer a least-privileged, organization-approved service account where practical.
- For workgroup computers, cross-domain connections, or HTTPS listeners, configure WinRM authentication and trust according to your organization's security policy before running the audit.
- Do not place plaintext passwords in scripts, endpoint lists, command histories, or scheduled-task arguments.

Prompt for an administrative or service-account credential and scan named computers:

```powershell
.\Invoke-WindowsCisAuditRemote.ps1 `
    -ComputerName PC-001,PC-002,SERVER-001 `
    -ReportDirectory C:\CisBenchmarkReports `
    -IncludeEvidence
```

The secure `Get-Credential` dialog appears once. The resulting `PSCredential` is used only for WinRM sessions and is not stored in a report or written to disk.

Scan computers listed one per line in a text file while using the current Windows logon token:

```powershell
.\Invoke-WindowsCisAuditRemote.ps1 `
    -ComputerListPath .\computers.txt `
    -CredentialMode CurrentUser `
    -Format Both
```

Blank lines and lines beginning with `#` are ignored in the computer-list file. Available connection controls include `-Authentication Default|Kerberos|Negotiate`, `-UseSSL`, and `-Port`. WinRM is intentionally the supported transport because it is built into supported Windows versions and supports controlled PowerShell remoting. The script does not embed credentials or depend on third-party remote-execution tools.

### Common examples

Generate a Level 1-only HTML report:

```powershell
.\Invoke-WindowsCisAudit.ps1 -MaximumProfile L1 -OutputPath C:\Reports\level1.html
```

Generate HTML and JSON, then open the HTML report:

```powershell
.\Invoke-WindowsCisAudit.ps1 -Format Both -OutputPath C:\Reports\endpoint.html -OpenReport
```

Add organization-specific manual review items:

```powershell
.\Invoke-WindowsCisAudit.ps1 -ConfigurationPath .\example.overlay.json -OutputPath C:\Reports\endpoint.html
```

## Parameters

| Parameter | Purpose |
| --- | --- |
| `-OutputPath` | Report output path. Defaults to `C:\cis-benchmark-report-of-yyyyMMdd-HHmmss.html`. |
| `-Format HTML\|JSON\|Both` | Export HTML, JSON, or both. The default is `HTML`. |
| `-MaximumProfile L1\|L2` | Include controls up to the selected profile. The default is `L2`. |
| `-ConfigurationPath` | Optional JSON overlay that appends organization-specific manual checks. |
| `-IncludeEvidence` | Add expandable evidence details to HTML rows. |
| `-OpenReport` | Open the generated HTML report after the audit completes. |

## Interpreting results

| Status | Meaning |
| --- | --- |
| `Pass` | The observed local setting satisfies the script's built-in expectation. |
| `Fail` | The local setting does not satisfy the built-in expectation or is not configured. |
| `Manual` | The check needs organizational context, a management console, or human review. |
| `NotApplicable` | The relevant role, feature, or management cmdlet is unavailable on the endpoint. |
| `Error` | A setting could not be inspected, commonly because of insufficient permissions. |

A local `Pass` does not prove that the endpoint is compliant with your organization's effective domain policy or the currently licensed CIS Benchmark. Use Group Policy reporting, MDM reporting, vulnerability management, and risk-accepted exceptions alongside this script.

## Overlay schema

The optional overlay deliberately adds **manual** controls only. This keeps the script safe and makes organization-specific evidence requirements explicit:

```json
{
  "manualControls": [
    {
      "id": "ORG-001",
      "title": "Endpoint is enrolled in the approved EDR platform",
      "profile": "L1",
      "expected": "Endpoint is healthy and actively reporting",
      "recommendation": "Enroll the endpoint and verify its health in the management console."
    }
  ]
}
```

## Operational notes

- Run the script locally, through the included Intune-friendly launcher, or through the included WinRM remote orchestrator from an authorized administration computer.
- Store generated reports in an access-controlled location because endpoint configuration evidence can be sensitive.
- Review the script and overlay in source control, validate it on representative Windows client and server test systems, and version changes through your normal change-control process.
- For domain controllers, member servers, and specialized systems, maintain role-specific overlays and compare against the applicable licensed benchmark profile.
