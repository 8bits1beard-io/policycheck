# PolicyLens

Scan Windows devices for Group Policy, Intune, and SCCM configurations. See what's applied, find conflicts, and plan GPO-to-Intune migrations.

## Quick Start

```powershell
# Full scan with Graph API and verification (default)
.\PolicyLens.ps1

# Skip Intune/Graph queries (local-only scan)
.\PolicyLens.ps1 -SkipIntune

# Scan a remote machine
.\PolicyLens.ps1 -ComputerName SERVER1

# With SCCM deployment verification
.\PolicyLens.ps1 -SCCMCredential (Get-Credential)
```

Results export to JSON. Open `Viewer/PolicyLensViewer.html` in a browser and drag in the JSON file to explore.

## Requirements

- Windows 10/11 with PowerShell 5.1+
- Run as Administrator for full results
- Microsoft.Graph module for Intune features (included by default)

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```

## Parameters

| Parameter | Description |
|-----------|-------------|
| `-SkipIntune` | Skip Graph API queries for Intune profiles, apps, and groups |
| `-SkipVerify` | Skip Intune deployment verification (assigned vs applied) |
| `-SkipGPOVerify` | Skip GPO application verification via Active Directory |
| `-SkipSCCM` | Skip SCCM client data collection |
| `-SkipSCCMVerify` | Skip SCCM deployment verification (site server queries) |
| `-SCCMSiteServer` | SCCM site server for verification (auto-discovered if omitted) |
| `-SCCMSiteCode` | SCCM site code (auto-discovered if omitted) |
| `-SCCMCredential` | Credentials for SCCM site server connection |
| `-SuggestMappings` | Find Intune equivalents for unmapped GPO settings |
| `-ComputerName` | Scan a remote machine via WinRM |
| `-Credential` | Credentials for remote authentication |
| `-TenantId` | Azure AD tenant ID for Graph authentication |
| `-OutputPath` | Custom path for JSON export |
| `-SkipMDMDiag` | Skip mdmdiagnosticstool (faster scans) |

## What It Collects

| Source | Data |
|--------|------|
| **Group Policy** | Applied GPOs, registry-based policy settings, source GPO attribution |
| **Intune/MDM** | Enrollment status, PolicyManager CSP settings, sync status |
| **SCCM** | Applications, compliance baselines, software updates, client settings |
| **Graph API** | Intune profiles, app assignments, Azure AD groups, deployment status |

## Verification Features

PolicyLens can verify that policies are actually applied, not just assigned:

- **Intune Verification** - Compares assigned profiles against device deployment status
- **GPO Verification** - Queries AD to compare linked GPOs against applied GPOs (detects filtering)
- **SCCM Verification** - Queries site server to compare deployments against installed state

## Using as a Module

```powershell
Import-Module .\PolicyLens.psd1

# Collect from individual sources
$gpo = Get-GPOPolicyData
$mdm = Get-MDMPolicyData
$sccm = Get-SCCMPolicyData

# Analyze overlap
$analysis = Compare-PolicyOverlap -GPOData $gpo -MDMData $mdm
$analysis.Summary

# Verify SCCM deployments
$verification = Get-SCCMVerificationStatus -SCCMData $sccm -SiteCredential $cred
```

## Limitations

- **Read-only** - collects and reports data only, never modifies policies
- **GPO mapping** - built-in mappings cover common settings but not everything
- **Graph API** - requires interactive auth (no service principal support yet)
- **SCCM verification** - requires credentials with read access to SMS Provider

## License

MIT - See [LICENSE](LICENSE)
