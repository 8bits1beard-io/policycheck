# PolicyLens

Scan Windows devices for Group Policy, Intune, and SCCM configurations. See what's applied, find conflicts, and plan GPO-to-Intune migrations.

## Quick Start

```powershell
# Basic scan (GPO, MDM, SCCM)
.\PolicyLens.ps1

# Include Intune profiles and app assignments
.\PolicyLens.ps1 -IncludeGraph

# Scan a remote machine
.\PolicyLens.ps1 -ComputerName SERVER1
```

Results export to JSON. Open `Viewer/PolicyLensViewer.html` in a browser and drag in the JSON file to explore.

## Requirements

- Windows 10/11 with PowerShell 5.1+
- Run as Administrator for full results
- Microsoft.Graph module for `-IncludeGraph` features

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```

## Parameters

| Parameter | Description |
|-----------|-------------|
| `-IncludeGraph` | Connect to Graph API for Intune profiles, apps, and group memberships |
| `-SuggestMappings` | Find Intune equivalents for unmapped GPO settings (requires `-IncludeGraph`) |
| `-ComputerName` | Scan a remote machine via WinRM |
| `-Credential` | Credentials for remote authentication |
| `-OutputPath` | Custom path for JSON export |
| `-SkipMDMDiag` | Skip mdmdiagnosticstool (faster scans) |

## What It Collects

| Source | Data |
|--------|------|
| **Group Policy** | Applied GPOs, registry-based policy settings |
| **Intune/MDM** | Enrollment status, PolicyManager CSP settings |
| **SCCM** | Applications, compliance baselines, software updates |
| **Graph API** | Intune profiles, app assignments, Azure AD groups |

## Using as a Module

```powershell
Import-Module .\PolicyLens.psd1

# Collect from individual sources
$gpo = Get-GPOPolicyData
$mdm = Get-MDMPolicyData

# Analyze overlap
$analysis = Compare-PolicyOverlap -GPOData $gpo -MDMData $mdm
$analysis.Summary
```

## Limitations

- **Read-only** - collects and reports data only, never modifies policies
- **GPO mapping** - built-in mappings cover common settings but not everything
- **Graph API** - requires interactive auth (no service principal support yet)

## License

MIT - See [LICENSE](LICENSE)
