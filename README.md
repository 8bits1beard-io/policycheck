# PolicyCheck

GPO & Intune policy scanner for Windows devices. Identifies applied Group Policies and MDM/Intune policies, analyzes overlap, and generates an HTML report to assist with GPO-to-Intune migration.

## What It Does

- **Group Policy**: Enumerates all applied GPOs (computer & user) via `gpresult` and scans registry-based policy keys
- **MDM/Intune**: Reads MDM enrollment status and applied policies from `PolicyManager` registry keys
- **Overlap Analysis**: Cross-references GPO settings against their Intune CSP equivalents using a built-in mapping file
- **App Assignments** (Graph): Lists Intune app assignments (Win32, LOB, Store, WinGet, etc.)
- **Group Memberships** (Graph): Shows Azure AD groups the device belongs to (drives policy/app targeting)
- **HTML Report**: Generates a self-contained report with collapsible sections, color-coded overlap analysis, and search/filter

## Requirements

- Windows 10/11
- PowerShell 5.1+ (built-in) or PowerShell 7+
- **Recommended**: Run as Administrator for full `gpresult` and registry access
- **Optional**: [Microsoft.Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation) for Graph API features

```powershell
# Install Graph module (only needed for -IncludeGraph)
Install-Module Microsoft.Graph -Scope CurrentUser
```

## Quick Start

```powershell
# Basic local scan
.\PolicyCheck.ps1

# Full scan with Graph API (opens browser for auth)
.\PolicyCheck.ps1 -IncludeGraph

# Full scan with specific tenant and output path
.\PolicyCheck.ps1 -IncludeGraph -TenantId "contoso.onmicrosoft.com" -OutputPath "C:\Reports\scan.html"

# Skip MDM diagnostics tool (faster)
.\PolicyCheck.ps1 -SkipMDMDiag
```

## Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-IncludeGraph` | Switch | Connect to Graph API for Intune profiles, app assignments, and group memberships |
| `-TenantId` | String | Azure AD tenant ID or domain (e.g., `contoso.onmicrosoft.com`) |
| `-OutputPath` | String | HTML report file path (default: timestamped file in current directory) |
| `-SkipMDMDiag` | Switch | Skip `mdmdiagnosticstool` execution |

## Graph API Permissions

When using `-IncludeGraph`, the tool requests these Microsoft Graph scopes via interactive authentication:

| Scope | Purpose |
|-------|---------|
| `DeviceManagementConfiguration.Read.All` | Read Intune configuration profiles and compliance policies |
| `DeviceManagementManagedDevices.Read.All` | Read managed device information |
| `DeviceManagementApps.Read.All` | Read app assignments |
| `Directory.Read.All` | Read Azure AD group memberships |
| `Device.Read.All` | Look up the device in Azure AD |

## HTML Report Sections

1. **Summary Cards** - At-a-glance counts for GPOs, MDM settings, matches, conflicts, and migration candidates
2. **Applied Group Policies** - All GPOs with scope, link location, and link order
3. **MDM Enrollment** - Enrollment provider, UPN, and tenant details
4. **Overlap Analysis** - Color-coded table with search/filter:
   - **Green**: Setting configured in both GPO and Intune, values match
   - **Red**: Setting in both, values conflict
   - **Cyan**: GPO-only, Intune mapping exists (migration candidate)
   - **Magenta**: GPO-only, no known Intune equivalent
5. **Azure AD Groups** - Device group memberships (dynamic vs assigned)
6. **App Assignments** - Intune apps with assignment intent and targets
7. **Intune Profiles** - Configuration profiles and Settings Catalog policies
8. **MDM Policy Details** - Full list of PolicyManager CSP settings
9. **GPO Registry Details** - All scanned registry policy entries

## Module Usage

You can also import PolicyCheck as a PowerShell module and use individual functions:

```powershell
Import-Module .\PolicyCheck.psd1

# Collect data individually
$gpo = Get-GPOPolicyData
$mdm = Get-MDMPolicyData
$analysis = Compare-PolicyOverlap -GPOData $gpo -MDMData $mdm

# Access analysis results programmatically
$analysis.Summary
$analysis.DetailedResults | Where-Object Status -eq 'GPOOnly_MappingExists'
```

## Extending the Settings Map

The GPO-to-Intune mapping is stored in `Config/SettingsMap.psd1`. Add entries following this pattern:

```powershell
@{
    CategoryName = @(
        @{
            GPOPathPattern = 'Registry\\Path\\Pattern'
            GPODescription = 'What this GPO setting does'
            MDMArea        = 'CSPAreaName'
            MDMSetting     = 'SettingName'
            CSPURI         = './Device/Vendor/MSFT/Policy/Config/Area/Setting'
            Notes          = 'Any migration notes'
        }
    )
}
```

## Limitations

- **Read-only**: This tool only scans and reports. It does not modify any policies.
- **Mapping coverage**: The built-in settings map covers ~50 common policies. Not all GPO settings have Intune equivalents.
- **gpresult on non-domain devices**: `gpresult` requires domain connectivity for full results. On Azure AD-only devices, only registry-based policies are scanned.
- **Graph API**: Requires interactive authentication. Service principal / app-only auth is not currently supported.
- **Settings Catalog**: Retrieved from the beta Graph endpoint, which may change.

## License

MIT
