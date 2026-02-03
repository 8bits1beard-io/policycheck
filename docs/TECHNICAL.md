# PolicyLens Technical Documentation

This document provides detailed technical information for developers, contributors, and advanced users.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        Invoke-PolicyLens                         │
│                      (Main Orchestrator)                         │
└──────────────────────────┬──────────────────────────────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        ▼                  ▼                  ▼
┌───────────────┐  ┌───────────────┐  ┌───────────────┐
│ Get-GPOPolicy │  │ Get-MDMPolicy │  │ Get-SCCMPolicy│
│     Data      │  │     Data      │  │     Data      │
└───────┬───────┘  └───────┬───────┘  └───────┬───────┘
        │                  │                  │
        └──────────────────┼──────────────────┘
                           ▼
                ┌─────────────────────┐
                │ Compare-PolicyOverlap│◄── Config/SettingsMap.psd1
                └──────────┬──────────┘
                           │
        ┌──────────────────┼──────────────────┐
        ▼                  ▼                  ▼
┌───────────────┐  ┌───────────────┐  ┌───────────────┐
│ Write-Console │  │ ConvertTo-    │  │   Return      │
│    Summary    │  │  JsonExport   │  │ PSCustomObject│
└───────────────┘  └───────────────┘  └───────────────┘
```

## Data Collection

### Group Policy (Get-GPOPolicyData)

**Sources:**
- `gpresult /scope:computer /x` - XML export of applied GPOs
- Registry scanning under `HKLM:\SOFTWARE\Policies` and `HKCU:\SOFTWARE\Policies`
- RSoP WMI (`root\rsop\computer` and `root\rsop\user`) - Source GPO attribution

**Process:**
1. Runs `gpresult` to get list of applied GPOs with metadata
2. Calls `Get-RSoPPolicySource` to build a lookup table mapping registry settings to source GPOs
3. Scans policy registry keys recursively
4. Correlates each registry setting with its source GPO using the RSoP lookup
5. Categorizes settings by registry path patterns
6. Returns structured object with GPO list and registry policies

**Output structure:**
```powershell
@{
    TotalGPOCount    = [int]
    ComputerGPOs     = @(...)  # GPO names/GUIDs applied to computer
    UserGPOs         = @(...)  # GPO names/GUIDs applied to user
    RegistryPolicies = @(
        @{
            Path      = "Microsoft\Windows\..."  # Relative path
            ValueName = "SettingName"
            Data      = "Value"
            DataType  = "String|Int32|..."
            Scope     = "Computer|User"
            Category  = "Detected category"
            FullPath  = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\..."
            SourceGPO = "GPO Display Name"  # From RSoP WMI
            SourceOU  = "OU=...,DC=..."      # Scope of Management ID
        }
    )
    CollectedAt      = [datetime]
    ComputerName     = "HOSTNAME"
}
```

### MDM/Intune (Get-MDMPolicyData)

**Sources:**
- `HKLM:\SOFTWARE\Microsoft\Enrollments` - MDM enrollment status and provider GUIDs
- `HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers\{GUID}\default\Device` - Intune-configured policies
- `HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device` - All CSP values (including defaults)
- `mdmdiagnosticstool` - Additional MDM diagnostics (optional)

**Important distinction:**
- **IntunePolicies**: Settings explicitly configured by Intune, read from the `Providers/{GUID}/default/Device` path. This contains only policies that were actively pushed by the Intune management server.
- **DevicePolicies/UserPolicies**: All current CSP values from `PolicyManager/current/device`, which includes defaults and values from all sources. Useful for comparison and debugging.

**Process:**
1. Reads enrollment information from `HKLM:\SOFTWARE\Microsoft\Enrollments`
2. Identifies the Intune enrollment GUID (where `ProviderID = 'MS DM Server'`)
3. Reads Intune-specific policies from `Providers\{GUID}\default\Device` and `Providers\{GUID}\default\User`
4. Reads all CSP values from `current\device` and `current\user` paths for comparison
5. Optionally runs `mdmdiagnosticstool` for detailed diagnostics

**Output structure:**
```powershell
@{
    IsEnrolled           = [bool]
    Enrollments          = @(
        @{
            EnrollmentId   = "GUID"
            ProviderId     = "MS DM Server"  # Intune
            UPN            = "user@domain.com"
            AADTenantId    = "tenant-guid"
            EnrollmentType = [int]
            DeviceId       = "SID"
            IsIntune       = [bool]
        }
    )
    IntuneEnrollmentGuid = "GUID"  # For provider path lookup
    # Primary: Only Intune-configured policies
    IntunePolicies       = @(
        @{
            Area    = "CSP Area name"
            Setting = "Setting name"
            Value   = "Configured value"
            Scope   = "Device|User"
            Source  = "Intune"
        }
    )
    # Secondary: All CSP values for comparison/debugging
    DevicePolicies       = @(
        @{
            Area            = "CSP Area name"
            Setting         = "Setting name"
            Value           = "Current value"
            Scope           = "Device"
            Source          = "PolicyManager"
            WinningProvider = "Provider GUID"
            IsFromIntune    = [bool]
        }
    )
    UserPolicies         = @(...)  # Same structure as DevicePolicies
    IntunePolicyCount    = [int]   # Count of Intune-specific policies
    TotalCSPValueCount   = [int]   # Count of all CSP values
    DiagnosticsPath      = "C:\...\extracted"  # If mdmdiagnosticstool ran
    CollectedAt          = [datetime]
}
```

### GPO Source Attribution (Get-RSoPPolicySource)

This private function uses Resultant Set of Policy (RSoP) WMI to determine which GPO configured each registry policy setting.

**Sources:**
- `root\rsop\computer` - Computer-scoped RSoP data
- `root\rsop\user\{SID}` - User-scoped RSoP data (SID with underscores instead of hyphens)

**WMI Classes Used:**
- `RSOP_GPO` - Contains GPO metadata (name, GUID, file system path)
- `RSOP_RegistryPolicySetting` - Contains registry settings with GPO attribution

**Process:**
1. Builds a GPO lookup table from `RSOP_GPO` instances
2. Queries `RSOP_RegistryPolicySetting` for all registry policy settings
3. Filters to only winning policies (`precedence = 1`)
4. Creates a lookup hashtable keyed by `"Scope|RegistryKey|ValueName"`
5. Returns the lookup table for use by `Get-GPOPolicyData`

**Lookup Key Format:**
```
"Machine|SOFTWARE\Policies\Microsoft\Windows\...|SettingName"
"User|SOFTWARE\Policies\Microsoft\...|SettingName"
```

**Output structure (hashtable entry):**
```powershell
@{
    SourceGPO    = "GPO Display Name"      # Human-readable GPO name
    GPOID        = "GPO Identifier"        # GPO ID from RSoP
    GPOGuid      = "{GUID}"                # GPO GUID
    SOMID        = "OU=...,DC=..."         # Scope of Management (OU/domain link)
    Precedence   = 1                       # Always 1 (winning policy)
    CreationTime = [datetime]              # When the setting was applied
}
```

**Notes:**
- Requires Administrator privileges to query RSoP data
- RSoP logging must be enabled (default unless disabled by policy)
- If RSoP is disabled, `Get-GPOPolicyData` will temporarily enable it and run `gpupdate /force`

### SCCM/ConfigMgr (Get-SCCMPolicyData)

**Sources:**
- WMI namespace `ROOT\ccm\ClientSDK`
- `CCM_Application` - Deployed applications
- `CCM_DCMBaseline` - Compliance baselines
- `CCM_SoftwareUpdate` - Software updates

**Output structure:**
```powershell
@{
    IsInstalled  = [bool]
    ClientInfo   = @{ Version, SiteCode, ... }
    Applications = @(...)
    Baselines    = @(...)
    Updates      = @(...)
}
```

### Graph API (Get-GraphPolicyData)

**Endpoints queried:**
- `/deviceManagement/deviceConfigurations` - Configuration profiles
- `/deviceManagement/deviceCompliancePolicies` - Compliance policies
- `/deviceManagement/configurationPolicies` - Settings Catalog policies

**Output structure:**
```powershell
@{
    Available          = [bool]
    Profiles           = @(...)  # Device configuration profiles
    CompliancePolicies = @(...)  # Compliance policies
    SettingsCatalog    = @(...)  # Settings Catalog policies
}
```

## Graph API Permissions

When using `-IncludeGraph`, these Microsoft Graph scopes are requested:

| Scope | Purpose | Used By |
|-------|---------|---------|
| `DeviceManagementConfiguration.Read.All` | Read Intune device configurations | Get-GraphPolicyData |
| `DeviceManagementManagedDevices.Read.All` | Read managed device info | Get-DeviceGroupMemberships |
| `DeviceManagementApps.Read.All` | Read app assignments | Get-DeviceAppAssignments |
| `Directory.Read.All` | Read Azure AD groups | Get-DeviceGroupMemberships |
| `Device.Read.All` | Look up device in Azure AD | Get-DeviceGroupMemberships |

**Authentication:**
- Uses interactive authentication via `Connect-MgGraph`
- Service principal authentication not yet supported
- Session is disconnected after data collection completes

## Policy Overlap Analysis

### How Compare-PolicyOverlap Works

1. **Load SettingsMap** - Reads `Config/SettingsMap.psd1` containing GPO-to-CSP mappings
2. **Match GPO settings** - For each GPO registry policy:
   - Find matching pattern in SettingsMap
   - Look for corresponding MDM policy by Area/Setting
   - Determine status: `BothConfigured`, `GPOOnly_MappingExists`, `GPOOnly_NoMapping`
3. **Compare values** - When both GPO and MDM configure same setting, check if values match
4. **Identify MDM-only** - Find MDM policies not matched to any GPO setting

### Status Values

| Status | Meaning |
|--------|---------|
| `BothConfigured` | GPO and MDM both configure this setting |
| `GPOOnly_MappingExists` | GPO configures it, known MDM equivalent exists but not configured |
| `GPOOnly_NoMapping` | GPO configures it, no known MDM equivalent in SettingsMap |
| `MDMOnly` | Only MDM configures this setting |

### SettingsMap Format

```powershell
# Config/SettingsMap.psd1
@{
    CategoryName = @(
        @{
            GPOPathPattern = 'Registry\\Path\\Pattern'  # Regex
            GPODescription = 'Human-readable description'
            MDMArea        = 'CSPAreaName'
            MDMSetting     = 'SettingName'
            CSPURI         = './Device/Vendor/MSFT/Policy/Config/Area/Setting'
            Notes          = 'Value mapping differences, etc.'
        }
    )
}
```

**Adding new mappings:**
1. Identify the GPO registry path pattern
2. Find the corresponding Intune CSP URI (use `-SuggestMappings` to help)
3. Add entry to appropriate category in SettingsMap.psd1

## Remote Scanning

### How It Works

1. **Establish WinRM session** to target machine
2. **Execute collection scriptblock** remotely via `Invoke-Command`
3. **Return collected data** to local machine
4. **Run Graph API calls locally** (avoids credential complexity on remote)
5. **Close session**

### Prerequisites

On the target machine:
```powershell
# Enable WinRM
Enable-PSRemoting -Force

# Firewall must allow TCP 5985 (HTTP) or 5986 (HTTPS)
```

The scanning user needs:
- Admin rights on the remote machine
- Network access to WinRM ports

### Remote vs Local Differences

| Aspect | Local Scan | Remote Scan |
|--------|------------|-------------|
| GPO/MDM/SCCM collection | Direct | Via WinRM |
| Graph API calls | Local | Local (uses remote device info) |
| Authentication | Current user | Specified credential or current user |
| Performance | Faster | Network overhead |

## JSON Export Format

The exported JSON contains:

```json
{
  "ExportInfo": {
    "ExportDate": "2024-01-15T10:30:00Z",
    "PolicyLensVersion": "1.0.0",
    "ComputerName": "WORKSTATION1"
  },
  "DeviceInfo": {
    "ComputerName": "...",
    "Domain": "...",
    "OSVersion": "...",
    "AADJoined": true,
    "HybridJoined": false,
    "MDMEnrolled": true
  },
  "GPOData": { ... },
  "MDMData": { ... },
  "SCCMData": { ... },
  "GraphData": { ... },
  "AppData": { ... },
  "GroupData": { ... },
  "Analysis": {
    "Summary": { ... },
    "DetailedResults": [ ... ],
    "MDMOnlyPolicies": [ ... ]
  },
  "MappingSuggestions": [ ... ]
}
```

## Mapping Suggestions Feature

When `-SuggestMappings` is used:

1. **Query Settings Catalog** via Graph API (`Get-SettingsCatalogMappings`)
2. **Find unmapped GPO settings** (status = `GPOOnly_NoMapping`)
3. **Match using multiple strategies** (`Find-SettingsCatalogMatch`):
   - ADMX ID matching
   - Registry path similarity
   - Setting name keyword matching
   - CSP URI pattern matching
4. **Score and rank matches** by confidence (High/Medium/Low)
5. **Include in JSON export** for review in viewer

## Module Functions Reference

### Public (Exported)

| Function | Purpose |
|----------|---------|
| `Invoke-PolicyLens` | Main entry point, orchestrates full scan |
| `Get-GPOPolicyData` | Collect Group Policy data |
| `Get-MDMPolicyData` | Collect MDM/Intune policy data |
| `Get-SCCMPolicyData` | Collect SCCM/ConfigMgr data |
| `Get-GraphPolicyData` | Fetch Intune profiles via Graph |
| `Get-DeviceAppAssignments` | Get Intune app assignments |
| `Get-DeviceGroupMemberships` | Get Azure AD group memberships |
| `Get-SettingsCatalogMappings` | Query Settings Catalog definitions |
| `Compare-PolicyOverlap` | Analyze GPO vs MDM overlap |

### Private (Internal)

| Function | Purpose |
|----------|---------|
| `ConvertTo-JsonExport` | Format and write JSON output |
| `Write-ConsoleSummary` | Display color-coded console output |
| `Write-PolicyLensLog` | Write to operational log file |
| `Find-SettingsCatalogMatch` | Match GPO to Settings Catalog items |
| `Get-RemoteCollectionScriptBlock` | Generate scriptblock for WinRM |
| `Get-RSoPPolicySource` | Query RSoP WMI for GPO source attribution |
| `Merge-PolicyData` | Combine data from multiple sources |

## Troubleshooting

### Common Issues

**"RSOP logging is disabled"**
- PolicyLens attempts to enable RSOP logging automatically
- May require `gpupdate /force` to take effect
- Some GPOs may block RSOP; check domain policy

**"Device not found in Azure AD"**
- Device may not be Azure AD joined/registered
- Check device name matches exactly
- Verify Graph API permissions

**"Graph connection failed"**
- Ensure Microsoft.Graph module is installed
- Check network connectivity to Microsoft endpoints
- Verify user has appropriate Intune RBAC roles

**Remote scan connection failures**
- Verify WinRM is enabled: `Test-WSMan -ComputerName TARGET`
- Check firewall allows TCP 5985/5986
- Verify credentials have admin rights on target

### Log File

Operational logs are written to:
```
%LOCALAPPDATA%\PolicyLens\PolicyLens.log
```

Override with `-LogPath` parameter.
