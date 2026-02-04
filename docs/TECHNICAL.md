# PolicyLens Technical Documentation

This document provides detailed technical information for developers, contributors, and advanced users.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            Invoke-PolicyLens                                 │
│                          (Main Orchestrator)                                 │
└─────────────────────────────────────┬───────────────────────────────────────┘
                                      │
        ┌─────────────────────────────┼─────────────────────────────┐
        │                             │                             │
        ▼                             ▼                             ▼
┌───────────────────┐       ┌───────────────────┐       ┌───────────────────┐
│  Get-GPOPolicyData│       │  Get-MDMPolicyData│       │ Get-SCCMPolicyData│
│   (gpresult/reg)  │       │   (registry/WMI)  │       │      (WMI)        │
└─────────┬─────────┘       └─────────┬─────────┘       └─────────┬─────────┘
          │                           │                           │
          ▼                           │                           ▼
┌───────────────────┐                 │               ┌───────────────────┐
│Get-GPOVerification│                 │               │Get-SCCMVerification│
│      Status       │                 │               │       Status       │
│  (Active Directory│                 │               │   (SMS Provider)   │
└─────────┬─────────┘                 │               └─────────┬─────────┘
          │                           │                         │
          └─────────────────┬─────────┴─────────────────────────┘
                            │
                            ▼
              ┌───────────────────────────┐
              │   Microsoft Graph API     │
              │  (Connect-MgGraph upfront)│
              └─────────────┬─────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│Get-GraphPolicy│   │Get-DeviceApp  │   │Get-DeviceGroup│
│     Data      │   │  Assignments  │   │  Memberships  │
└───────┬───────┘   └───────┬───────┘   └───────┬───────┘
        │                   │                   │
        │                   │                   ▼
        │                   │           ┌───────────────┐
        │                   │           │Get-DeviceDeploy│
        │                   │           │   mentStatus   │
        │                   │           └───────┬───────┘
        │                   │                   │
        └───────────────────┼───────────────────┘
                            │
                            ▼
              ┌───────────────────────────┐
              │   Compare-PolicyOverlap   │◄── Config/SettingsMap.psd1
              └─────────────┬─────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│ Write-Console │   │ ConvertTo-    │   │    Return     │
│    Summary    │   │  JsonExport   │   │ PSCustomObject│
└───────────────┘   └───────────────┘   └───────────────┘
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
    CollectedAt              = [datetime]
    ComputerName             = "HOSTNAME"
    RSoPWasTemporarilyEnabled = [bool]  # If RSoP logging was enabled during scan
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
3. Gets last sync time from enrollment registry key `LastWriteTime`
4. Reads Intune-specific policies from `Providers\{GUID}\default\Device` and `Providers\{GUID}\default\User`
5. Reads all CSP values from `current\device` and `current\user` paths for comparison
6. Optionally runs `mdmdiagnosticstool` for detailed diagnostics

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
    LastSyncTime         = [DateTime]  # Registry key last write time (indicates last sync)
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

## Verification Features

### GPO Verification (Get-GPOVerificationStatus)

Compares GPOs linked in Active Directory against GPOs actually applied to the device.

**Sources:**
- Active Directory (via ADSI or `Get-ADObject`)
- Device's OU path from computer object
- `gPLink` attribute on OUs and domain

**Process:**
1. Find the device's computer object in AD
2. Walk up the OU hierarchy to collect all linked GPOs
3. Parse `gPLink` attributes using `Parse-GPLink` helper
4. Compare linked GPOs against applied GPOs from `Get-GPOPolicyData`
5. Determine status for each GPO

**Verification States:**
| Status | Meaning |
|--------|---------|
| `applied` | GPO is linked and applied |
| `security-filtered` | GPO is linked but not applied (permissions block it) |
| `disabled` | GPO link exists but is disabled |
| `wmi-filtered` | GPO didn't apply due to WMI filter |
| `not-applied` | GPO is linked but not in applied list (unknown reason) |

**Output structure:**
```powershell
@{
    Available         = [bool]
    ADReachable       = [bool]
    DeviceFound       = [bool]
    DomainJoined      = [bool]
    DeviceDN          = "CN=COMPUTER,OU=..."
    VerificationStates = @(
        @{
            GPOName       = "GPO Display Name"
            GPOGUID       = "{GUID}"
            LinkedOU      = "OU=...,DC=..."
            LinkEnabled   = [bool]
            Enforced      = [bool]
            Status        = "applied|security-filtered|disabled|..."
            StatusLabel   = "Applied|Security Filtered|..."
        }
    )
    AppliedCount      = [int]
    DeniedCount       = [int]
    NotAppliedCount   = [int]
    DisabledCount     = [int]
    CollectedAt       = [datetime]
    Message           = "Error message if failed"
}
```

### Intune Verification (Get-DeviceDeploymentStatus)

Compares Intune profiles assigned to the device against actual deployment status.

**Sources:**
- Graph API: `/deviceManagement/managedDevices/{id}/deviceConfigurationStates`
- Graph API: `/deviceManagement/managedDevices/{id}/deviceCompliancePolicyStates`

**Process:**
1. Find the device in Intune by Azure AD device ID
2. Query configuration profile deployment states
3. Query compliance policy deployment states
4. Map states to verification status

**Verification States:**
| Status | Meaning |
|--------|---------|
| `applied` | Profile successfully deployed |
| `pending` | Profile assigned but not yet applied |
| `error` | Profile failed to apply |
| `conflict` | Profile conflicts with another |
| `not-applicable` | Profile doesn't apply to this device |

**Output structure:**
```powershell
@{
    DeviceFound      = [bool]
    IntuneDeviceId   = "GUID"
    ProfileStates    = @(
        @{
            ProfileName  = "Profile Display Name"
            ProfileId    = "GUID"
            ProfileType  = "DeviceConfiguration|SettingsCatalog|..."
            State        = "applied|pending|error|..."
            StateLabel   = "Applied|Pending|Error|..."
            ErrorCode    = [int]  # If error
        }
    )
    ComplianceStates = @(
        @{
            PolicyName   = "Compliance Policy Name"
            PolicyId     = "GUID"
            State        = "compliant|noncompliant|..."
            StateLabel   = "Compliant|Non-Compliant|..."
        }
    )
    CollectedAt      = [datetime]
}
```

### SCCM Verification (Get-SCCMVerificationStatus)

Compares SCCM deployments assigned to the device (via collection membership) against installed state.

**Sources:**
- SMS Provider WMI on site server (`root\SMS\site_{code}`)
- `SMS_R_System` - Find device resource ID
- `SMS_FullCollectionMembership` - Device's collection memberships
- `SMS_DeploymentInfo` - Deployments targeted at those collections
- Client-side data from `Get-SCCMPolicyData`

**Process:**
1. Auto-discover site server and site code from client registry (or use parameters)
2. Connect to SMS Provider via `Get-SCCMSiteConnection` helper
3. Find device by name in `SMS_R_System`
4. Query collection memberships
5. Query deployments targeted at those collections
6. Compare against client-side installed state

**Verification States:**
| Status | Meaning |
|--------|---------|
| `installed` | Application deployed and installed |
| `compliant` | Baseline evaluated as compliant |
| `pending` | Deployment in progress |
| `failed` | Installation/evaluation failed |
| `not-applicable` | Deployment doesn't apply |
| `not-installed` | Required but not installed |

**Output structure:**
```powershell
@{
    Available              = [bool]
    SiteServerReachable    = [bool]
    DeviceFound            = [bool]
    SiteServer             = "SCCMSERVER.contoso.com"
    SiteCode               = "PS1"
    DeviceResourceId       = [int]
    CollectionMemberships  = @(
        @{ CollectionID = "PS100001"; Name = "All Workstations" }
    )
    VerificationStates     = @(
        @{
            DeploymentName = "Microsoft Office 365"
            DeploymentType = "Application|Baseline|Update|..."
            CollectionName = "All Workstations"
            Intent         = "Required|Available"
            Deadline       = [datetime]
            Status         = "installed|pending|failed|..."
            StatusLabel    = "Installed|Pending|Failed|..."
            ClientState    = "Installed"  # From CCM_Application
        }
    )
    InstalledCount         = [int]
    PendingCount           = [int]
    FailedCount            = [int]
    NotApplicableCount     = [int]
    CollectedAt            = [datetime]
    Message                = "Error message if failed"
}
```

## Graph API Permissions

When using Graph API features (default, use `-SkipIntune` to disable), these scopes are requested:

| Scope | Purpose | Used By |
|-------|---------|---------|
| `DeviceManagementConfiguration.Read.All` | Read Intune device configurations | Get-GraphPolicyData |
| `DeviceManagementManagedDevices.Read.All` | Read managed device info, deployment status | Get-DeviceDeploymentStatus |
| `DeviceManagementApps.Read.All` | Read app assignments | Get-DeviceAppAssignments |
| `Directory.Read.All` | Read Azure AD groups | Get-DeviceGroupMemberships |
| `Device.Read.All` | Look up device in Azure AD | Get-DeviceGroupMemberships |

**Authentication:**
- Uses interactive authentication via `Connect-MgGraph`
- Authentication happens upfront at the start of the scan
- If auth fails, scan continues with local-only data
- Service principal authentication not yet supported
- Session is disconnected after scan completes

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

1. **Authenticate to Graph upfront** (if not `-SkipIntune`)
2. **Establish WinRM session** to target machine
3. **Execute collection scriptblock** remotely via `Invoke-Command`
4. **Return collected data** to local machine
5. **Run Graph API calls locally** (uses remote device info)
6. **Run verification** (GPO via AD, SCCM via site server)
7. **Close sessions and disconnect Graph**

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
| GPO Verification | Local AD query | Local AD query (uses remote device DN) |
| SCCM Verification | Local site server query | Local site server query |
| Authentication | Current user | Specified credential or current user |
| Performance | Faster | Network overhead |

## JSON Export Format

The exported JSON (schema version 1.3) contains:

```json
{
  "schemaVersion": "1.3",
  "exportedAt": "2026-02-04T10:30:00Z",
  "exportedBy": "PolicyLens v1.3.0",
  "device": {
    "computerName": "WORKSTATION1",
    "osVersion": "Microsoft Windows 11 Pro 10.0.22631",
    "osBuild": "22631",
    "domainJoined": true,
    "azureADJoined": true,
    "hybridJoined": true
  },
  "gpoData": { ... },
  "mdmData": { ... },
  "sccmData": { ... },
  "graphData": { ... },
  "appData": { ... },
  "groupData": { ... },
  "analysis": {
    "Summary": { ... },
    "DetailedResults": [ ... ],
    "MDMOnlyPolicies": [ ... ]
  },
  "mappingSuggestions": [ ... ],
  "verificationData": {
    "enabled": true,
    "collectedAt": "2026-02-04T10:30:00Z",
    "deviceFound": true,
    "intuneDeviceId": "guid",
    "profileStates": [ ... ],
    "complianceStates": [ ... ]
  },
  "gpoVerificationData": {
    "enabled": true,
    "adReachable": true,
    "deviceFound": true,
    "domainJoined": true,
    "deviceDN": "CN=WORKSTATION1,OU=...",
    "verificationStates": [ ... ],
    "appliedCount": 10,
    "deniedCount": 2,
    "notAppliedCount": 0,
    "disabledCount": 1,
    "collectedAt": "2026-02-04T10:30:00Z"
  },
  "sccmVerificationData": {
    "enabled": true,
    "siteServerReachable": true,
    "deviceFound": true,
    "siteServer": "SCCMSERVER.contoso.com",
    "siteCode": "PS1",
    "deviceResourceId": 12345,
    "collectionMemberships": [ ... ],
    "verificationStates": [ ... ],
    "installedCount": 5,
    "pendingCount": 2,
    "failedCount": 1,
    "notApplicableCount": 0,
    "collectedAt": "2026-02-04T10:30:00Z"
  }
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
| `Get-DeviceDeploymentStatus` | Verify Intune deployment status |
| `Get-GPOVerificationStatus` | Verify GPO application via AD |
| `Get-SCCMVerificationStatus` | Verify SCCM deployments via SMS Provider |
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
| `Get-SCCMSiteConnection` | Auto-discover and connect to SMS Provider |
| `Parse-GPLink` | Parse Active Directory gPLink attribute |
| `Merge-PolicyData` | Combine data from multiple sources |

## Troubleshooting

### Common Issues

**"RSOP logging is disabled"**
- PolicyLens attempts to enable RSOP logging automatically
- May require `gpupdate /force` to take effect
- Some GPOs may block RSOP; check domain policy
- Warning is logged when RSoP is temporarily enabled and restored

**"Device not found in Azure AD"**
- Device may not be Azure AD joined/registered
- Check device name matches exactly
- Verify Graph API permissions

**"Graph connection failed"**
- Ensure Microsoft.Graph module is installed
- Check network connectivity to Microsoft endpoints
- Verify user has appropriate Intune RBAC roles
- Scan continues with local-only data if auth fails

**"Site server unreachable" (SCCM)**
- Verify site server name and network connectivity
- Check credentials have read access to SMS Provider
- Verify WMI connectivity to `root\SMS\site_{code}` namespace

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
