# Microsoft Graph API - Settings Catalog Research

## Executive Summary

This document provides comprehensive research on querying the Intune Settings Catalog via Microsoft Graph API to retrieve all available settings, especially ADMX-backed settings that correspond to Group Policy. This enables building a PowerShell function to match GPO registry settings to their Intune equivalents.

**Key Findings:**
- Settings Catalog uses the `beta` Graph API endpoint `/deviceManagement/configurationPolicies`
- Requires `DeviceManagementConfiguration.ReadWrite.All` permission
- Setting definitions include CSP URI paths (`baseUri` + `offsetUri`)
- ADMX-backed settings follow a predictable naming pattern
- Pagination is supported via `@odata.nextLink`
- Categories provide hierarchical organization of settings

---

## 1. Graph API Endpoints

### Primary Endpoints

#### Configuration Policies (Settings Catalog Policies)
```http
GET https://graph.microsoft.com/beta/deviceManagement/configurationPolicies
```

**Filter by platform and technology:**
```http
GET https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?$filter=platforms has 'windows10' and technologies has 'mdm'
```

**Get specific policy with settings:**
```http
GET https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('{policyId}')?$expand=settings
```

**Get policy settings with definitions expanded:**
```http
GET https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('{policyId}')/settings?$expand=settingDefinitions
```

#### Setting Definitions (Available Settings Metadata)
```http
GET https://graph.microsoft.com/beta/deviceManagement/configurationSettings
GET https://graph.microsoft.com/beta/deviceManagement/reusableSettings
GET https://graph.microsoft.com/beta/deviceManagement/inventorySettings
GET https://graph.microsoft.com/beta/deviceManagement/complianceSettings
```

**Get setting definitions for a specific setting:**
```http
GET https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/{policyId}/settings/{settingId}/settingDefinitions
```

#### Categories (Organizational Hierarchy)
```http
GET https://graph.microsoft.com/beta/deviceManagement/configurationCategories
GET https://graph.microsoft.com/beta/deviceManagement/complianceCategories
GET https://graph.microsoft.com/beta/deviceManagement/inventoryCategories
```

**Filter categories by usage:**
```http
GET https://graph.microsoft.com/beta/deviceManagement/configurationCategories?$filter=settingUsage eq 'configuration'
```

---

## 2. Required Permissions

### Microsoft Graph API Permissions

**Permission Name:** `DeviceManagementConfiguration.ReadWrite.All`

| Permission Type | Scope | Description |
|-----------------|-------|-------------|
| **Delegated** (work/school account) | `DeviceManagementConfiguration.Read.All` | Read Intune device configuration and policies |
| **Delegated** (work/school account) | `DeviceManagementConfiguration.ReadWrite.All` | Read and write Intune device configuration and policies |
| **Application** | `DeviceManagementConfiguration.Read.All` | Read Intune device configuration and policies (no signed-in user) |
| **Application** | `DeviceManagementConfiguration.ReadWrite.All` | Read and write Intune device configuration and policies (no signed-in user) |

**Notes:**
- Personal Microsoft accounts are **NOT supported**
- Requires an **active Intune license** for the tenant
- For read-only operations, `.Read.All` is sufficient
- For creating/modifying policies, `.ReadWrite.All` is required

### PowerShell Authentication Example

```powershell
# Using Microsoft.Graph.Authentication
Connect-MgGraph -Scopes "DeviceManagementConfiguration.ReadWrite.All"

# Or using app-only authentication
$ClientId = "your-app-id"
$TenantId = "your-tenant-id"
$ClientSecret = "your-client-secret"

$Body = @{
    grant_type    = "client_credentials"
    client_id     = $ClientId
    client_secret = $ClientSecret
    scope         = "https://graph.microsoft.com/.default"
}

$TokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Method POST -Body $Body
$AccessToken = $TokenResponse.access_token

$Headers = @{
    Authorization = "Bearer $AccessToken"
    "Content-Type" = "application/json"
}
```

---

## 3. Response Structure

### deviceManagementConfigurationSettingDefinition

This is the core object that describes each available setting in the Settings Catalog.

#### Complete JSON Structure

```json
{
  "@odata.type": "#microsoft.graph.deviceManagementConfigurationSettingDefinition",
  "id": "device_vendor_msft_policy_config_browser_allowsmartscreen",
  "name": "AllowSmartScreen",
  "displayName": "Allow Smart Screen",
  "description": "Microsoft Defender SmartScreen provides warning messages...",
  "helpText": "Detailed help text explaining the setting",
  "version": "1.0",
  "baseUri": "./Device/Vendor/MSFT/Policy",
  "offsetUri": "/Config/Browser/AllowSmartScreen",
  "rootDefinitionId": "device_vendor_msft_policy_config_browser_allowsmartscreen",
  "categoryId": "category-guid-here",
  "applicability": {
    "@odata.type": "microsoft.graph.deviceManagementConfigurationSettingApplicability",
    "description": "Applicable to Windows 10/11 devices",
    "platform": "windows10",
    "deviceMode": "none",
    "technologies": "mdm"
  },
  "accessTypes": "add,delete,get,replace",
  "keywords": [
    "SmartScreen",
    "Security",
    "Browser"
  ],
  "infoUrls": [
    "https://learn.microsoft.com/windows/client-management/mdm/policy-csp-browser"
  ],
  "occurrence": {
    "@odata.type": "microsoft.graph.deviceManagementConfigurationSettingOccurrence",
    "minDeviceOccurrence": 0,
    "maxDeviceOccurrence": 1
  },
  "settingUsage": "configuration",
  "uxBehavior": "toggle",
  "visibility": "settingsCatalog",
  "riskLevel": "low",
  "referredSettingInformationList": []
}
```

#### Key Properties for GPO Mapping

| Property | Type | Purpose for GPO Mapping |
|----------|------|-------------------------|
| **id** | String | Unique identifier (follows pattern: `device_vendor_msft_policy_config_{area}_{setting}`) |
| **name** | String | Setting name (often matches ADMX policy name) |
| **displayName** | String | User-friendly name shown in Intune UI |
| **description** | String | Detailed explanation of the setting |
| **baseUri** | String | Base CSP path (e.g., `./Device/Vendor/MSFT/Policy`) |
| **offsetUri** | String | Offset from base (e.g., `/Config/Browser/AllowSmartScreen`) |
| **categoryId** | String | Links to category for hierarchical organization |
| **applicability.platform** | String | Platform: `windows10`, `android`, `iOS`, etc. |
| **applicability.technologies** | String | Technology: `mdm`, `windows10XManagement`, `appleRemoteManagement` |
| **keywords** | String[] | Searchable terms |
| **infoUrls** | String[] | Links to CSP documentation |

#### Full CSP URI Construction

```
Full CSP URI = baseUri + offsetUri
Example: ./Device/Vendor/MSFT/Policy/Config/Browser/AllowSmartScreen
```

### ADMX-Backed Setting Identification

ADMX-backed settings can be identified by:

1. **Setting ID Pattern:**
   - Format: `device_vendor_msft_policy_config_admx_{category}_{policyname}`
   - Example: `device_vendor_msft_policy_config_admx_windowsexplorer_enablesmartscreen`

2. **CSP URI Pattern:**
   - ADMX policies use Policy CSP with ADMX category
   - Format: `./Device/Vendor/MSFT/Policy/Config/ADMX_{Category}/{PolicyName}`
   - Example: `./Device/Vendor/MSFT/Policy/Config/ADMX_WindowsExplorer/EnableSmartScreen`

3. **User vs Device Scope:**
   - Device scope: `./Device/Vendor/MSFT/Policy/...`
   - User scope: `./User/Vendor/MSFT/Policy/...`
   - Settings with "(User)" in displayName apply to users

### deviceManagementConfigurationCategory

Categories organize settings hierarchically, similar to GPO folder structure.

```json
{
  "@odata.type": "#microsoft.graph.deviceManagementConfigurationCategory",
  "id": "cff34dd2-4dd2-cff3-d24d-f3cfd24df3cf",
  "name": "Browser",
  "displayName": "Browser",
  "description": "Browser settings category",
  "categoryDescription": "Settings related to browser configuration",
  "helpText": "Configure browser behavior and security",
  "platforms": "windows10",
  "technologies": "mdm",
  "settingUsage": "configuration",
  "parentCategoryId": "parent-category-guid",
  "rootCategoryId": "root-category-guid",
  "childCategoryIds": [
    "child-category-1-guid",
    "child-category-2-guid"
  ]
}
```

**Hierarchical Navigation:**
- Use `parentCategoryId` to traverse up the tree
- Use `childCategoryIds` to traverse down
- Use `rootCategoryId` to jump to top-level category

### Registry Path Information

**Important Note:** The Graph API does **NOT** directly expose registry paths in the settingDefinition response. However, you can infer or map registry paths using:

1. **CSP Documentation:**
   - Each `infoUrls` links to Policy CSP documentation
   - CSP documentation shows registry mappings
   - Example: [Policy CSP - Browser](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-browser)

2. **ADMX File Parsing:**
   - ADMX files (in `%SystemRoot%\PolicyDefinitions`) contain registry mappings
   - Parse ADMX XML to extract `<key>` and `<valueName>` elements
   - Map ADMX policy name to Intune setting ID

3. **Empirical Mapping:**
   - Apply setting via Intune
   - Check device registry for changes
   - Build mapping database

---

## 4. Pagination

The Graph API uses OData pagination for large result sets.

### Detecting Pagination

```json
{
  "@odata.context": "https://graph.microsoft.com/beta/$metadata#deviceManagement/configurationSettings",
  "@odata.count": 2100,
  "@odata.nextLink": "https://graph.microsoft.com/beta/deviceManagement/configurationSettings?$skiptoken=xyz123...",
  "value": [
    { /* setting 1 */ },
    { /* setting 2 */ },
    // ... more settings
  ]
}
```

### PowerShell Pagination Example

```powershell
function Get-AllSettingDefinitions {
    param(
        [hashtable]$Headers
    )

    $AllSettings = @()
    $Uri = "https://graph.microsoft.com/beta/deviceManagement/configurationSettings"

    do {
        Write-Host "Fetching: $Uri"
        $Response = Invoke-RestMethod -Uri $Uri -Headers $Headers -Method Get

        # Add current page results
        $AllSettings += $Response.value

        # Get next page URL
        $Uri = $Response.'@odata.nextLink'

        Write-Host "Retrieved $($AllSettings.Count) settings so far..."

    } while ($null -ne $Uri)

    Write-Host "Total settings retrieved: $($AllSettings.Count)"
    return $AllSettings
}

# Usage
$Headers = @{
    Authorization = "Bearer $AccessToken"
    "Content-Type" = "application/json"
}

$AllSettings = Get-AllSettingDefinitions -Headers $Headers
```

### Pagination Best Practices

1. **Always check for `@odata.nextLink`** - Don't assume a single page
2. **Use `@odata.count`** - Shows total available items (if supported)
3. **Handle rate limiting** - Add delays if needed (429 Too Many Requests)
4. **Consider `$top` parameter** - Control page size (default is often 100-1000)
   ```http
   GET /deviceManagement/configurationSettings?$top=500
   ```

---

## 5. Search/Filter Capabilities

### OData Query Parameters

The Graph API supports OData query parameters for filtering, searching, and selecting data.

#### $filter (Filter by Property)

**Filter by platform:**
```http
GET /deviceManagement/configurationSettings?$filter=applicability/platform eq 'windows10'
```

**Filter by category:**
```http
GET /deviceManagement/configurationSettings?$filter=categoryId eq 'guid-here'
```

**Filter by technology:**
```http
GET /deviceManagement/configurationPolicies?$filter=technologies has 'mdm'
```

**Combine filters:**
```http
GET /deviceManagement/configurationPolicies?$filter=platforms has 'windows10' and technologies has 'mdm'
```

#### $search (Full-Text Search)

**Search by keyword:**
```http
GET /deviceManagement/configurationSettings?$search="smartscreen"
```

**Note:** `$search` support varies by endpoint and may not be available for all resources.

#### $select (Choose Properties)

**Retrieve specific properties only:**
```http
GET /deviceManagement/configurationSettings?$select=id,displayName,baseUri,offsetUri,categoryId
```

#### $expand (Include Related Resources)

**Expand setting definitions:**
```http
GET /deviceManagement/configurationPolicies('{id}')/settings?$expand=settingDefinitions
```

#### $orderby (Sort Results)

**Sort by display name:**
```http
GET /deviceManagement/configurationSettings?$orderby=displayName
```

### Advanced Query Example

```powershell
# Search for ADMX-backed Windows 10 browser settings
$Filter = "applicability/platform eq 'windows10' and contains(id,'admx')"
$Select = "id,displayName,name,baseUri,offsetUri,categoryId,keywords"
$OrderBy = "displayName"

$Uri = "https://graph.microsoft.com/beta/deviceManagement/configurationSettings?" +
       "`$filter=$Filter&" +
       "`$select=$Select&" +
       "`$orderby=$OrderBy"

$Response = Invoke-RestMethod -Uri $Uri -Headers $Headers -Method Get
```

### Search by Category Name

Since `categoryId` is a GUID, you need to:
1. First query categories to find the category ID
2. Then filter settings by that category ID

```powershell
# Step 1: Find category by name
$Categories = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationCategories" -Headers $Headers -Method Get
$BrowserCategory = $Categories.value | Where-Object { $_.displayName -eq "Browser" }

# Step 2: Get settings in that category
$Settings = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationSettings?`$filter=categoryId eq '$($BrowserCategory.id)'" -Headers $Headers -Method Get
```

---

## 6. Example API Calls

### Example 1: Get All Windows 10 Settings Catalog Policies

```powershell
$Uri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?`$filter=platforms has 'windows10' and technologies has 'mdm'"
$Headers = @{
    Authorization = "Bearer $AccessToken"
    "Content-Type" = "application/json"
}

$Policies = Invoke-RestMethod -Uri $Uri -Headers $Headers -Method Get

foreach ($Policy in $Policies.value) {
    Write-Host "$($Policy.name) - $($Policy.id)"
}
```

### Example 2: Get All Setting Definitions with Pagination

```powershell
$AllSettings = @()
$Uri = "https://graph.microsoft.com/beta/deviceManagement/configurationSettings"

do {
    $Response = Invoke-RestMethod -Uri $Uri -Headers $Headers -Method Get
    $AllSettings += $Response.value
    $Uri = $Response.'@odata.nextLink'
} while ($null -ne $Uri)

Write-Host "Total settings: $($AllSettings.Count)"

# Export to JSON
$AllSettings | ConvertTo-Json -Depth 10 | Out-File "AllSettingDefinitions.json"
```

### Example 3: Get Settings for a Specific Policy

```powershell
$PolicyId = "your-policy-guid-here"
$Uri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$PolicyId')/settings?`$expand=settingDefinitions"

$Settings = Invoke-RestMethod -Uri $Uri -Headers $Headers -Method Get

foreach ($Setting in $Settings.value) {
    $SettingDef = $Setting.settingDefinitions[0]
    Write-Host "Setting: $($SettingDef.displayName)"
    Write-Host "CSP URI: $($SettingDef.baseUri)$($SettingDef.offsetUri)"
    Write-Host "ID: $($SettingDef.id)"
    Write-Host ""
}
```

### Example 4: Search for ADMX Settings

```powershell
# Get all settings and filter locally (since $search may not work on all endpoints)
$AllSettings = @()
$Uri = "https://graph.microsoft.com/beta/deviceManagement/configurationSettings"

do {
    $Response = Invoke-RestMethod -Uri $Uri -Headers $Headers -Method Get
    $AllSettings += $Response.value
    $Uri = $Response.'@odata.nextLink'
} while ($null -ne $Uri)

# Filter for ADMX settings
$ADMXSettings = $AllSettings | Where-Object { $_.id -like "*admx*" }

Write-Host "Found $($ADMXSettings.Count) ADMX settings"

# Group by category
$ByCategory = $ADMXSettings | Group-Object -Property categoryId

foreach ($CategoryGroup in $ByCategory) {
    Write-Host "`nCategory: $($CategoryGroup.Name)"
    Write-Host "Settings count: $($CategoryGroup.Count)"
}
```

### Example 5: Create Settings Catalog Policy

```powershell
$NewPolicy = @{
    name = "Test Policy from Graph API"
    description = "Created via PowerShell and Graph API"
    platforms = "windows10"
    technologies = "mdm"
    settings = @(
        @{
            "@odata.type" = "#microsoft.graph.deviceManagementConfigurationSetting"
            settingInstance = @{
                "@odata.type" = "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance"
                settingDefinitionId = "device_vendor_msft_policy_config_browser_allowsmartscreen"
                choiceSettingValue = @{
                    "@odata.type" = "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue"
                    value = "device_vendor_msft_policy_config_browser_allowsmartscreen_1"
                    children = @()
                }
            }
        }
    )
} | ConvertTo-Json -Depth 10

$Uri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies"
$Response = Invoke-RestMethod -Uri $Uri -Headers $Headers -Method POST -Body $NewPolicy

Write-Host "Created policy: $($Response.id)"
```

---

## 7. Complete PowerShell Function Example

```powershell
function Get-SettingsCatalogDefinitions {
    <#
    .SYNOPSIS
        Retrieves all Settings Catalog definitions from Microsoft Graph API.

    .DESCRIPTION
        Queries the Microsoft Graph API to retrieve all available Settings Catalog
        setting definitions, with support for pagination, filtering, and caching.

    .PARAMETER AccessToken
        The OAuth 2.0 access token for Microsoft Graph API authentication.

    .PARAMETER Platform
        Filter by platform (e.g., 'windows10', 'android', 'iOS').

    .PARAMETER IncludeADMXOnly
        Return only ADMX-backed settings.

    .PARAMETER CachePath
        Path to cache the results (to avoid repeated API calls).

    .EXAMPLE
        $Token = (Get-MgGraphToken).AccessToken
        $Settings = Get-SettingsCatalogDefinitions -AccessToken $Token -Platform "windows10"

    .EXAMPLE
        $Settings = Get-SettingsCatalogDefinitions -AccessToken $Token -IncludeADMXOnly
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccessToken,

        [Parameter(Mandatory = $false)]
        [ValidateSet('windows10', 'android', 'iOS', 'macOS')]
        [string]$Platform,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeADMXOnly,

        [Parameter(Mandatory = $false)]
        [string]$CachePath
    )

    # Check cache
    if ($CachePath -and (Test-Path $CachePath)) {
        Write-Host "Loading from cache: $CachePath"
        $CachedData = Get-Content $CachePath -Raw | ConvertFrom-Json

        # Apply filters if needed
        if ($Platform) {
            $CachedData = $CachedData | Where-Object { $_.applicability.platform -eq $Platform }
        }
        if ($IncludeADMXOnly) {
            $CachedData = $CachedData | Where-Object { $_.id -like "*admx*" }
        }

        return $CachedData
    }

    # Build headers
    $Headers = @{
        Authorization = "Bearer $AccessToken"
        "Content-Type" = "application/json"
    }

    # Build URI with filters
    $Uri = "https://graph.microsoft.com/beta/deviceManagement/configurationSettings"

    if ($Platform) {
        $Uri += "?`$filter=applicability/platform eq '$Platform'"
    }

    # Retrieve all pages
    Write-Host "Querying Microsoft Graph API..."
    $AllSettings = @()
    $PageCount = 0

    do {
        $PageCount++
        Write-Host "Fetching page $PageCount..."

        try {
            $Response = Invoke-RestMethod -Uri $Uri -Headers $Headers -Method Get -ErrorAction Stop
            $AllSettings += $Response.value
            $Uri = $Response.'@odata.nextLink'

            Write-Host "  Retrieved $($Response.value.Count) settings (Total: $($AllSettings.Count))"

        } catch {
            Write-Error "Error querying Graph API: $_"
            return $null
        }

    } while ($null -ne $Uri)

    Write-Host "Total settings retrieved: $($AllSettings.Count)"

    # Apply ADMX filter if requested
    if ($IncludeADMXOnly) {
        Write-Host "Filtering for ADMX-backed settings..."
        $AllSettings = $AllSettings | Where-Object { $_.id -like "*admx*" }
        Write-Host "ADMX settings: $($AllSettings.Count)"
    }

    # Cache results
    if ($CachePath) {
        Write-Host "Caching results to: $CachePath"
        $AllSettings | ConvertTo-Json -Depth 10 | Out-File $CachePath -Force
    }

    return $AllSettings
}

# Example usage
Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All"
$Token = (Get-MgContext).AccessToken

$AllSettings = Get-SettingsCatalogDefinitions `
    -AccessToken $Token `
    -Platform "windows10" `
    -CachePath "C:\Temp\SettingsCatalog.json"

# Find settings related to "SmartScreen"
$SmartScreenSettings = $AllSettings | Where-Object {
    $_.displayName -like "*SmartScreen*" -or
    $_.keywords -contains "SmartScreen"
}

foreach ($Setting in $SmartScreenSettings) {
    Write-Host "`nSetting: $($Setting.displayName)"
    Write-Host "ID: $($Setting.id)"
    Write-Host "CSP URI: $($Setting.baseUri)$($Setting.offsetUri)"
}
```

---

## 8. Gotchas and Limitations

### 1. Beta API Stability
- **Issue:** Settings Catalog uses the `beta` endpoint, which may change
- **Mitigation:**
  - Pin to specific API version in production code
  - Monitor Microsoft Graph changelog
  - Test regularly for breaking changes

### 2. No Direct Registry Path Exposure
- **Issue:** Graph API doesn't return registry paths in responses
- **Mitigation:**
  - Parse ADMX files locally to extract registry mappings
  - Use CSP documentation to infer registry paths
  - Build empirical mapping by testing settings

### 3. Large Result Sets
- **Issue:** ~2,100+ settings in catalog (and growing)
- **Mitigation:**
  - Always implement pagination
  - Cache results locally
  - Use filters to reduce result size
  - Consider incremental updates

### 4. Category Resolution
- **Issue:** `categoryId` is a GUID, not human-readable
- **Mitigation:**
  - Query `/configurationCategories` separately
  - Build a category lookup dictionary
  - Cache category tree for performance

### 5. Rate Limiting
- **Issue:** Microsoft Graph has rate limits (varies by tenant)
- **Mitigation:**
  - Implement exponential backoff on 429 errors
  - Add delays between requests if hitting limits
  - Use caching to reduce API calls

### 6. Setting Instance vs Definition
- **Issue:** Confusion between `settingDefinition` (metadata) and `settingInstance` (actual value)
- **Clarification:**
  - `settingDefinition` = What settings are available (schema)
  - `settingInstance` = What values are configured (data)

### 7. Complex Nested Settings
- **Issue:** Some settings have children (nested configurations)
- **Mitigation:**
  - Use `$expand=settingDefinitions` to get full structure
  - Check `rootDefinitionId` to identify parent-child relationships
  - Handle recursive JSON parsing

### 8. ADMX Identification
- **Issue:** Not all settings clearly marked as ADMX-backed
- **Identification Methods:**
  - Check if `id` contains "admx": `*admx*`
  - Check if `offsetUri` contains "ADMX": `*/ADMX_*`
  - Check `infoUrls` for ADMX-specific documentation

### 9. User vs Device Scope
- **Issue:** Some settings apply to users, others to devices
- **Identification:**
  - Check `baseUri`: `./Device/...` vs `./User/...`
  - Check `displayName` for "(User)" suffix
  - Check `applicability.deviceMode`

### 10. Permissions and Licensing
- **Issue:** API requires active Intune license and proper permissions
- **Validation:**
  - Check tenant has Intune subscription
  - Verify app/user has `DeviceManagementConfiguration` permissions
  - Test authentication before bulk operations

---

## 9. Mapping GPO to Intune Strategy

### Approach Overview

1. **Collect GPO Settings** (existing PolicyLens functionality)
   - Run `gpresult /scope:computer /x report.xml`
   - Parse registry keys from `HKLM\Software\Policies`

2. **Query Settings Catalog** (new functionality)
   - Retrieve all setting definitions via Graph API
   - Cache locally for performance

3. **Build Mapping Database**
   - Parse ADMX files to extract registry paths
   - Map ADMX policy names to Intune setting IDs
   - Store in extensible mapping file (like `SettingsMap.psd1`)

4. **Match Settings**
   - For each GPO registry key, search mapping database
   - Return matching Intune setting ID and CSP URI
   - Flag unmapped settings for manual review

### Example Mapping Entry

```powershell
@{
    # GPO Information
    GPOPolicyName = "Turn on SmartScreen"
    GPOCategory = "Windows Components\Microsoft Defender SmartScreen\Explorer"
    RegistryPath = "HKLM\Software\Policies\Microsoft\Windows\System"
    RegistryValue = "EnableSmartScreen"

    # Intune Information
    IntuneSettingId = "device_vendor_msft_policy_config_admx_windowsexplorer_enablesmartscreen"
    IntuneDisplayName = "Configure Windows Defender SmartScreen"
    CSPURI = "./Device/Vendor/MSFT/Policy/Config/ADMX_WindowsExplorer/EnableSmartScreen"
    CSPDocUrl = "https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-windowsexplorer"

    # Mapping Metadata
    MappingConfidence = "High"  # High, Medium, Low
    MappingSource = "ADMX"  # ADMX, CSP, Manual, Empirical
    LastVerified = "2026-02-02"
}
```

---

## 10. References and Resources

### Official Microsoft Documentation

- [Working with Intune in Microsoft Graph](https://learn.microsoft.com/en-us/graph/api/resources/intune-graph-overview?view=graph-rest-1.0)
- [deviceManagementConfigurationPolicy resource type](https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfigv2-devicemanagementconfigurationpolicy?view=graph-rest-beta)
- [List deviceManagementConfigurationSettingDefinitions](https://learn.microsoft.com/en-us/graph/api/intune-deviceconfigv2-devicemanagementconfigurationsettingdefinition-list?view=graph-rest-beta)
- [List deviceManagementConfigurationCategories](https://learn.microsoft.com/en-us/graph/api/intune-deviceconfigv2-devicemanagementconfigurationcategory-list?view=graph-rest-beta)
- [Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-configuration-service-provider)
- [Understanding ADMX policies](https://learn.microsoft.com/en-us/windows/client-management/understanding-admx-backed-policies)
- [Create a policy using settings catalog](https://learn.microsoft.com/en-us/intune/intune-service/configuration/settings-catalog)

### Community Resources

- [Deploy Intune settings catalog automated from scratch with Graph API](https://rozemuller.com/deploy-intune-settings-catalog-automated-from-scratch-with-graph-api/)
- [Working with Intune Settings Catalog using PowerShell and Graph](https://powers-hell.com/2021/03/08/working-with-intune-settings-catalog-using-powershell-and-graph/)
- [Microsoft Graph PowerShell Intune Samples - Settings Catalog](https://github.com/microsoftgraph/powershell-intune-samples/blob/master/SettingsCatalog/SettingsCatalog_Export.ps1)

### Graph API Tools

- [Microsoft Graph Explorer](https://developer.microsoft.com/en-us/graph/graph-explorer) - Interactive API testing
- [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/overview) - Official PowerShell module
- [Graph X-Ray](https://graphxray.merill.net/) - Visualize Graph API calls

---

## Appendix A: Sample Response Data

### Full Setting Definition Response

```json
{
  "@odata.context": "https://graph.microsoft.com/beta/$metadata#deviceManagement/configurationSettings",
  "@odata.count": 2147,
  "value": [
    {
      "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingDefinition",
      "id": "device_vendor_msft_policy_config_browser_allowsmartscreen",
      "name": "AllowSmartScreen",
      "displayName": "Configure Windows Defender SmartScreen",
      "description": "Microsoft Defender SmartScreen provides warning messages to help protect your users from potential phishing scams and malicious software. By default, Windows Defender SmartScreen is turned on.",
      "helpText": "Microsoft Defender SmartScreen helps protect PCs by warning users before running unrecognized programs downloaded from the Internet. Some information is sent to Microsoft about files and programs run on PCs with this feature enabled.",
      "version": "1.0",
      "baseUri": "./Device/Vendor/MSFT/Policy",
      "offsetUri": "/Config/Browser/AllowSmartScreen",
      "rootDefinitionId": "device_vendor_msft_policy_config_browser_allowsmartscreen",
      "categoryId": "bca7f43f-a5bf-4f6e-82f5-cd1a792c8c38",
      "applicability": {
        "@odata.type": "microsoft.graph.deviceManagementConfigurationSettingApplicability",
        "description": null,
        "platform": "windows10",
        "deviceMode": "none",
        "technologies": "mdm"
      },
      "accessTypes": "add,delete,get,replace",
      "keywords": [
        "AllowSmartScreen",
        "SmartScreen",
        "Browser",
        "Security",
        "Windows Defender"
      ],
      "infoUrls": [
        "https://learn.microsoft.com/windows/client-management/mdm/policy-csp-browser#browser-allowsmartscreen"
      ],
      "occurrence": {
        "@odata.type": "microsoft.graph.deviceManagementConfigurationSettingOccurrence",
        "minDeviceOccurrence": 0,
        "maxDeviceOccurrence": 1
      },
      "settingUsage": "configuration",
      "uxBehavior": "toggle",
      "visibility": "settingsCatalog",
      "riskLevel": "low",
      "referredSettingInformationList": [],
      "options": [
        {
          "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValueDefinition",
          "displayName": "Allowed",
          "name": "Allowed",
          "itemId": "device_vendor_msft_policy_config_browser_allowsmartscreen_1",
          "optionValue": {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationIntegerSettingValue",
            "value": 1
          }
        },
        {
          "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValueDefinition",
          "displayName": "Not Allowed",
          "name": "Not Allowed",
          "itemId": "device_vendor_msft_policy_config_browser_allowsmartscreen_0",
          "optionValue": {
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationIntegerSettingValue",
            "value": 0
          }
        }
      ]
    }
  ]
}
```

### ADMX-Backed Setting Example

```json
{
  "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingDefinition",
  "id": "device_vendor_msft_policy_config_admx_windowsexplorer_enablesmartscreen",
  "name": "EnableSmartScreen",
  "displayName": "Configure Windows Defender SmartScreen",
  "description": "This policy setting allows you to manage the behavior of Windows SmartScreen. Windows SmartScreen helps keep PCs safer by warning users before running unrecognized programs downloaded from the Internet.",
  "helpText": null,
  "version": "1.0",
  "baseUri": "./Device/Vendor/MSFT/Policy",
  "offsetUri": "/Config/ADMX_WindowsExplorer/EnableSmartScreen",
  "rootDefinitionId": "device_vendor_msft_policy_config_admx_windowsexplorer_enablesmartscreen",
  "categoryId": "df7e2d4c-2b4e-4c6f-8c8e-7f6c5a8b9d3e",
  "applicability": {
    "@odata.type": "microsoft.graph.deviceManagementConfigurationSettingApplicability",
    "description": null,
    "platform": "windows10",
    "deviceMode": "none",
    "technologies": "mdm"
  },
  "accessTypes": "add,delete,get,replace",
  "keywords": [
    "EnableSmartScreen",
    "SmartScreen",
    "Windows Explorer",
    "Security"
  ],
  "infoUrls": [
    "https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-windowsexplorer#admx-windowsexplorer-enablesmartscreen"
  ],
  "occurrence": {
    "@odata.type": "microsoft.graph.deviceManagementConfigurationSettingOccurrence",
    "minDeviceOccurrence": 0,
    "maxDeviceOccurrence": 1
  },
  "settingUsage": "configuration",
  "uxBehavior": "dropdown",
  "visibility": "settingsCatalog",
  "riskLevel": "low",
  "referredSettingInformationList": []
}
```

---

## Document Metadata

**Created:** 2026-02-02
**Author:** PolicyLens Development Team
**Purpose:** Graph API research for GPO-to-Intune mapping feature
**Target Audience:** PowerShell developers, Intune administrators
**Related Files:**
- `/Public/Get-GraphPolicyData.ps1` (existing Graph function)
- `/Config/SettingsMap.psd1` (mapping database)
- Future: `/Public/Get-SettingsCatalogMappings.ps1`
