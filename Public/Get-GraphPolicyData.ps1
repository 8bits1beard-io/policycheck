function Get-GraphPolicyData {
    <#
    .SYNOPSIS
        Queries Microsoft Graph API for Intune policy metadata.
    .DESCRIPTION
        Connects to Microsoft Graph and retrieves device configuration profiles,
        compliance policies, and Settings Catalog policies with their assignments.
        When FilterLookup is provided, assignments are enriched with filter names and rules.
    .PARAMETER TenantId
        Azure AD tenant ID for authentication.
    .PARAMETER GraphConnected
        Skip connecting/disconnecting from Graph (caller manages the connection).
    .PARAMETER FilterLookup
        Hashtable of filter definitions keyed by filter ID, from Get-AssignmentFilterDefinitions.
        Used to enrich assignments with filter name and rule information.
    .OUTPUTS
        PSCustomObject with profiles, compliance policies, and settings catalog data.
    .AUTHOR
        Joshua Walderbach
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [string]$TenantId,

        [switch]$GraphConnected,

        [hashtable]$FilterLookup
    )

    Write-Verbose "Querying Microsoft Graph API for Intune policy data..."

    # --- 1. Check for Microsoft.Graph module ---
    $graphModule = Get-Module -ListAvailable Microsoft.Graph.DeviceManagement -ErrorAction SilentlyContinue
    if (-not $graphModule) {
        Write-Warning @"
Microsoft.Graph.DeviceManagement module not found.
Install it with: Install-Module Microsoft.Graph -Scope CurrentUser
Then re-run with -IncludeGraph to fetch Intune policy details.
"@
        return [PSCustomObject]@{
            Available          = $false
            Profiles           = @()
            CompliancePolicies = @()
            SettingsCatalog    = @()
            CollectedAt        = Get-Date
        }
    }

    # --- 2. Connect to Graph (if not already connected) ---
    if (-not $GraphConnected) {
        try {
            $connectParams = @{
                Scopes = @(
                    'DeviceManagementConfiguration.Read.All'
                    'DeviceManagementManagedDevices.Read.All'
                )
            }
            if ($TenantId) {
                $connectParams['TenantId'] = $TenantId
            }

            Write-Host "  Connecting to Microsoft Graph (browser auth)..." -ForegroundColor Gray
            Connect-MgGraph @connectParams -ErrorAction Stop | Out-Null
            Write-Verbose "Connected to Microsoft Graph successfully."
        }
        catch {
            Write-Warning "Failed to connect to Microsoft Graph: $_"
            return [PSCustomObject]@{
                Available          = $false
                Profiles           = @()
                CompliancePolicies = @()
                SettingsCatalog    = @()
                CollectedAt        = Get-Date
            }
        }
    }

    # --- 3. Get device configuration profiles (using beta with $expand for assignments) ---
    $profiles = @()
    try {
        Write-Host "        Fetching device configuration profiles..." -ForegroundColor Gray
        $uri = 'https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?$expand=assignments&$top=999'
        $response = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop

        $allConfigs = @($response.value)
        while ($response.'@odata.nextLink') {
            $response = Invoke-MgGraphRequest -Uri $response.'@odata.nextLink' -Method GET -ErrorAction Stop
            $allConfigs += $response.value
        }

        Write-Host "        Processing $($allConfigs.Count) profiles..." -ForegroundColor Gray

        $profiles = @(foreach ($config in $allConfigs) {
            $assignments = @($config.assignments | Where-Object { $_ } | ForEach-Object {
                $target = $_.target
                $targetLabel = switch ($target.'@odata.type') {
                    '#microsoft.graph.allDevicesAssignmentTarget'       { 'All Devices' }
                    '#microsoft.graph.allLicensedUsersAssignmentTarget' { 'All Users' }
                    '#microsoft.graph.groupAssignmentTarget'            { "Group: $($target.groupId)" }
                    '#microsoft.graph.exclusionGroupAssignmentTarget'   { "Exclude: $($target.groupId)" }
                    default { $target.'@odata.type' -replace '#microsoft\.graph\.' }
                }

                # Enrich with filter information if available
                $filterId = $target.deviceAndAppManagementAssignmentFilterId
                $filterName = $null
                $filterRule = $null
                if ($filterId -and $FilterLookup -and $FilterLookup.ContainsKey($filterId)) {
                    $filterDef = $FilterLookup[$filterId]
                    $filterName = $filterDef.DisplayName
                    $filterRule = $filterDef.Rule
                }

                [PSCustomObject]@{
                    TargetType = $targetLabel
                    GroupId    = $target.groupId
                    FilterId   = $filterId
                    FilterType = $target.deviceAndAppManagementAssignmentFilterType
                    FilterName = $filterName
                    FilterRule = $filterRule
                }
            })

            [PSCustomObject]@{
                Id              = $config.id
                DisplayName     = $config.displayName
                Description     = $config.description
                OdataType       = $config.'@odata.type'
                CreatedDateTime = $config.createdDateTime
                LastModified    = $config.lastModifiedDateTime
                Assignments     = $assignments
            }
        })

        Write-Verbose "Retrieved $($profiles.Count) device configuration profiles."
    }
    catch {
        Write-Warning "Failed to retrieve device configuration profiles: $_"
    }

    # --- 4. Get compliance policies (using beta with $expand) ---
    $compliancePolicies = @()
    try {
        Write-Host "        Fetching compliance policies..." -ForegroundColor Gray
        $uri = 'https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies?$expand=assignments&$top=999'
        $response = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop

        $allPolicies = @($response.value)
        while ($response.'@odata.nextLink') {
            $response = Invoke-MgGraphRequest -Uri $response.'@odata.nextLink' -Method GET -ErrorAction Stop
            $allPolicies += $response.value
        }

        Write-Host "        Processing $($allPolicies.Count) compliance policies..." -ForegroundColor Gray

        $compliancePolicies = @(foreach ($policy in $allPolicies) {
            $assignments = @($policy.assignments | Where-Object { $_ } | ForEach-Object {
                $target = $_.target
                $targetLabel = switch ($target.'@odata.type') {
                    '#microsoft.graph.allDevicesAssignmentTarget'       { 'All Devices' }
                    '#microsoft.graph.allLicensedUsersAssignmentTarget' { 'All Users' }
                    '#microsoft.graph.groupAssignmentTarget'            { "Group: $($target.groupId)" }
                    '#microsoft.graph.exclusionGroupAssignmentTarget'   { "Exclude: $($target.groupId)" }
                    default { $target.'@odata.type' -replace '#microsoft\.graph\.' }
                }

                # Enrich with filter information if available
                $filterId = $target.deviceAndAppManagementAssignmentFilterId
                $filterName = $null
                $filterRule = $null
                if ($filterId -and $FilterLookup -and $FilterLookup.ContainsKey($filterId)) {
                    $filterDef = $FilterLookup[$filterId]
                    $filterName = $filterDef.DisplayName
                    $filterRule = $filterDef.Rule
                }

                [PSCustomObject]@{
                    TargetType = $targetLabel
                    GroupId    = $target.groupId
                    FilterId   = $filterId
                    FilterType = $target.deviceAndAppManagementAssignmentFilterType
                    FilterName = $filterName
                    FilterRule = $filterRule
                }
            })

            [PSCustomObject]@{
                Id              = $policy.id
                DisplayName     = $policy.displayName
                Description     = $policy.description
                OdataType       = $policy.'@odata.type'
                CreatedDateTime = $policy.createdDateTime
                LastModified    = $policy.lastModifiedDateTime
                Assignments     = $assignments
            }
        })

        Write-Verbose "Retrieved $($compliancePolicies.Count) compliance policies."
    }
    catch {
        Write-Warning "Failed to retrieve compliance policies: $_"
    }

    # --- 5. Get Settings Catalog policies (beta endpoint with $expand) ---
    $settingsCatalog = @()
    try {
        Write-Host "        Fetching Settings Catalog policies..." -ForegroundColor Gray
        $uri = 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?$expand=assignments&$top=999'
        $response = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop

        $allCatalog = @($response.value)
        while ($response.'@odata.nextLink') {
            $response = Invoke-MgGraphRequest -Uri $response.'@odata.nextLink' -Method GET -ErrorAction Stop
            $allCatalog += $response.value
        }

        Write-Host "        Processing $($allCatalog.Count) Settings Catalog policies..." -ForegroundColor Gray

        $settingsCatalog = @(foreach ($policy in $allCatalog) {
            $assignments = @($policy.assignments | Where-Object { $_ } | ForEach-Object {
                $target = $_.target
                $targetLabel = switch ($target.'@odata.type') {
                    '#microsoft.graph.allDevicesAssignmentTarget'       { 'All Devices' }
                    '#microsoft.graph.allLicensedUsersAssignmentTarget' { 'All Users' }
                    '#microsoft.graph.groupAssignmentTarget'            { "Group: $($target.groupId)" }
                    '#microsoft.graph.exclusionGroupAssignmentTarget'   { "Exclude: $($target.groupId)" }
                    default { $target.'@odata.type' -replace '#microsoft\.graph\.' }
                }

                # Enrich with filter information if available
                $filterId = $target.deviceAndAppManagementAssignmentFilterId
                $filterName = $null
                $filterRule = $null
                if ($filterId -and $FilterLookup -and $FilterLookup.ContainsKey($filterId)) {
                    $filterDef = $FilterLookup[$filterId]
                    $filterName = $filterDef.DisplayName
                    $filterRule = $filterDef.Rule
                }

                [PSCustomObject]@{
                    TargetType = $targetLabel
                    GroupId    = $target.groupId
                    FilterId   = $filterId
                    FilterType = $target.deviceAndAppManagementAssignmentFilterType
                    FilterName = $filterName
                    FilterRule = $filterRule
                }
            })

            [PSCustomObject]@{
                Id              = $policy.id
                Name            = $policy.name
                Description     = $policy.description
                Platforms       = $policy.platforms
                Technologies    = $policy.technologies
                CreatedDateTime = $policy.createdDateTime
                LastModified    = $policy.lastModifiedDateTime
                Assignments     = $assignments
            }
        })

        Write-Verbose "Retrieved $($settingsCatalog.Count) Settings Catalog policies."
    }
    catch {
        Write-Verbose "Could not retrieve Settings Catalog policies (beta): $_"
    }

    # --- 6. Disconnect (only if we connected) ---
    if (-not $GraphConnected) {
        try {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        }
        catch { }
    }

    [PSCustomObject]@{
        Available          = $true
        Profiles           = $profiles
        CompliancePolicies = $compliancePolicies
        SettingsCatalog    = $settingsCatalog
        CollectedAt        = Get-Date
    }
}
