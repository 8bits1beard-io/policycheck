function Get-DeviceAppAssignments {
    <#
    .SYNOPSIS
        Queries Microsoft Graph API for Intune app assignments relevant to the device.
    .DESCRIPTION
        Retrieves all mobile apps configured in Intune along with their assignments,
        including Win32 apps, LOB apps, Microsoft Store apps, and web apps.
        Requires an active Microsoft Graph connection (call after Connect-MgGraph).
        When FilterLookup is provided, assignments are enriched with filter names and rules.
    .PARAMETER GraphConnected
        Indicates Graph is already connected (called from Invoke-PolicyLens).
    .PARAMETER SkipLocalApps
        Skip the local Win32Apps registry enumeration. Use this when scanning a
        remote device where the local registry is not relevant.
    .PARAMETER FilterLookup
        Hashtable of filter definitions keyed by filter ID, from Get-AssignmentFilterDefinitions.
        Used to enrich assignments with filter name and rule information.
    .OUTPUTS
        PSCustomObject with app assignment details.
    .AUTHOR
        Joshua Walderbach
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [switch]$GraphConnected,

        [switch]$SkipLocalApps,

        [hashtable]$FilterLookup
    )

    Write-Verbose "Querying Microsoft Graph for app assignments..."

    if (-not $GraphConnected) {
        $context = Get-MgContext -ErrorAction SilentlyContinue
        if (-not $context) {
            Write-Warning "Not connected to Microsoft Graph. Call Connect-MgGraph first or use -IncludeGraph."
            return [PSCustomObject]@{
                Available = $false
                Apps      = @()
                CollectedAt = Get-Date
            }
        }
    }

    $apps = @()

    # --- 1. Get all mobile apps with assignments ---
    try {
        $uri = 'https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?$expand=assignments&$top=999'
        $response = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop

        $allApps = @($response.value)

        # Handle pagination
        while ($response.'@odata.nextLink') {
            $response = Invoke-MgGraphRequest -Uri $response.'@odata.nextLink' -Method GET -ErrorAction Stop
            $allApps += $response.value
        }

        $apps = @(foreach ($app in $allApps) {
            # Determine app type from odata type
            $odataType = $app.'@odata.type'
            $appType = switch -Wildcard ($odataType) {
                '*win32LobApp'              { 'Win32 App' }
                '*windowsMobileMSI'         { 'MSI (LOB)' }
                '*microsoftStoreForBusiness*' { 'Microsoft Store' }
                '*winGetApp'                { 'WinGet App' }
                '*webApp'                   { 'Web Link' }
                '*officeSuiteApp'           { 'Microsoft 365 Apps' }
                '*windowsUniversalAppX'     { 'MSIX/AppX' }
                '*windowsAppX'              { 'AppX' }
                '*managedIOSStoreApp'       { 'iOS Store App' }
                '*managedAndroidStoreApp'   { 'Android Store App' }
                default                     { $odataType -replace '#microsoft\.graph\.' }
            }

            # Parse assignments
            $assignments = @($app.assignments | Where-Object { $_ } | ForEach-Object {
                $target = $_.target
                $intentLabel = switch ($_.intent) {
                    'required'              { 'Required' }
                    'available'             { 'Available' }
                    'uninstall'             { 'Uninstall' }
                    'availableWithoutEnrollment' { 'Available (No Enrollment)' }
                    default                 { $_.intent }
                }

                $targetLabel = switch ($target.'@odata.type') {
                    '#microsoft.graph.allDevicesAssignmentTarget'       { 'All Devices' }
                    '#microsoft.graph.allLicensedUsersAssignmentTarget' { 'All Users' }
                    '#microsoft.graph.groupAssignmentTarget'            { "Group: $($target.groupId)" }
                    '#microsoft.graph.exclusionGroupAssignmentTarget'   { "Exclude Group: $($target.groupId)" }
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
                    Intent     = $intentLabel
                    TargetType = $targetLabel
                    GroupId    = $target.groupId
                    FilterId   = $filterId
                    FilterType = $target.deviceAndAppManagementAssignmentFilterType
                    FilterName = $filterName
                    FilterRule = $filterRule
                }
            })

            # Get version - different app types store version in different properties
            $appVersion = $app.displayVersion
            if (-not $appVersion) { $appVersion = $app.version }
            if (-not $appVersion) { $appVersion = $app.productVersion }

            [PSCustomObject]@{
                Id           = $app.id
                DisplayName  = $app.displayName
                Description  = $app.description
                AppType      = $appType
                OdataType    = $odataType
                Publisher    = $app.publisher
                Version      = $appVersion
                CreatedDate  = $app.createdDateTime
                LastModified = $app.lastModifiedDateTime
                Assignments  = $assignments
                IsAssigned   = ($assignments.Count -gt 0)
            }
        })

        Write-Verbose "Retrieved $($apps.Count) apps ($(@($apps | Where-Object IsAssigned).Count) with assignments)."
    }
    catch {
        Write-Warning "Failed to retrieve app assignments from Graph: $_"
    }

    # --- 2. Get locally installed Intune-managed apps (from registry) ---
    # Skip this for remote scans where local registry is not relevant
    $localApps = @()

    if (-not $SkipLocalApps) {
        $imePath = 'HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps'

        if (Test-Path $imePath) {
            $userFolders = Get-ChildItem $imePath -ErrorAction SilentlyContinue
            foreach ($userFolder in $userFolders) {
                $appFolders = Get-ChildItem $userFolder.PSPath -ErrorAction SilentlyContinue
                foreach ($appFolder in $appFolders) {
                    $props = Get-ItemProperty $appFolder.PSPath -ErrorAction SilentlyContinue
                    if ($props) {
                        # Determine installation state from Result code
                        # Common Result codes: 0 = Pending/InProgress, 1 = Success, others = Failed
                        $installState = switch ($props.Result) {
                            1       { 'Installed' }
                            0       { 'Pending' }
                            $null   { 'Unknown' }
                            default { 'Failed' }
                        }

                        $localApps += [PSCustomObject]@{
                            AppId        = $appFolder.PSChildName
                            UserId       = $userFolder.PSChildName
                            Result       = $props.Result
                            ResultCode   = $props.ResultCode
                            ErrorCode    = $props.ErrorCode
                            InstallState = $installState
                        }
                    }
                }
            }
        }
    }

    [PSCustomObject]@{
        Available      = $true
        Apps           = $apps
        AssignedApps   = @($apps | Where-Object IsAssigned)
        LocalApps      = $localApps
        CollectedAt    = Get-Date
    }
}
