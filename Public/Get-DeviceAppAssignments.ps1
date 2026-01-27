function Get-DeviceAppAssignments {
    <#
    .SYNOPSIS
        Queries Microsoft Graph API for Intune app assignments relevant to the device.
    .DESCRIPTION
        Retrieves all mobile apps configured in Intune along with their assignments,
        including Win32 apps, LOB apps, Microsoft Store apps, and web apps.
        Requires an active Microsoft Graph connection (call after Connect-MgGraph).
    .PARAMETER GraphConnected
        Indicates Graph is already connected (called from Invoke-PolicyCheck).
    .OUTPUTS
        PSCustomObject with app assignment details.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [switch]$GraphConnected
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

                [PSCustomObject]@{
                    Intent     = $intentLabel
                    TargetType = $targetLabel
                    GroupId    = $target.groupId
                    FilterId   = if ($_.target.deviceAndAppManagementAssignmentFilterId) {
                        $_.target.deviceAndAppManagementAssignmentFilterId
                    } else { $null }
                    FilterType = if ($_.target.deviceAndAppManagementAssignmentFilterType) {
                        $_.target.deviceAndAppManagementAssignmentFilterType
                    } else { $null }
                }
            })

            [PSCustomObject]@{
                Id           = $app.id
                DisplayName  = $app.displayName
                Description  = $app.description
                AppType      = $appType
                OdataType    = $odataType
                Publisher    = $app.publisher
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
    $localApps = @()
    $imePath = 'HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps'

    if (Test-Path $imePath) {
        $userFolders = Get-ChildItem $imePath -ErrorAction SilentlyContinue
        foreach ($userFolder in $userFolders) {
            $appFolders = Get-ChildItem $userFolder.PSPath -ErrorAction SilentlyContinue
            foreach ($appFolder in $appFolders) {
                $props = Get-ItemProperty $appFolder.PSPath -ErrorAction SilentlyContinue
                if ($props) {
                    $localApps += [PSCustomObject]@{
                        AppId   = $appFolder.PSChildName
                        UserId  = $userFolder.PSChildName
                        Result  = $props.Result
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
