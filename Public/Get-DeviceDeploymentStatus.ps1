function Get-DeviceDeploymentStatus {
    <#
    .SYNOPSIS
        Queries Microsoft Graph for device-specific policy deployment status.
    .DESCRIPTION
        Retrieves the deployment/application status of Intune configuration profiles
        and compliance policies for a specific device. Uses the device's Azure AD
        device ID to find the corresponding Intune managed device, then queries
        the deployment states.
    .PARAMETER AzureADDeviceId
        The Azure AD device ID (GUID) of the device to query.
    .PARAMETER GraphConnected
        Skip connecting/disconnecting from Graph (caller manages the connection).
    .OUTPUTS
        PSCustomObject with profile and compliance policy deployment states.
    .EXAMPLE
        Get-DeviceDeploymentStatus -AzureADDeviceId "12345678-1234-1234-1234-123456789012" -GraphConnected
    .AUTHOR
        Joshua Walderbach
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$AzureADDeviceId,

        [switch]$GraphConnected
    )

    Write-Verbose "Querying deployment status for device: $AzureADDeviceId"

    # --- 1. Check for Microsoft.Graph module ---
    $graphModule = Get-Module -ListAvailable Microsoft.Graph.DeviceManagement -ErrorAction SilentlyContinue
    if (-not $graphModule) {
        Write-Warning "Microsoft.Graph.DeviceManagement module not found."
        return [PSCustomObject]@{
            Available        = $false
            IntuneDeviceId   = $null
            ProfileStates    = @()
            ComplianceStates = @()
            CollectedAt      = Get-Date
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
            Write-Host "  Connecting to Microsoft Graph (browser auth)..." -ForegroundColor Gray
            Connect-MgGraph @connectParams -ErrorAction Stop | Out-Null
            Write-Verbose "Connected to Microsoft Graph successfully."
        }
        catch {
            Write-Warning "Failed to connect to Microsoft Graph: $_"
            return [PSCustomObject]@{
                Available        = $false
                IntuneDeviceId   = $null
                ProfileStates    = @()
                ComplianceStates = @()
                CollectedAt      = Get-Date
            }
        }
    }

    # --- 3. Find the Intune managed device by Azure AD device ID ---
    $intuneDeviceId = $null
    $deviceName = $null
    try {
        Write-Host "        Looking up Intune managed device..." -ForegroundColor Gray
        $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=azureADDeviceId eq '$AzureADDeviceId'&`$select=id,deviceName,managementState,complianceState"
        $response = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop

        if ($response.value -and $response.value.Count -gt 0) {
            $intuneDevice = $response.value[0]
            $intuneDeviceId = $intuneDevice.id
            $deviceName = $intuneDevice.deviceName
            Write-Verbose "Found Intune device: $deviceName (ID: $intuneDeviceId)"
        }
        else {
            Write-Warning "Device not found in Intune managed devices. It may be Azure AD joined but not Intune enrolled."
            return [PSCustomObject]@{
                Available        = $true
                DeviceFound      = $false
                IntuneDeviceId   = $null
                ProfileStates    = @()
                ComplianceStates = @()
                CollectedAt      = Get-Date
            }
        }
    }
    catch {
        Write-Warning "Failed to look up Intune managed device: $_"
        return [PSCustomObject]@{
            Available        = $false
            IntuneDeviceId   = $null
            ProfileStates    = @()
            ComplianceStates = @()
            CollectedAt      = Get-Date
        }
    }

    # --- 4. Get device configuration states ---
    $profileStates = @()
    try {
        Write-Host "        Fetching device configuration states..." -ForegroundColor Gray
        $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$intuneDeviceId/deviceConfigurationStates"
        $response = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop

        $allStates = @($response.value)
        while ($response.'@odata.nextLink') {
            $response = Invoke-MgGraphRequest -Uri $response.'@odata.nextLink' -Method GET -ErrorAction Stop
            $allStates += $response.value
        }

        Write-Verbose "Retrieved $($allStates.Count) configuration states."

        $profileStates = @(foreach ($state in $allStates) {
            # Map Graph state to our simplified states
            $normalizedState = switch ($state.state) {
                'compliant'       { 'applied' }
                'notApplicable'   { 'notApplicable' }
                'conflict'        { 'error' }
                'error'           { 'error' }
                'nonCompliant'    { 'error' }
                'notAssigned'     { 'notApplicable' }
                'remediated'      { 'applied' }
                'unknown'         { 'pending' }
                'pending'         { 'pending' }
                default           { 'unknown' }
            }

            [PSCustomObject]@{
                ProfileId        = $state.id
                ProfileName      = $state.displayName
                ProfileType      = 'DeviceConfiguration'
                State            = $normalizedState
                OriginalState    = $state.state
                Version          = $state.version
                LastReported     = $state.lastReportedDateTime
                PlatformType     = $state.platformType
                SettingCount     = $state.settingCount
            }
        })
    }
    catch {
        Write-Warning "Failed to retrieve device configuration states: $_"
    }

    # --- 5. Get compliance policy states ---
    $complianceStates = @()
    try {
        Write-Host "        Fetching compliance policy states..." -ForegroundColor Gray
        $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$intuneDeviceId/deviceCompliancePolicyStates"
        $response = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop

        $allComplianceStates = @($response.value)
        while ($response.'@odata.nextLink') {
            $response = Invoke-MgGraphRequest -Uri $response.'@odata.nextLink' -Method GET -ErrorAction Stop
            $allComplianceStates += $response.value
        }

        Write-Verbose "Retrieved $($allComplianceStates.Count) compliance policy states."

        $complianceStates = @(foreach ($state in $allComplianceStates) {
            # Map compliance state to our simplified states
            $normalizedState = switch ($state.state) {
                'compliant'       { 'applied' }
                'notApplicable'   { 'notApplicable' }
                'conflict'        { 'error' }
                'error'           { 'error' }
                'nonCompliant'    { 'error' }
                'notAssigned'     { 'notApplicable' }
                'unknown'         { 'pending' }
                'pending'         { 'pending' }
                default           { 'unknown' }
            }

            [PSCustomObject]@{
                PolicyId         = $state.id
                PolicyName       = $state.displayName
                PolicyType       = 'CompliancePolicy'
                State            = $normalizedState
                OriginalState    = $state.state
                Version          = $state.version
                LastReported     = $state.lastReportedDateTime
                PlatformType     = $state.platformType
                SettingCount     = $state.settingCount
            }
        })
    }
    catch {
        Write-Warning "Failed to retrieve compliance policy states: $_"
    }

    # --- 6. Disconnect (only if we connected) ---
    if (-not $GraphConnected) {
        try {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        }
        catch { }
    }

    [PSCustomObject]@{
        Available        = $true
        DeviceFound      = $true
        IntuneDeviceId   = $intuneDeviceId
        DeviceName       = $deviceName
        ProfileStates    = $profileStates
        ComplianceStates = $complianceStates
        CollectedAt      = Get-Date
    }
}
