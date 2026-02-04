function Get-DeviceGroupMemberships {
    <#
    .SYNOPSIS
        Queries Microsoft Graph API for the device's Azure AD group memberships.
    .DESCRIPTION
        Looks up the current device in Azure AD and retrieves all group memberships.
        This helps identify which Intune policies and apps target this device.
        Requires an active Microsoft Graph connection.
    .PARAMETER GraphConnected
        Indicates Graph is already connected (called from Invoke-PolicyLens).
    .PARAMETER DeviceName
        The name of the device to look up in Azure AD. Defaults to the local computer name.
        Use this when scanning a remote device.
    .PARAMETER DeviceId
        The Azure AD device ID (GUID) for precise device lookup. When provided, skips
        local registry/dsregcmd lookup and uses this ID directly for Graph queries.
    .OUTPUTS
        PSCustomObject with device identity and group membership details.
    .AUTHOR
        Joshua Walderbach
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [switch]$GraphConnected,

        [string]$DeviceName,

        [string]$DeviceId
    )

    Write-Verbose "Querying Microsoft Graph for device group memberships..."

    if (-not $GraphConnected) {
        $context = Get-MgContext -ErrorAction SilentlyContinue
        if (-not $context) {
            Write-Warning "Not connected to Microsoft Graph. Call Connect-MgGraph first or use -IncludeGraph."
            return [PSCustomObject]@{
                Available   = $false
                DeviceFound = $false
                Device      = $null
                Groups      = @()
                CollectedAt = Get-Date
            }
        }
    }

    $deviceInfo = $null
    $groups = @()

    # --- 1. Find the device in Azure AD ---
    # Use provided parameters or fall back to local lookup
    $targetDeviceName = if ($DeviceName) { $DeviceName } else { $env:COMPUTERNAME }
    $aadDeviceId = $null

    # If DeviceId was provided, use it directly (remote scan scenario)
    if ($DeviceId) {
        $aadDeviceId = $DeviceId
        Write-Verbose "Using provided AAD Device ID: $aadDeviceId"
    }
    # Only do local lookup if no DeviceId provided AND we're looking up the local machine
    elseif (-not $DeviceName -or $DeviceName -eq $env:COMPUTERNAME) {
        # Check for AAD device ID in registry (most reliable)
        $aadRegPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo'
        if (Test-Path $aadRegPath) {
            $joinInfo = Get-ChildItem $aadRegPath -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($joinInfo) {
                $joinProps = Get-ItemProperty $joinInfo.PSPath -ErrorAction SilentlyContinue
                $aadDeviceId = $joinInfo.PSChildName
            }
        }

        # Also try dsregcmd output for device ID
        if (-not $aadDeviceId) {
            try {
                $dsreg = & dsregcmd /status 2>&1
                $deviceIdLine = $dsreg | Where-Object { $_ -match 'DeviceId\s*:\s*(.+)' }
                if ($deviceIdLine -and $Matches[1]) {
                    $aadDeviceId = $Matches[1].Trim()
                }
            }
            catch {
                Write-Verbose "dsregcmd not available: $_"
            }
        }
    }

    try {
        # Search by device name first (works across scenarios)
        $uri = "https://graph.microsoft.com/v1.0/devices?`$filter=displayName eq '$targetDeviceName'"
        $response = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop

        if ($response.value.Count -gt 0) {
            $device = $response.value[0]

            # If we have AAD device ID, try to match more precisely
            if ($aadDeviceId -and $response.value.Count -gt 1) {
                $match = $response.value | Where-Object { $_.deviceId -eq $aadDeviceId }
                if ($match) { $device = $match }
            }

            $deviceInfo = [PSCustomObject]@{
                ObjectId         = $device.id
                DeviceId         = $device.deviceId
                DisplayName      = $device.displayName
                OperatingSystem  = $device.operatingSystem
                OSVersion        = $device.operatingSystemVersion
                TrustType        = $device.trustType
                IsManaged        = $device.isManaged
                IsCompliant      = $device.isCompliant
                ManagementType   = $device.managementType
                EnrollmentType   = $device.enrollmentType
                RegisteredOwners = @()
            }

            # --- 2. Get group memberships ---
            $memberOfUri = "https://graph.microsoft.com/v1.0/devices/$($device.id)/memberOf?`$top=999"
            $memberResponse = Invoke-MgGraphRequest -Uri $memberOfUri -Method GET -ErrorAction Stop

            $allMembers = @($memberResponse.value)
            while ($memberResponse.'@odata.nextLink') {
                $memberResponse = Invoke-MgGraphRequest -Uri $memberResponse.'@odata.nextLink' -Method GET -ErrorAction Stop
                $allMembers += $memberResponse.value
            }

            $groups = @($allMembers |
                Where-Object { $_.'@odata.type' -eq '#microsoft.graph.group' } |
                ForEach-Object {
                    $membershipRule = $null
                    $groupType = 'Assigned'

                    if ($_.membershipRule) {
                        $membershipRule = $_.membershipRule
                        $groupType = 'Dynamic'
                    }

                    if ($_.groupTypes -contains 'DynamicMembership') {
                        $groupType = 'Dynamic'
                    }

                    [PSCustomObject]@{
                        ObjectId       = $_.id
                        DisplayName    = $_.displayName
                        Description    = $_.description
                        GroupType      = $groupType
                        MembershipRule = $membershipRule
                        MailEnabled    = $_.mailEnabled
                        SecurityEnabled = $_.securityEnabled
                        Mail           = $_.mail
                    }
                })

            Write-Verbose "Device '$targetDeviceName' found. Member of $($groups.Count) groups."

            # --- 3. Get registered owners ---
            try {
                $ownerUri = "https://graph.microsoft.com/v1.0/devices/$($device.id)/registeredOwners"
                $ownerResponse = Invoke-MgGraphRequest -Uri $ownerUri -Method GET -ErrorAction SilentlyContinue
                $deviceInfo.RegisteredOwners = @($ownerResponse.value | ForEach-Object {
                    [PSCustomObject]@{
                        DisplayName = $_.displayName
                        UPN         = $_.userPrincipalName
                    }
                })
            }
            catch {
                Write-Verbose "Could not retrieve registered owners: $_"
            }
        }
        else {
            Write-Warning "Device '$targetDeviceName' not found in Azure AD. The device may not be Azure AD joined/registered."
        }
    }
    catch {
        Write-Warning "Failed to query device information from Graph: $_"
    }

    [PSCustomObject]@{
        Available   = $true
        DeviceFound = ($null -ne $deviceInfo)
        Device      = $deviceInfo
        Groups      = $groups
        CollectedAt = Get-Date
    }
}
