function Get-SCCMVerificationStatus {
    <#
    .SYNOPSIS
        Verifies SCCM deployment status by comparing assigned deployments against installed state.
    .DESCRIPTION
        Queries the SCCM site server to enumerate collection memberships and deployments
        targeted at this device, then compares against client-side data to show verification
        status for each deployment (installed, pending, failed, etc.).
    .PARAMETER SCCMData
        The PSCustomObject from Get-SCCMPolicyData containing client-side SCCM data.
    .PARAMETER ComputerName
        The target computer name. Defaults to local computer.
    .PARAMETER SiteServer
        The SCCM site server (SMS Provider). Auto-discovered if not specified.
    .PARAMETER SiteCode
        The SCCM site code. Auto-discovered if not specified.
    .PARAMETER SiteCredential
        PSCredential for authenticating to the site server.
    .OUTPUTS
        PSCustomObject with verification states for all deployments.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$SCCMData,

        [string]$ComputerName = $env:COMPUTERNAME,

        [string]$SiteServer,
        [string]$SiteCode,
        [PSCredential]$SiteCredential
    )

    Write-Verbose "Starting SCCM deployment verification for $ComputerName..."

    # Initialize result object
    $result = [PSCustomObject]@{
        Available              = $false
        SiteServerReachable    = $false
        DeviceFound            = $false
        SiteServer             = $null
        SiteCode               = $null
        DeviceResourceId       = $null
        CollectionMemberships  = @()
        VerificationStates     = @()
        InstalledCount         = 0
        PendingCount           = 0
        FailedCount            = 0
        NotApplicableCount     = 0
        CollectedAt            = Get-Date
        Message                = $null
    }

    # Check if SCCM client data is available
    if (-not $SCCMData -or -not $SCCMData.IsInstalled) {
        $result.Message = "SCCM client not installed or data not available"
        return $result
    }

    # --- Establish connection to SMS Provider ---
    $connection = Get-SCCMSiteConnection -SiteServer $SiteServer -SiteCode $SiteCode -Credential $SiteCredential

    if (-not $connection.Connected) {
        $result.Message = $connection.Message
        return $result
    }

    $result.SiteServerReachable = $true
    $result.SiteServer = $connection.Server
    $result.SiteCode = $connection.SiteCode

    Write-Verbose "Connected to SMS Provider: $($connection.Server)"

    # --- Create CIM session for queries ---
    $cimSession = $null
    try {
        $sessionParams = @{
            ComputerName = $connection.Server
            ErrorAction  = 'Stop'
        }

        if ($SiteCredential) {
            $sessionParams['Credential'] = $SiteCredential
            try {
                $sessionOption = New-CimSessionOption -Protocol Dcom
                $cimSession = New-CimSession @sessionParams -SessionOption $sessionOption
            }
            catch {
                $cimSession = New-CimSession @sessionParams
            }
        }
        else {
            $cimSession = New-CimSession @sessionParams
        }
    }
    catch {
        $result.Message = "Could not establish CIM session to site server: $_"
        return $result
    }

    try {
        # --- Find device in SCCM ---
        Write-Verbose "Searching for device '$ComputerName' in SCCM..."

        $deviceQuery = "SELECT ResourceID, Name FROM SMS_R_System WHERE Name = '$ComputerName'"
        $device = Get-CimInstance -CimSession $cimSession -Namespace $connection.Namespace `
            -Query $deviceQuery -ErrorAction Stop | Select-Object -First 1

        if (-not $device) {
            $result.Message = "Device '$ComputerName' not found in SCCM database"
            return $result
        }

        $result.DeviceFound = $true
        $result.DeviceResourceId = $device.ResourceID
        Write-Verbose "Found device with ResourceID: $($device.ResourceID)"

        # --- Get collection memberships ---
        Write-Verbose "Querying collection memberships..."

        $membershipQuery = "SELECT CollectionID FROM SMS_FullCollectionMembership WHERE ResourceID = $($device.ResourceID)"
        $memberships = Get-CimInstance -CimSession $cimSession -Namespace $connection.Namespace `
            -Query $membershipQuery -ErrorAction Stop

        $collectionIds = @($memberships | ForEach-Object { $_.CollectionID })
        Write-Verbose "Device is a member of $($collectionIds.Count) collections"

        # Get collection details
        if ($collectionIds.Count -gt 0) {
            $collectionList = ($collectionIds | ForEach-Object { "'$_'" }) -join ','
            $collectionQuery = "SELECT CollectionID, Name FROM SMS_Collection WHERE CollectionID IN ($collectionList)"
            $collections = Get-CimInstance -CimSession $cimSession -Namespace $connection.Namespace `
                -Query $collectionQuery -ErrorAction Stop

            $result.CollectionMemberships = @($collections | ForEach-Object {
                [PSCustomObject]@{
                    CollectionID = $_.CollectionID
                    Name         = $_.Name
                }
            })
        }

        # --- Get deployments targeted at device's collections ---
        Write-Verbose "Querying deployments for device collections..."

        $verificationStates = @()

        if ($collectionIds.Count -gt 0) {
            # Query SMS_DeploymentInfo for all deployment types
            $deploymentQuery = "SELECT * FROM SMS_DeploymentInfo WHERE CollectionID IN ($collectionList)"
            $deployments = Get-CimInstance -CimSession $cimSession -Namespace $connection.Namespace `
                -Query $deploymentQuery -ErrorAction Stop

            Write-Verbose "Found $(@($deployments).Count) deployments targeted at device"

            foreach ($deployment in $deployments) {
                $verificationState = [PSCustomObject]@{
                    DeploymentName   = $deployment.TargetName
                    DeploymentType   = Get-SCCMDeploymentTypeName -TypeCode $deployment.DeploymentType
                    CollectionID     = $deployment.CollectionID
                    CollectionName   = $deployment.CollectionName
                    Intent           = if ($deployment.DeploymentIntent -eq 1) { 'Required' } else { 'Available' }
                    Deadline         = $null
                    Status           = 'unknown'
                    StatusLabel      = 'Unknown'
                    ClientState      = $null
                }

                # Match against client-side data based on deployment type
                switch ($deployment.DeploymentType) {
                    # Application (type 2)
                    2 {
                        $clientApp = $SCCMData.Applications | Where-Object {
                            $_.Name -eq $deployment.TargetName
                        } | Select-Object -First 1

                        if ($clientApp) {
                            $verificationState.ClientState = $clientApp.InstallState
                            $verificationState.Deadline = $clientApp.Deadline

                            switch ($clientApp.InstallState) {
                                'Installed' {
                                    $verificationState.Status = 'installed'
                                    $verificationState.StatusLabel = 'Installed'
                                }
                                'Not Installed' {
                                    if ($verificationState.Intent -eq 'Required') {
                                        $verificationState.Status = 'not-installed'
                                        $verificationState.StatusLabel = 'Not Installed'
                                    }
                                    else {
                                        $verificationState.Status = 'not-applicable'
                                        $verificationState.StatusLabel = 'Available (Not Installed)'
                                    }
                                }
                                'Unknown' {
                                    $verificationState.Status = 'pending'
                                    $verificationState.StatusLabel = 'Pending'
                                }
                                default {
                                    $verificationState.Status = 'unknown'
                                    $verificationState.StatusLabel = $clientApp.InstallState
                                }
                            }

                            # Check evaluation state for pending/failed
                            if ($clientApp.EvaluationState -and $clientApp.EvaluationState -ne 'None') {
                                if ($clientApp.EvaluationState -match 'Error|Fail') {
                                    $verificationState.Status = 'failed'
                                    $verificationState.StatusLabel = 'Failed'
                                }
                                elseif ($clientApp.EvaluationState -match 'Pending|Installing|Download') {
                                    $verificationState.Status = 'pending'
                                    $verificationState.StatusLabel = 'In Progress'
                                }
                            }
                        }
                        else {
                            # App not found on client - could be not applicable or not yet evaluated
                            $verificationState.Status = 'not-applicable'
                            $verificationState.StatusLabel = 'Not Applicable'
                        }
                    }

                    # Baseline (type 4)
                    4 {
                        $clientBaseline = $SCCMData.Baselines | Where-Object {
                            $_.Name -eq $deployment.TargetName
                        } | Select-Object -First 1

                        if ($clientBaseline) {
                            $verificationState.ClientState = $clientBaseline.ComplianceState

                            switch ($clientBaseline.ComplianceState) {
                                'Compliant' {
                                    $verificationState.Status = 'compliant'
                                    $verificationState.StatusLabel = 'Compliant'
                                }
                                'Non-Compliant' {
                                    $verificationState.Status = 'failed'
                                    $verificationState.StatusLabel = 'Non-Compliant'
                                }
                                'Error' {
                                    $verificationState.Status = 'failed'
                                    $verificationState.StatusLabel = 'Error'
                                }
                                'Not Applicable' {
                                    $verificationState.Status = 'not-applicable'
                                    $verificationState.StatusLabel = 'Not Applicable'
                                }
                                default {
                                    $verificationState.Status = 'unknown'
                                    $verificationState.StatusLabel = $clientBaseline.ComplianceState
                                }
                            }
                        }
                        else {
                            $verificationState.Status = 'not-applicable'
                            $verificationState.StatusLabel = 'Not Evaluated'
                        }
                    }

                    # Software Update (type 5)
                    5 {
                        # Software updates are harder to match - use update group name
                        # For now, mark as unknown unless we can find specific updates
                        $verificationState.Status = 'unknown'
                        $verificationState.StatusLabel = 'See Updates Tab'
                    }

                    # Task Sequence (type 1)
                    1 {
                        # Task sequences run once, so check if device has run it
                        $verificationState.Status = 'not-applicable'
                        $verificationState.StatusLabel = 'Task Sequence'
                    }

                    # Package (type 3)
                    3 {
                        $verificationState.Status = 'unknown'
                        $verificationState.StatusLabel = 'Package'
                    }

                    default {
                        $verificationState.Status = 'unknown'
                        $verificationState.StatusLabel = "Type $($deployment.DeploymentType)"
                    }
                }

                $verificationStates += $verificationState
            }
        }

        $result.VerificationStates = $verificationStates
        $result.Available = $true

        # Calculate summary counts
        $result.InstalledCount = @($verificationStates | Where-Object { $_.Status -in @('installed', 'compliant') }).Count
        $result.PendingCount = @($verificationStates | Where-Object { $_.Status -eq 'pending' }).Count
        $result.FailedCount = @($verificationStates | Where-Object { $_.Status -in @('failed', 'not-installed') }).Count
        $result.NotApplicableCount = @($verificationStates | Where-Object { $_.Status -eq 'not-applicable' }).Count

        Write-Verbose "Verification complete: $($result.InstalledCount) installed, $($result.PendingCount) pending, $($result.FailedCount) failed"
    }
    catch {
        $result.Message = "Error querying SCCM site server: $_"
        Write-Verbose "SCCM verification error: $_"
    }
    finally {
        if ($cimSession) {
            Remove-CimSession $cimSession -ErrorAction SilentlyContinue
        }
    }

    return $result
}

function Get-SCCMDeploymentTypeName {
    <#
    .SYNOPSIS
        Converts SCCM deployment type code to human-readable name.
    #>
    param([int]$TypeCode)

    switch ($TypeCode) {
        1 { 'TaskSequence' }
        2 { 'Application' }
        3 { 'Package' }
        4 { 'Baseline' }
        5 { 'Update' }
        6 { 'ConfigItem' }
        default { "Type$TypeCode" }
    }
}
