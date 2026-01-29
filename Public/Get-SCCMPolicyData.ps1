function Get-SCCMPolicyData {
    <#
    .SYNOPSIS
        Collects SCCM/ConfigMgr client data from the local device.
    .DESCRIPTION
        Queries the ConfigMgr client WMI namespaces to retrieve information about
        SCCM-managed applications, compliance baselines, software updates, and client settings.
    .OUTPUTS
        PSCustomObject with SCCM client status, applications, baselines, and updates.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    Write-Verbose "Collecting SCCM/ConfigMgr client data..."

    # Check if SCCM client is installed
    $ccmNamespace = Get-CimInstance -Namespace 'root' -ClassName __Namespace -Filter "Name='ccm'" -ErrorAction SilentlyContinue

    if (-not $ccmNamespace) {
        Write-Verbose "SCCM client not installed (root\ccm namespace not found)"
        return [PSCustomObject]@{
            IsInstalled     = $false
            ClientInfo      = $null
            Applications    = @()
            Baselines       = @()
            Updates         = @()
            ClientSettings  = @()
            CollectedAt     = Get-Date
        }
    }

    # --- 1. Get Client Info ---
    $clientInfo = $null
    try {
        $client = Get-CimInstance -Namespace 'root\ccm' -ClassName SMS_Client -ErrorAction SilentlyContinue
        $clientVersion = (Get-CimInstance -Namespace 'root\ccm' -ClassName CCM_InstalledComponent -Filter "Name='CcmFramework'" -ErrorAction SilentlyContinue).Version

        # Get site info
        $siteInfo = Get-CimInstance -Namespace 'root\ccm' -ClassName SMS_Authority -ErrorAction SilentlyContinue | Select-Object -First 1

        # Get management point
        $mpInfo = Get-CimInstance -Namespace 'root\ccm' -ClassName SMS_LookupMP -ErrorAction SilentlyContinue | Select-Object -First 1

        $clientInfo = [PSCustomObject]@{
            ClientVersion    = $clientVersion
            SiteCode         = $siteInfo.Name -replace '^SMS:', ''
            ManagementPoint  = $mpInfo.Name
            ClientId         = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client' -Name 'SMS Unique Identifier' -ErrorAction SilentlyContinue).'SMS Unique Identifier'
        }

        Write-Verbose "SCCM Client version: $clientVersion"
    }
    catch {
        Write-Verbose "Could not retrieve SCCM client info: $_"
    }

    # --- 2. Get Deployed Applications ---
    $applications = @()
    try {
        $apps = Get-CimInstance -Namespace 'root\ccm\ClientSDK' -ClassName CCM_Application -ErrorAction SilentlyContinue

        $applications = @(foreach ($app in $apps) {
            # Get deployment info
            $installState = switch ($app.InstallState) {
                'Installed' { 'Installed' }
                'NotInstalled' { 'Not Installed' }
                'Unknown' { 'Unknown' }
                default { $app.InstallState }
            }

            $applicableState = switch ($app.ApplicabilityState) {
                'Applicable' { 'Applicable' }
                'NotApplicable' { 'Not Applicable' }
                default { $app.ApplicabilityState }
            }

            [PSCustomObject]@{
                Name              = $app.Name
                Publisher         = $app.Publisher
                Version           = $app.SoftwareVersion
                InstallState      = $installState
                ApplicabilityState = $applicableState
                EvaluationState   = $app.EvaluationState
                ResolvedState     = $app.ResolvedState
                IsRequired        = ($app.IsMachineTarget -or $app.EnforcePreference -eq 1)
                Deadline          = $app.Deadline
                LastEvalTime      = $app.LastEvalTime
            }
        })

        Write-Verbose "Found $($applications.Count) SCCM applications"
    }
    catch {
        Write-Verbose "Could not retrieve SCCM applications: $_"
    }

    # --- 3. Get Compliance Baselines ---
    $baselines = @()
    try {
        $dcmBaselines = Get-CimInstance -Namespace 'root\ccm\dcm' -ClassName SMS_DesiredConfiguration -ErrorAction SilentlyContinue

        $baselines = @(foreach ($baseline in $dcmBaselines) {
            $complianceState = switch ($baseline.LastComplianceStatus) {
                0 { 'Non-Compliant' }
                1 { 'Compliant' }
                2 { 'Not Applicable' }
                3 { 'Unknown' }
                4 { 'Error' }
                default { "Status: $($baseline.LastComplianceStatus)" }
            }

            [PSCustomObject]@{
                Name              = $baseline.DisplayName
                Version           = $baseline.Version
                ComplianceState   = $complianceState
                LastEvaluated     = $baseline.LastEvalTime
                IsMachineTarget   = $baseline.IsMachineTarget
            }
        })

        Write-Verbose "Found $($baselines.Count) compliance baselines"
    }
    catch {
        Write-Verbose "Could not retrieve compliance baselines: $_"
    }

    # --- 4. Get Software Updates ---
    $updates = @()
    try {
        # Get assigned updates
        $assignedUpdates = Get-CimInstance -Namespace 'root\ccm\ClientSDK' -ClassName CCM_SoftwareUpdate -ErrorAction SilentlyContinue

        $updates = @(foreach ($update in $assignedUpdates) {
            $evalState = switch ($update.EvaluationState) {
                0 { 'None' }
                1 { 'Available' }
                2 { 'Submitted' }
                3 { 'Detecting' }
                4 { 'PreDownload' }
                5 { 'Downloading' }
                6 { 'WaitInstall' }
                7 { 'Installing' }
                8 { 'PendingSoftReboot' }
                9 { 'PendingHardReboot' }
                10 { 'WaitReboot' }
                11 { 'Verifying' }
                12 { 'InstallComplete' }
                13 { 'Error' }
                14 { 'WaitServiceWindow' }
                15 { 'WaitUserLogon' }
                16 { 'WaitUserLogoff' }
                17 { 'WaitJobUserLogon' }
                18 { 'WaitUserReconnect' }
                19 { 'PendingUserLogoff' }
                20 { 'PendingUpdate' }
                21 { 'WaitingRetry' }
                22 { 'WaitPresModeOff' }
                23 { 'WaitForOrchestration' }
                default { "State: $($update.EvaluationState)" }
            }

            [PSCustomObject]@{
                ArticleID         = $update.ArticleID
                Name              = $update.Name
                BulletinID        = $update.BulletinID
                IsRequired        = ($update.ComplianceState -eq 0)
                EvaluationState   = $evalState
                PercentComplete   = $update.PercentComplete
                Deadline          = $update.Deadline
                Publisher         = $update.Publisher
            }
        })

        Write-Verbose "Found $($updates.Count) software updates"
    }
    catch {
        Write-Verbose "Could not retrieve software updates: $_"
    }

    # --- 5. Get Client Settings (Policy) ---
    $clientSettings = @()
    try {
        # Get key client policies that affect device management
        $policies = @(
            @{ Class = 'CCM_ClientAgentConfig'; Name = 'Client Agent' }
            @{ Class = 'CCM_SoftwareUpdatesClientConfig'; Name = 'Software Updates' }
            @{ Class = 'CCM_ApplicationManagementClientConfig'; Name = 'Application Management' }
            @{ Class = 'CCM_ComplianceEvaluationClientConfig'; Name = 'Compliance Settings' }
            @{ Class = 'CCM_HardwareInventoryClientConfig'; Name = 'Hardware Inventory' }
            @{ Class = 'CCM_SoftwareInventoryClientConfig'; Name = 'Software Inventory' }
            @{ Class = 'CCM_RemoteToolsConfig'; Name = 'Remote Tools' }
            @{ Class = 'CCM_EndpointProtectionClientConfig'; Name = 'Endpoint Protection' }
        )

        foreach ($policy in $policies) {
            try {
                $config = Get-CimInstance -Namespace 'root\ccm\Policy\Machine\ActualConfig' -ClassName $policy.Class -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($config) {
                    $settings = @{}
                    foreach ($prop in $config.CimInstanceProperties) {
                        if ($prop.Name -notmatch '^(CIM|__)|Reserved|SiteSettingsKey') {
                            $settings[$prop.Name] = $prop.Value
                        }
                    }

                    $clientSettings += [PSCustomObject]@{
                        Category = $policy.Name
                        Settings = $settings
                    }
                }
            }
            catch {
                Write-Verbose "Could not retrieve $($policy.Name) settings: $_"
            }
        }

        Write-Verbose "Collected $($clientSettings.Count) client setting categories"
    }
    catch {
        Write-Verbose "Could not retrieve client settings: $_"
    }

    [PSCustomObject]@{
        IsInstalled     = $true
        ClientInfo      = $clientInfo
        Applications    = $applications
        Baselines       = $baselines
        Updates         = $updates
        ClientSettings  = $clientSettings
        CollectedAt     = Get-Date
    }
}
