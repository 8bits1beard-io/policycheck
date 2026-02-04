function Get-RemoteCollectionScriptBlock {
    <#
    .SYNOPSIS
        Returns a self-contained script block for remote policy collection via WinRM.
    .DESCRIPTION
        This function returns a script block that can be executed on a remote machine
        via Invoke-Command. The script block contains all the logic needed to collect
        GPO, MDM, and SCCM data without requiring the PolicyLens module to be installed
        on the remote machine.
    .PARAMETER SkipMDMDiag
        When $true, the returned script block will skip running mdmdiagnosticstool.
    .OUTPUTS
        ScriptBlock - A self-contained script block for remote execution.
    #>
    [CmdletBinding()]
    [OutputType([ScriptBlock])]
    param(
        [switch]$SkipMDMDiag
    )

    $skipMDMDiagValue = $SkipMDMDiag.IsPresent

    return {
        param([bool]$SkipMDMDiag = $false)

        $result = @{
            DeviceMetadata = $null
            GPOData        = $null
            MDMData        = $null
            SCCMData       = $null
            CollectedAt    = Get-Date
            Errors         = @()
        }

        # ============================================================
        # DEVICE METADATA COLLECTION
        # ============================================================
        try {
            $computerName = $env:COMPUTERNAME

            # Get OS information
            $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
            $osVersion = if ($osInfo) { "$($osInfo.Caption) $($osInfo.Version)" } else { "Unknown" }
            $osBuild = if ($osInfo) { $osInfo.BuildNumber } else { "Unknown" }

            # Get domain join status
            $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
            $domainJoined = if ($computerSystem) { $computerSystem.PartOfDomain } else { $false }

            # Get Azure AD join status and device ID
            $azureADJoined = $false
            $hybridJoined = $false
            $aadDeviceId = $null

            $joinInfoPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
            if (Test-Path -Path $joinInfoPath) {
                $joinInfoKeys = Get-ChildItem -Path $joinInfoPath -ErrorAction SilentlyContinue
                if ($joinInfoKeys) {
                    $azureADJoined = $true
                    $hybridJoined = $domainJoined -and $azureADJoined
                    # The key name is the AAD device ID
                    $aadDeviceId = $joinInfoKeys[0].PSChildName
                }
            }

            # Also try dsregcmd for device ID if not found
            if (-not $aadDeviceId) {
                try {
                    $dsreg = & dsregcmd /status 2>&1
                    $deviceIdLine = $dsreg | Where-Object { $_ -match 'DeviceId\s*:\s*(.+)' }
                    if ($deviceIdLine -and $Matches[1]) {
                        $aadDeviceId = $Matches[1].Trim()
                    }
                }
                catch {
                    # dsregcmd not available
                }
            }

            $result.DeviceMetadata = @{
                ComputerName  = $computerName
                OSVersion     = $osVersion
                OSBuild       = $osBuild
                DomainJoined  = $domainJoined
                AzureADJoined = $azureADJoined
                HybridJoined  = $hybridJoined
                AADDeviceId   = $aadDeviceId
            }
        }
        catch {
            $result.Errors += "DeviceMetadata: $_"
        }

        # ============================================================
        # GPO DATA COLLECTION
        # ============================================================
        try {
            $computerGpos = @()
            $userGpos = @()
            $tempXml = Join-Path $env:TEMP "PolicyLens_gpresult_$(Get-Random).xml"

            # Check if RSOP logging is disabled and temporarily enable if needed
            $rsopPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
            $rsopWasDisabled = $false
            $rsopValueName = 'RSoPLogging'

            try {
                $rsopValue = Get-ItemProperty -Path $rsopPath -Name $rsopValueName -ErrorAction SilentlyContinue
                if ($null -ne $rsopValue -and $rsopValue.$rsopValueName -eq 0) {
                    $rsopWasDisabled = $true
                    # Note: Warning will be captured in result errors for remote display
                    $result.Errors += "RSOP logging was disabled by Group Policy. Temporarily enabled to collect GPO data."
                    Set-ItemProperty -Path $rsopPath -Name $rsopValueName -Value 1 -ErrorAction Stop

                    # Run gpupdate to populate RSOP cache
                    $result.Errors += "Running gpupdate /force to populate RSOP cache..."
                    $gpupdateProc = Start-Process -FilePath 'gpupdate.exe' -ArgumentList '/force' `
                        -NoNewWindow -Wait -PassThru -ErrorAction SilentlyContinue
                    if ($gpupdateProc.ExitCode -ne 0) {
                        $result.Errors += "gpupdate exited with code $($gpupdateProc.ExitCode)"
                    }
                }
            }
            catch {
                $result.Errors += "Could not enable RSOP logging: $_. GPO enumeration may be incomplete."
            }

            try {
                $proc = Start-Process -FilePath 'gpresult.exe' `
                    -ArgumentList "/x `"$tempXml`" /f /scope:computer" `
                    -NoNewWindow -Wait -PassThru -ErrorAction Stop

                if ($proc.ExitCode -eq 0 -and (Test-Path $tempXml)) {
                    $gpresultXml = [xml](Get-Content $tempXml -Raw)

                    # Parse computer GPOs
                    $compResults = $gpresultXml.Rsop.ComputerResults
                    if ($compResults) {
                        $computerGpos = @($compResults.GPO | Where-Object { $_ } | ForEach-Object {
                            @{
                                Name         = $_.Name
                                Guid         = if ($_.Path.Identifier) { $_.Path.Identifier.'#text' } else { '' }
                                LinkLocation = if ($_.Link.SOMPath) { $_.Link.SOMPath } else { '' }
                                LinkOrder    = if ($_.Link.SOMOrder) { [int]$_.Link.SOMOrder } else { 0 }
                                Scope        = 'Computer'
                                Enabled      = if ($null -ne $_.Enabled) { [bool]$_.Enabled } else { $true }
                                AccessDenied = if ($null -ne $_.AccessDenied) { [bool]$_.AccessDenied } else { $false }
                                SecurityFilter = if ($_.SecurityFilter) { $_.SecurityFilter } else { '' }
                            }
                        })
                    }

                    # Parse user GPOs
                    $userResults = $gpresultXml.Rsop.UserResults
                    if ($userResults) {
                        $userGpos = @($userResults.GPO | Where-Object { $_ } | ForEach-Object {
                            @{
                                Name         = $_.Name
                                Guid         = if ($_.Path.Identifier) { $_.Path.Identifier.'#text' } else { '' }
                                LinkLocation = if ($_.Link.SOMPath) { $_.Link.SOMPath } else { '' }
                                LinkOrder    = if ($_.Link.SOMOrder) { [int]$_.Link.SOMOrder } else { 0 }
                                Scope        = 'User'
                                Enabled      = if ($null -ne $_.Enabled) { [bool]$_.Enabled } else { $true }
                                AccessDenied = if ($null -ne $_.AccessDenied) { [bool]$_.AccessDenied } else { $false }
                                SecurityFilter = if ($_.SecurityFilter) { $_.SecurityFilter } else { '' }
                            }
                        })
                    }
                }
            }
            catch {
                # gpresult may fail on non-domain-joined devices
            }
            finally {
                # Restore RSOP logging to disabled if we enabled it
                if ($rsopWasDisabled) {
                    try {
                        Set-ItemProperty -Path $rsopPath -Name $rsopValueName -Value 0 -ErrorAction Stop
                        $result.Errors += "RSOP logging restored to disabled state (was temporarily enabled)"
                    }
                    catch {
                        $result.Errors += "Could not restore RSOP logging setting: $_"
                    }
                }

                if (Test-Path $tempXml -ErrorAction SilentlyContinue) {
                    Remove-Item $tempXml -Force -ErrorAction SilentlyContinue
                }
            }

            # Enumerate registry-based policies
            $categoryMap = @{
                'FVE'                  = 'BitLocker'
                'WindowsUpdate'        = 'Windows Update'
                'Windows Defender'     = 'Windows Defender'
                'Edge'                 = 'Microsoft Edge'
                'MicrosoftEdge'        = 'Microsoft Edge'
                'Internet Settings'    = 'Internet Explorer'
                'SystemCertificates'   = 'Certificates'
                'Terminal Services'    = 'Remote Desktop'
                'Safer'                = 'Software Restriction'
                'CodeIdentifiers'      = 'Software Restriction'
                'Netlogon'             = 'Network Authentication'
                'Windows Firewall'     = 'Firewall'
                'Lanman'               = 'File Sharing'
                'PassportForWork'      = 'Windows Hello'
                'DataCollection'       = 'Privacy'
                'DeliveryOptimization' = 'Delivery Optimization'
                'Power'                = 'Power'
                'AppLocker'            = 'AppLocker'
                'Biometrics'           = 'Biometrics'
                'CloudContent'         = 'Cloud Content'
                'CredentialProviders'  = 'Credential Providers'
                'DeviceGuard'          = 'Device Guard'
                'Lsa'                  = 'Security'
                'EventLog'             = 'Event Log'
                'WindowsInkWorkspace'  = 'Windows Ink'
                'DeviceInstall'        = 'Device Installation'
                'NetworkProvider'      = 'Network'
                'Sense'                = 'Defender ATP'
            }

            $registryPolicies = @()
            $registryPaths = @(
                @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft'; Scope = 'Computer' }
                @{ Path = 'HKCU:\SOFTWARE\Policies\Microsoft'; Scope = 'User' }
                @{ Path = 'HKLM:\SOFTWARE\Policies\Google'; Scope = 'Computer' }
                @{ Path = 'HKCU:\SOFTWARE\Policies\Google'; Scope = 'User' }
            )

            foreach ($regEntry in $registryPaths) {
                if (-not (Test-Path $regEntry.Path -ErrorAction SilentlyContinue)) {
                    continue
                }

                try {
                    $keys = Get-ChildItem $regEntry.Path -Recurse -ErrorAction SilentlyContinue

                    foreach ($key in $keys) {
                        $props = Get-ItemProperty $key.PSPath -ErrorAction SilentlyContinue
                        if (-not $props) { continue }

                        $props.PSObject.Properties | Where-Object {
                            $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Provider|Drive)$'
                        } | ForEach-Object {
                            $relativePath = $key.Name -replace '^HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\', '' `
                                                      -replace '^HKEY_CURRENT_USER\\SOFTWARE\\Policies\\', ''

                            # Determine category from path
                            $category = 'Other'
                            foreach ($pattern in $categoryMap.Keys) {
                                if ($relativePath -match [regex]::Escape($pattern)) {
                                    $category = $categoryMap[$pattern]
                                    break
                                }
                            }

                            $registryPolicies += @{
                                Path      = $relativePath
                                ValueName = $_.Name
                                Data      = $_.Value
                                DataType  = $_.TypeNameOfValue -replace 'System\.', ''
                                Scope     = $regEntry.Scope
                                Category  = $category
                                FullPath  = $key.Name
                            }
                        }
                    }
                }
                catch {
                    # Continue on registry errors
                }
            }

            $result.GPOData = @{
                ComputerGPOs     = $computerGpos
                UserGPOs         = $userGpos
                RegistryPolicies = $registryPolicies
                TotalGPOCount    = $computerGpos.Count + $userGpos.Count
                CollectedAt      = Get-Date
                ComputerName     = $env:COMPUTERNAME
            }
        }
        catch {
            $result.Errors += "GPOData: $_"
        }

        # ============================================================
        # MDM DATA COLLECTION
        # ============================================================
        try {
            # Check MDM enrollment status
            $enrollments = @()
            $enrollmentPath = 'HKLM:\SOFTWARE\Microsoft\Enrollments'

            if (Test-Path $enrollmentPath) {
                $enrollments = @(Get-ChildItem $enrollmentPath -ErrorAction SilentlyContinue |
                    Where-Object {
                        $provider = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).ProviderID
                        $provider -and $provider -ne ''
                    } |
                    ForEach-Object {
                        $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                        @{
                            EnrollmentId   = $_.PSChildName
                            ProviderId     = $props.ProviderID
                            UPN            = $props.UPN
                            AADTenantId    = $props.AADTenantID
                            EnrollmentType = $props.EnrollmentType
                            DeviceId       = $props.SID
                        }
                    })
            }

            $isEnrolled = $enrollments.Count -gt 0

            # Read applied MDM policies from PolicyManager
            $devicePolicies = @()
            $deviceBasePath = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device'

            if (Test-Path $deviceBasePath) {
                $areas = Get-ChildItem $deviceBasePath -ErrorAction SilentlyContinue
                foreach ($area in $areas) {
                    try {
                        $props = Get-ItemProperty $area.PSPath -ErrorAction SilentlyContinue
                        if (-not $props) { continue }

                        $props.PSObject.Properties |
                            Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Provider|Drive)$' } |
                            ForEach-Object {
                                $devicePolicies += @{
                                    Area    = $area.PSChildName
                                    Setting = $_.Name
                                    Value   = $_.Value
                                    Scope   = 'Device'
                                    Source  = 'PolicyManager'
                                }
                            }
                    }
                    catch {
                        # Continue on errors
                    }
                }
            }

            $userPolicies = @()
            $userBasePath = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\user'

            if (Test-Path $userBasePath) {
                $userSubPaths = Get-ChildItem $userBasePath -ErrorAction SilentlyContinue
                foreach ($userSub in $userSubPaths) {
                    $userAreas = Get-ChildItem $userSub.PSPath -ErrorAction SilentlyContinue
                    foreach ($area in $userAreas) {
                        try {
                            $props = Get-ItemProperty $area.PSPath -ErrorAction SilentlyContinue
                            if (-not $props) { continue }

                            $props.PSObject.Properties |
                                Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Provider|Drive)$' } |
                                ForEach-Object {
                                    $userPolicies += @{
                                        Area    = $area.PSChildName
                                        Setting = $_.Name
                                        Value   = $_.Value
                                        Scope   = 'User'
                                        Source  = 'PolicyManager'
                                    }
                                }
                        }
                        catch {
                            # Continue on errors
                        }
                    }
                }
            }

            # Check PolicyManager providers for source info
            $policyProviders = @()
            $providerPath = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\providers'

            if (Test-Path $providerPath) {
                $providers = Get-ChildItem $providerPath -ErrorAction SilentlyContinue
                foreach ($provider in $providers) {
                    $providerName = $provider.PSChildName
                    $defaultPath = Join-Path $provider.PSPath 'default'
                    if (Test-Path $defaultPath) {
                        $providerAreas = Get-ChildItem $defaultPath -ErrorAction SilentlyContinue
                        foreach ($pa in $providerAreas) {
                            try {
                                $props = Get-ItemProperty $pa.PSPath -ErrorAction SilentlyContinue
                                if (-not $props) { continue }

                                $props.PSObject.Properties |
                                    Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Provider|Drive)$' } |
                                    ForEach-Object {
                                        $policyProviders += @{
                                            ProviderId = $providerName
                                            Area       = $pa.PSChildName
                                            Setting    = $_.Name
                                            Value      = $_.Value
                                        }
                                    }
                            }
                            catch {
                                # Continue on errors
                            }
                        }
                    }
                }
            }

            # Run mdmdiagnosticstool (optional)
            $diagPath = $null

            if (-not $SkipMDMDiag -and $isEnrolled) {
                $diagFolder = Join-Path $env:TEMP "PolicyLens_MDMDiag_$(Get-Random)"
                try {
                    New-Item -Path $diagFolder -ItemType Directory -Force | Out-Null
                    $diagCab = Join-Path $diagFolder 'mdmdiag.cab'

                    $proc = Start-Process -FilePath 'mdmdiagnosticstool.exe' `
                        -ArgumentList "-area DeviceEnrollment;DeviceProvisioning;Autopilot -cab `"$diagCab`"" `
                        -NoNewWindow -Wait -PassThru -ErrorAction SilentlyContinue

                    if ($proc.ExitCode -eq 0 -and (Test-Path $diagCab)) {
                        $extractPath = Join-Path $diagFolder 'extracted'
                        New-Item -Path $extractPath -ItemType Directory -Force | Out-Null
                        & expand.exe $diagCab -F:* $extractPath | Out-Null
                        $diagPath = $extractPath
                    }
                }
                catch {
                    # Continue without diagnostics
                }
            }

            $result.MDMData = @{
                IsEnrolled      = $isEnrolled
                Enrollments     = $enrollments
                DevicePolicies  = $devicePolicies
                UserPolicies    = $userPolicies
                PolicyProviders = $policyProviders
                DiagnosticsPath = $diagPath
                CollectedAt     = Get-Date
            }
        }
        catch {
            $result.Errors += "MDMData: $_"
        }

        # ============================================================
        # SCCM DATA COLLECTION
        # ============================================================
        try {
            # Check if SCCM client is installed
            $ccmNamespace = Get-CimInstance -Namespace 'root' -ClassName __Namespace -Filter "Name='ccm'" -ErrorAction SilentlyContinue

            if (-not $ccmNamespace) {
                $result.SCCMData = @{
                    IsInstalled     = $false
                    ClientInfo      = $null
                    Applications    = @()
                    Baselines       = @()
                    Updates         = @()
                    ClientSettings  = @()
                    CollectedAt     = Get-Date
                }
            }
            else {
                # Get Client Info
                $clientInfo = $null
                try {
                    $clientVersion = (Get-CimInstance -Namespace 'root\ccm' -ClassName CCM_InstalledComponent -Filter "Name='CcmFramework'" -ErrorAction SilentlyContinue).Version
                    $siteInfo = Get-CimInstance -Namespace 'root\ccm' -ClassName SMS_Authority -ErrorAction SilentlyContinue | Select-Object -First 1
                    $mpInfo = Get-CimInstance -Namespace 'root\ccm' -ClassName SMS_LookupMP -ErrorAction SilentlyContinue | Select-Object -First 1

                    $clientInfo = @{
                        ClientVersion    = $clientVersion
                        SiteCode         = $siteInfo.Name -replace '^SMS:', ''
                        ManagementPoint  = $mpInfo.Name
                        ClientId         = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client' -Name 'SMS Unique Identifier' -ErrorAction SilentlyContinue).'SMS Unique Identifier'
                    }
                }
                catch {
                    # Continue without client info
                }

                # Get Deployed Applications
                $applications = @()
                try {
                    $apps = Get-CimInstance -Namespace 'root\ccm\ClientSDK' -ClassName CCM_Application -ErrorAction SilentlyContinue

                    $applications = @(foreach ($app in $apps) {
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

                        @{
                            Name               = $app.Name
                            Publisher          = $app.Publisher
                            Version            = $app.SoftwareVersion
                            InstallState       = $installState
                            ApplicabilityState = $applicableState
                            EvaluationState    = $app.EvaluationState
                            ResolvedState      = $app.ResolvedState
                            IsRequired         = ($app.IsMachineTarget -or $app.EnforcePreference -eq 1)
                            Deadline           = $app.Deadline
                            LastEvalTime       = $app.LastEvalTime
                        }
                    })
                }
                catch {
                    # Continue without applications
                }

                # Get Compliance Baselines
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

                        @{
                            Name              = $baseline.DisplayName
                            Version           = $baseline.Version
                            ComplianceState   = $complianceState
                            LastEvaluated     = $baseline.LastEvalTime
                            IsMachineTarget   = $baseline.IsMachineTarget
                        }
                    })
                }
                catch {
                    # Continue without baselines
                }

                # Get Software Updates
                $updates = @()
                try {
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

                        @{
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
                }
                catch {
                    # Continue without updates
                }

                # Get Client Settings (Policy)
                $clientSettings = @()
                try {
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

                                $clientSettings += @{
                                    Category = $policy.Name
                                    Settings = $settings
                                }
                            }
                        }
                        catch {
                            # Continue without this policy
                        }
                    }
                }
                catch {
                    # Continue without client settings
                }

                $result.SCCMData = @{
                    IsInstalled     = $true
                    ClientInfo      = $clientInfo
                    Applications    = $applications
                    Baselines       = $baselines
                    Updates         = $updates
                    ClientSettings  = $clientSettings
                    CollectedAt     = Get-Date
                }
            }
        }
        catch {
            $result.Errors += "SCCMData: $_"
        }

        return $result
    }.GetNewClosure()
}
