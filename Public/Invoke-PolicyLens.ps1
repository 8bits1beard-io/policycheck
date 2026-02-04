function Invoke-PolicyLens {
    <#
    .SYNOPSIS
        Runs a full policy scan on the local or remote device.
    .DESCRIPTION
        Orchestrates collection of Group Policy data, MDM/Intune policy data,
        SCCM/ConfigMgr data, and Microsoft Graph API data. Performs overlap analysis,
        verifies deployment status, and exports results to JSON for the web viewer tool.
        By default, queries Graph API for Intune profiles, apps, groups, and deployment
        verification. Use -SkipIntune or -SkipVerify to disable these features.
        When scanning remote machines, device data is collected via WinRM while
        Graph API calls run locally for simpler authentication.
    .PARAMETER ComputerName
        Name of a remote computer to scan via WinRM. If not specified, scans the local machine.
    .PARAMETER Credential
        PSCredential object for authenticating to the remote computer. If not specified,
        uses the current user's credentials.
    .PARAMETER SkipIntune
        Skip Microsoft Graph API queries for Intune profiles, apps, and group memberships.
        Use this for offline scans or when Graph authentication is not available.
    .PARAMETER SkipVerify
        Skip deployment verification that checks whether assigned policies are actually
        applied to the device. Verification is enabled by default.
    .PARAMETER SkipGPOVerify
        Skip GPO application verification that checks whether linked GPOs are actually
        applied to the device. Requires Active Directory access.
    .PARAMETER TenantId
        Azure AD tenant ID for Graph authentication.
    .PARAMETER SkipSCCM
        Skip SCCM/ConfigMgr client data collection via WMI.
    .PARAMETER SCCMSiteServer
        SCCM site server (SMS Provider) for deployment verification. Auto-discovered if not specified.
    .PARAMETER SCCMSiteCode
        SCCM site code for deployment verification. Auto-discovered if not specified.
    .PARAMETER SCCMCredential
        PSCredential for authenticating to the SCCM site server. Required for deployment verification
        when running from a machine that doesn't have direct access to the site server.
    .PARAMETER SkipSCCMVerify
        Skip SCCM deployment verification that compares assigned deployments against installed state.
        Client-side SCCM data is still collected unless -SkipSCCM is also specified.
    .PARAMETER SkipMDMDiag
        Skip running mdmdiagnosticstool (can be slow on some devices).
    .PARAMETER SuggestMappings
        Find Intune Settings Catalog matches for unmapped GPO settings.
    .PARAMETER OutputPath
        Path for the JSON export file. Defaults to a timestamped file in the current directory.
    .PARAMETER LogPath
        Path for the operational log file. Defaults to PolicyLens.log in LocalAppData.
    .EXAMPLE
        Invoke-PolicyLens
        Runs a full scan with Graph API and deployment verification (default).
    .EXAMPLE
        Invoke-PolicyLens -SkipIntune
        Runs a local-only scan without Graph API queries.
    .EXAMPLE
        Invoke-PolicyLens -SkipVerify
        Runs a scan with Graph API but skips deployment verification.
    .EXAMPLE
        Invoke-PolicyLens -ComputerName SERVER1
        Runs a remote scan on SERVER1 with Graph API queries.
    .EXAMPLE
        Invoke-PolicyLens -ComputerName SERVER1 -SkipIntune
        Runs a remote scan on SERVER1 without Graph API queries.
    .EXAMPLE
        Invoke-PolicyLens -OutputPath "C:\Reports\device1.json"
        Runs a full scan and exports results to a specific path.
    .OUTPUTS
        PSCustomObject with all collected data and analysis results.
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName,

        [PSCredential]$Credential,

        [switch]$SkipIntune,

        [switch]$SkipVerify,

        [switch]$SkipGPOVerify,

        [string]$TenantId,

        [switch]$SkipSCCM,

        [string]$SCCMSiteServer,

        [string]$SCCMSiteCode,

        [PSCredential]$SCCMCredential,

        [switch]$SkipSCCMVerify,

        [switch]$SkipMDMDiag,

        [switch]$SuggestMappings,

        [string]$OutputPath,

        [string]$LogPath = "$env:LOCALAPPDATA\PolicyLens\PolicyLens.log"
    )

    # Derive internal flags from skip parameters
    $IncludeGraph = -not $SkipIntune
    $VerifyDeployment = -not $SkipVerify -and -not $SkipIntune  # Verification requires Graph
    $VerifyGPO = -not $SkipGPOVerify
    $VerifySCCM = -not $SkipSCCMVerify -and -not $SkipSCCM  # SCCM verification requires client data

    # Validate parameters
    if ($SuggestMappings -and $SkipIntune) {
        Write-Error "-SuggestMappings requires Graph API. Remove -SkipIntune to use this feature."
        return
    }

    # Determine target name for output path default
    $targetName = if ($ComputerName) { $ComputerName } else { $env:COMPUTERNAME }
    if (-not $OutputPath) {
        $OutputPath = ".\PolicyLens_${targetName}_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    }

    # Set script-scoped log path for Write-PolicyLensLog
    $Script:LogPath = $LogPath

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    # Track if this is a remote scan
    $isRemoteScan = [bool]$ComputerName
    $deviceMetadata = $null
    $session = $null

    # Calculate total steps for progress tracking
    # Base: GPO, MDM, SCCM, Analysis = 4 steps (+ Graph if enabled)
    $totalSteps = if ($IncludeGraph) { 5 } else { 4 }
    if ($SkipSCCM) { $totalSteps-- }  # Remove SCCM step
    if ($SuggestMappings) { $totalSteps++ }  # Add mapping suggestions step
    if ($VerifyDeployment) { $totalSteps++ }  # Add deployment verification step
    if ($VerifyGPO) { $totalSteps++ }  # Add GPO verification step
    if ($VerifySCCM) { $totalSteps++ }  # Add SCCM verification step
    if ($isRemoteScan) {
        $totalSteps = if ($IncludeGraph) { 4 } else { 3 }
        if ($SkipSCCM) { $totalSteps-- }
        if ($SuggestMappings) { $totalSteps++ }
        if ($VerifyDeployment) { $totalSteps++ }
        if ($VerifyGPO) { $totalSteps++ }
        if ($VerifySCCM) { $totalSteps++ }
    }
    $currentStep = 0

    # --- Start logging ---
    Write-PolicyLensLog "========================================" -Level Info
    Write-PolicyLensLog "PolicyLens started (v1.3.0)" -Level Info
    $logParams = "SkipIntune=$SkipIntune, SkipVerify=$SkipVerify, SkipGPOVerify=$SkipGPOVerify, SkipSCCM=$SkipSCCM, SkipSCCMVerify=$SkipSCCMVerify, SkipMDMDiag=$SkipMDMDiag"
    if ($isRemoteScan) { $logParams += ", ComputerName=$ComputerName" }
    Write-PolicyLensLog "Parameters: $logParams" -Level Info

    Write-Host ""
    Write-Host "  ┌──────────────────────────────────────────┐" -ForegroundColor Cyan
    Write-Host "  │  " -ForegroundColor Cyan -NoNewline
    Write-Host "PolicyLens v1.3.0" -ForegroundColor White -NoNewline
    Write-Host "                       │" -ForegroundColor Cyan
    Write-Host "  │  " -ForegroundColor Cyan -NoNewline
    Write-Host "GPO • Intune • SCCM Policy Scanner" -ForegroundColor DarkCyan -NoNewline
    Write-Host "     │" -ForegroundColor Cyan
    Write-Host "  └──────────────────────────────────────────┘" -ForegroundColor Cyan
    Write-Host ""

    # --- Check for remote scan ---
    if ($isRemoteScan) {
        Write-Host "  ► " -ForegroundColor Yellow -NoNewline
        Write-Host "Remote scan target: " -ForegroundColor White -NoNewline
        Write-Host "$ComputerName" -ForegroundColor Cyan
        Write-Host ""
        Write-PolicyLensLog "Remote scan mode - target: $ComputerName" -Level Info
    }

    # --- Check elevation (local only) ---
    if (-not $isRemoteScan) {
        $isAdmin = ([Security.Principal.WindowsPrincipal]`
            [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

        if (-not $isAdmin) {
            Write-Host "  ⚠ " -ForegroundColor Yellow -NoNewline
            Write-Host "Running without Administrator privileges" -ForegroundColor Yellow
            Write-Host "    Some data may be incomplete. Run as Admin for full results." -ForegroundColor DarkYellow
            Write-Host ""
            Write-PolicyLensLog "Running without Administrator privileges" -Level Warning
        }
        else {
            Write-Host "  ✓ " -ForegroundColor Green -NoNewline
            Write-Host "Running as Administrator" -ForegroundColor Green
            Write-Host ""
            Write-PolicyLensLog "Running with Administrator privileges" -Level Info
        }
    }

    # ============================================================
    # REMOTE SCAN PATH
    # ============================================================
    if ($isRemoteScan) {
        # --- Graph Authentication (upfront if not skipped) ---
        $graphConnected = $false
        if ($IncludeGraph) {
            $graphModule = Get-Module -ListAvailable Microsoft.Graph.DeviceManagement -ErrorAction SilentlyContinue
            if (-not $graphModule) {
                Write-Host "  ⚠ " -ForegroundColor Yellow -NoNewline
                Write-Host "Microsoft.Graph module not installed" -ForegroundColor Yellow
                Write-Host "    Install: " -ForegroundColor DarkGray -NoNewline
                Write-Host "Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor DarkCyan
                Write-Host "    Continuing without Intune data..." -ForegroundColor DarkYellow
                Write-Host ""
                Write-PolicyLensLog "Graph module not installed - continuing without Intune data" -Level Warning
                $IncludeGraph = $false
            }
            else {
                Write-Host "  ► " -ForegroundColor Yellow -NoNewline
                Write-Host "Connecting to " -ForegroundColor White -NoNewline
                Write-Host "Microsoft Graph" -ForegroundColor Cyan -NoNewline
                Write-Host "..." -ForegroundColor White
                try {
                    $connectParams = @{
                        Scopes = @(
                            'DeviceManagementConfiguration.Read.All'
                            'DeviceManagementManagedDevices.Read.All'
                            'DeviceManagementApps.Read.All'
                            'Directory.Read.All'
                            'Device.Read.All'
                        )
                    }
                    if ($TenantId) { $connectParams['TenantId'] = $TenantId }

                    Connect-MgGraph @connectParams -ErrorAction Stop | Out-Null
                    $graphConnected = $true
                    Write-Host "  ✓ " -ForegroundColor Green -NoNewline
                    Write-Host "Connected to Graph API" -ForegroundColor Green
                    Write-Host ""
                    Write-PolicyLensLog "Graph: Connected successfully (upfront auth)" -Level Info
                }
                catch {
                    Write-Host "  ✗ " -ForegroundColor Red -NoNewline
                    Write-Host "Graph connection failed: $_" -ForegroundColor Red
                    Write-Host "    Continuing without Intune data..." -ForegroundColor DarkYellow
                    Write-Host ""
                    Write-PolicyLensLog "Graph: Connection failed - $_ (continuing without Intune data)" -Level Warning
                    $IncludeGraph = $false
                }
            }
        }

        try {
            # --- Connect to remote machine ---
            Write-Host "  ┌─" -ForegroundColor DarkGray -NoNewline
            Write-Host " REMOTE " -ForegroundColor Cyan -NoNewline
            Write-Host "──────────────────────────────────┐" -ForegroundColor DarkGray
            Write-Host "  │ " -ForegroundColor DarkGray -NoNewline
            Write-Host "► " -ForegroundColor Yellow -NoNewline
            Write-Host "Connecting to " -ForegroundColor White -NoNewline
            Write-Host "$ComputerName" -ForegroundColor Cyan -NoNewline
            Write-Host "..." -ForegroundColor White
            Write-PolicyLensLog "Remote: Connecting to $ComputerName" -Level Info

            $sessionParams = @{
                ComputerName = $ComputerName
                ErrorAction  = 'Stop'
            }
            if ($Credential) {
                $sessionParams['Credential'] = $Credential
            }

            try {
                $session = New-PSSession @sessionParams
                Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                Write-Host "✓ " -ForegroundColor Green -NoNewline
                Write-Host "Connected via WinRM" -ForegroundColor Green
                Write-PolicyLensLog "Remote: WinRM session established" -Level Info
            }
            catch {
                Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                Write-Host "✗ " -ForegroundColor Red -NoNewline
                Write-Host "Connection failed" -ForegroundColor Red
                Write-Host ""
                Write-Host "  Connection Error Details:" -ForegroundColor Red
                Write-Host "  $($_.Exception.Message)" -ForegroundColor DarkRed
                Write-Host ""
                Write-Host "  Prerequisites for remote scanning:" -ForegroundColor Yellow
                Write-Host "    1. WinRM must be enabled on $ComputerName" -ForegroundColor Gray
                Write-Host "       Run: Enable-PSRemoting -Force" -ForegroundColor DarkGray
                Write-Host "    2. The target must be reachable over the network" -ForegroundColor Gray
                Write-Host "    3. Firewall must allow WinRM (TCP 5985/5986)" -ForegroundColor Gray
                Write-Host "    4. User must have admin rights on the remote machine" -ForegroundColor Gray
                Write-Host ""
                Write-PolicyLensLog "Remote: Connection failed - $_" -Level Error
                throw "Failed to connect to $ComputerName. $_"
            }

            # --- Execute remote collection ---
            Write-Host "  │ " -ForegroundColor DarkGray -NoNewline
            Write-Host "► " -ForegroundColor Yellow -NoNewline
            Write-Host "Collecting policy data remotely..." -ForegroundColor White
            Write-PolicyLensLog "Remote: Starting data collection" -Level Info

            $remoteScriptBlock = Get-RemoteCollectionScriptBlock -SkipMDMDiag:$SkipMDMDiag
            $remoteResult = Invoke-Command -Session $session -ScriptBlock $remoteScriptBlock -ArgumentList $SkipMDMDiag.IsPresent

            if (-not $remoteResult) {
                throw "Remote collection returned no data"
            }

            # Report any errors/warnings from remote collection
            if ($remoteResult.Errors -and $remoteResult.Errors.Count -gt 0) {
                foreach ($err in $remoteResult.Errors) {
                    # Show RSOP/gpupdate warnings to user, log all
                    if ($err -match 'RSOP logging|gpupdate') {
                        Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                        Write-Host "⚠ " -ForegroundColor Yellow -NoNewline
                        Write-Host "$err" -ForegroundColor Yellow
                    }
                    Write-PolicyLensLog "Remote collection: $err" -Level Warning
                }
            }

            # Extract device metadata
            $deviceMetadata = $remoteResult.DeviceMetadata
            if (-not $deviceMetadata) {
                throw "Remote collection did not return device metadata"
            }

            Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
            Write-Host "✓ " -ForegroundColor Green -NoNewline
            Write-Host "Data collected from " -ForegroundColor Gray -NoNewline
            Write-Host "$($deviceMetadata.ComputerName)" -ForegroundColor Green
            Write-PolicyLensLog "Remote: Data collection complete" -Level Info

            # Convert remote hashtables to PSCustomObjects for consistency
            $gpoData = [PSCustomObject]$remoteResult.GPOData
            $mdmData = [PSCustomObject]$remoteResult.MDMData
            $sccmData = [PSCustomObject]$remoteResult.SCCMData

            # Display collection results
            $gpoCount = @($gpoData.RegistryPolicies).Count
            Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
            Write-Host "  GPO: " -ForegroundColor Gray -NoNewline
            Write-Host "$($gpoData.TotalGPOCount)" -ForegroundColor Cyan -NoNewline
            Write-Host " GPOs, " -ForegroundColor Gray -NoNewline
            Write-Host "$gpoCount" -ForegroundColor Cyan -NoNewline
            Write-Host " registry policies" -ForegroundColor Gray

            $intuneCount = $mdmData.IntunePolicyCount
            $totalCSP = @($mdmData.DevicePolicies).Count + @($mdmData.UserPolicies).Count
            Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
            Write-Host "  MDM: " -ForegroundColor Gray -NoNewline
            if ($mdmData.IsEnrolled) {
                Write-Host "Enrolled" -ForegroundColor Green -NoNewline
                Write-Host " • " -ForegroundColor Gray -NoNewline
                Write-Host "$intuneCount" -ForegroundColor Cyan -NoNewline
                Write-Host " Intune policies" -ForegroundColor Gray
            }
            else {
                Write-Host "Not enrolled" -ForegroundColor Yellow
            }

            Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
            Write-Host "  SCCM: " -ForegroundColor Gray -NoNewline
            if ($sccmData.IsInstalled) {
                $appCount = @($sccmData.Applications).Count
                $baselineCount = @($sccmData.Baselines).Count
                Write-Host "Installed" -ForegroundColor Green -NoNewline
                Write-Host " • " -ForegroundColor Gray -NoNewline
                Write-Host "$appCount" -ForegroundColor Cyan -NoNewline
                Write-Host " apps, " -ForegroundColor Gray -NoNewline
                Write-Host "$baselineCount" -ForegroundColor Cyan -NoNewline
                Write-Host " baselines" -ForegroundColor Gray
            }
            else {
                Write-Host "Not installed" -ForegroundColor DarkGray
            }

            Write-Host "  └────────────────────────────────────────────┘" -ForegroundColor DarkGray

        }
        finally {
            # Clean up session
            if ($session) {
                Remove-PSSession -Session $session -ErrorAction SilentlyContinue
                Write-PolicyLensLog "Remote: Session closed" -Level Info
            }
        }

        # --- Graph API calls (local, using remote device info) ---
        $graphData = $null
        $appData = $null
        $groupData = $null
        $deploymentStatus = $null

        if ($IncludeGraph -and $graphConnected) {
            Write-PolicyLensLog "Phase 4: Graph collection started (for remote device)" -Level Info
            Write-Host ""
            Write-Host "  ┌─" -ForegroundColor DarkGray -NoNewline
            Write-Host " GRAPH " -ForegroundColor Cyan -NoNewline
            Write-Host "───────────────────────────────────┐" -ForegroundColor DarkGray

            # Get policy data
            Write-Host "  │ " -ForegroundColor DarkGray -NoNewline
            Write-Host "► " -ForegroundColor Yellow -NoNewline
            Write-Host "Fetching Intune configuration profiles..." -ForegroundColor White
            $graphData = Get-GraphPolicyData -TenantId $TenantId -GraphConnected
            if ($graphData.Available) {
                $totalProfiles = $graphData.Profiles.Count + $graphData.CompliancePolicies.Count + $graphData.SettingsCatalog.Count
                Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                Write-Host "✓ " -ForegroundColor Green -NoNewline
                Write-Host "$totalProfiles" -ForegroundColor Green -NoNewline
                Write-Host " profiles/policies" -ForegroundColor Gray
                Write-PolicyLensLog "Phase 4: Intune profiles retrieved ($totalProfiles profiles)" -Level Info
            }

            # Get app assignments (skip local apps for remote scan)
            Write-Host "  │ " -ForegroundColor DarkGray -NoNewline
            Write-Host "► " -ForegroundColor Yellow -NoNewline
            Write-Host "Fetching " -ForegroundColor White -NoNewline
            Write-Host "Intune app assignments" -ForegroundColor Cyan -NoNewline
            Write-Host "..." -ForegroundColor White
            Write-PolicyLensLog "Phase 4: App assignments started" -Level Info
            $appData = Get-DeviceAppAssignments -GraphConnected -SkipLocalApps
            $appCount = $appData.Apps.Count
            $assignedCount = @($appData.AssignedApps).Count
            Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
            Write-Host "✓ " -ForegroundColor Green -NoNewline
            Write-Host "$appCount" -ForegroundColor Green -NoNewline
            Write-Host " apps (" -ForegroundColor Gray -NoNewline
            Write-Host "$assignedCount" -ForegroundColor Cyan -NoNewline
            Write-Host " assigned)" -ForegroundColor Gray
            Write-PolicyLensLog "Phase 4: App assignments complete ($appCount apps, $assignedCount assigned)" -Level Info

            # Get group memberships using remote device info
            Write-Host "  │ " -ForegroundColor DarkGray -NoNewline
            Write-Host "► " -ForegroundColor Yellow -NoNewline
            Write-Host "Fetching " -ForegroundColor White -NoNewline
            Write-Host "Azure AD group memberships" -ForegroundColor Cyan -NoNewline
            Write-Host "..." -ForegroundColor White
            Write-PolicyLensLog "Phase 4: Group memberships started (remote device: $($deviceMetadata.ComputerName))" -Level Info
            $groupData = Get-DeviceGroupMemberships -GraphConnected `
                -DeviceName $deviceMetadata.ComputerName `
                -DeviceId $deviceMetadata.AADDeviceId
            if ($groupData.DeviceFound) {
                $groupCount = $groupData.Groups.Count
                Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                Write-Host "✓ " -ForegroundColor Green -NoNewline
                Write-Host "Device found • Member of " -ForegroundColor Gray -NoNewline
                Write-Host "$groupCount" -ForegroundColor Green -NoNewline
                Write-Host " groups" -ForegroundColor Gray
                Write-PolicyLensLog "Phase 4: Group memberships complete ($groupCount groups)" -Level Info
            }
            else {
                Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                Write-Host "○ " -ForegroundColor Yellow -NoNewline
                Write-Host "Device not found in Azure AD" -ForegroundColor Yellow
                Write-PolicyLensLog "Phase 4: Device not found in Azure AD" -Level Warning
            }

            # --- Deployment Verification (Optional) ---
            if ($VerifyDeployment -and $groupData.DeviceFound -and $groupData.Device.DeviceId) {
                Write-Host "  │ " -ForegroundColor DarkGray -NoNewline
                Write-Host "► " -ForegroundColor Yellow -NoNewline
                Write-Host "Verifying " -ForegroundColor White -NoNewline
                Write-Host "deployment status" -ForegroundColor Cyan -NoNewline
                Write-Host "..." -ForegroundColor White
                Write-PolicyLensLog "Deployment Verification: Started (remote device)" -Level Info
                try {
                    $deploymentStatus = Get-DeviceDeploymentStatus -AzureADDeviceId $groupData.Device.DeviceId -GraphConnected
                    if ($deploymentStatus.DeviceFound) {
                        $profileCount = @($deploymentStatus.ProfileStates).Count
                        $complianceCount = @($deploymentStatus.ComplianceStates).Count
                        $appliedCount = @($deploymentStatus.ProfileStates | Where-Object { $_.State -eq 'applied' }).Count
                        Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                        Write-Host "✓ " -ForegroundColor Green -NoNewline
                        Write-Host "$profileCount" -ForegroundColor Green -NoNewline
                        Write-Host " profiles (" -ForegroundColor Gray -NoNewline
                        Write-Host "$appliedCount" -ForegroundColor Cyan -NoNewline
                        Write-Host " applied), " -ForegroundColor Gray -NoNewline
                        Write-Host "$complianceCount" -ForegroundColor Green -NoNewline
                        Write-Host " compliance policies" -ForegroundColor Gray
                        Write-PolicyLensLog "Deployment Verification: Complete ($profileCount profiles, $complianceCount compliance)" -Level Info
                    }
                    else {
                        Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                        Write-Host "○ " -ForegroundColor Yellow -NoNewline
                        Write-Host "Device not found in Intune" -ForegroundColor Yellow
                        Write-PolicyLensLog "Deployment Verification: Device not in Intune" -Level Warning
                    }
                }
                catch {
                    Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                    Write-Host "⚠ " -ForegroundColor Yellow -NoNewline
                    Write-Host "Could not verify deployment status" -ForegroundColor Yellow
                    Write-PolicyLensLog "Deployment Verification: Failed - $_" -Level Warning
                }
            }

            Write-Host "  └────────────────────────────────────────────┘" -ForegroundColor DarkGray
        }
        elseif (-not $IncludeGraph) {
            Write-Host ""
            Write-Host "  ┌─" -ForegroundColor DarkGray -NoNewline
            Write-Host " GRAPH " -ForegroundColor DarkGray -NoNewline
            Write-Host "───────────────────────────────────┐" -ForegroundColor DarkGray
            Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
            Write-Host "○ " -ForegroundColor DarkGray -NoNewline
            Write-Host "Graph API skipped " -ForegroundColor DarkGray -NoNewline
            Write-Host "(remove -SkipIntune to enable)" -ForegroundColor DarkCyan
            Write-Host "  └────────────────────────────────────────────┘" -ForegroundColor DarkGray
            Write-PolicyLensLog "Phase 4: Skipped (SkipIntune specified)" -Level Info
        }

        # --- GPO Verification (Remote Scan) ---
        # Note: This runs on the target machine via the remote session, which has AD access
        $gpoVerification = $null
        if ($VerifyGPO -and $gpoData.TotalGPOCount -gt 0) {
            Write-Host ""
            Write-Host "  ┌─" -ForegroundColor DarkGray -NoNewline
            Write-Host " GPO VERIFY " -ForegroundColor Blue -NoNewline
            Write-Host "───────────────────────────────┐" -ForegroundColor DarkGray
            Write-Host "  │ " -ForegroundColor DarkGray -NoNewline
            Write-Host "► " -ForegroundColor Yellow -NoNewline
            Write-Host "Verifying GPO application status via AD..." -ForegroundColor White
            Write-PolicyLensLog "GPO Verification: Started (remote)" -Level Info
            try {
                $allAppliedGPOs = @($gpoData.ComputerGPOs) + @($gpoData.UserGPOs)
                $gpoVerification = Get-GPOVerificationStatus -AppliedGPOs $allAppliedGPOs -ComputerName $deviceMetadata.ComputerName
                if ($gpoVerification.Available) {
                    $appliedCount = $gpoVerification.AppliedCount
                    $deniedCount = $gpoVerification.DeniedCount
                    $disabledCount = $gpoVerification.DisabledCount
                    Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                    Write-Host "✓ " -ForegroundColor Green -NoNewline
                    Write-Host "$appliedCount" -ForegroundColor Green -NoNewline
                    Write-Host " applied, " -ForegroundColor Gray -NoNewline
                    Write-Host "$deniedCount" -ForegroundColor Yellow -NoNewline
                    Write-Host " filtered, " -ForegroundColor Gray -NoNewline
                    Write-Host "$disabledCount" -ForegroundColor Cyan -NoNewline
                    Write-Host " disabled" -ForegroundColor Gray
                    Write-PolicyLensLog "GPO Verification: Complete ($appliedCount applied, $deniedCount filtered, $disabledCount disabled)" -Level Info
                }
                elseif ($gpoVerification.Message) {
                    Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                    Write-Host "○ " -ForegroundColor Yellow -NoNewline
                    Write-Host "$($gpoVerification.Message)" -ForegroundColor Yellow
                    Write-PolicyLensLog "GPO Verification: $($gpoVerification.Message)" -Level Warning
                }
            }
            catch {
                Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                Write-Host "⚠ " -ForegroundColor Yellow -NoNewline
                Write-Host "Could not verify GPO status" -ForegroundColor Yellow
                Write-PolicyLensLog "GPO Verification: Failed - $_" -Level Warning
            }
            Write-Host "  └────────────────────────────────────────────┘" -ForegroundColor DarkGray
        }

        # --- SCCM Verification (Remote Scan) ---
        $sccmVerification = $null
        if ($VerifySCCM -and $sccmData -and $sccmData.IsInstalled) {
            Write-Host ""
            Write-Host "  ┌─" -ForegroundColor DarkGray -NoNewline
            Write-Host " SCCM VERIFY " -ForegroundColor DarkYellow -NoNewline
            Write-Host "──────────────────────────────┐" -ForegroundColor DarkGray
            Write-Host "  │ " -ForegroundColor DarkGray -NoNewline
            Write-Host "► " -ForegroundColor Yellow -NoNewline
            Write-Host "Verifying SCCM deployment status..." -ForegroundColor White
            Write-PolicyLensLog "SCCM Verification: Started (remote)" -Level Info
            try {
                $sccmVerification = Get-SCCMVerificationStatus `
                    -SCCMData $sccmData `
                    -ComputerName $deviceMetadata.ComputerName `
                    -SiteServer $SCCMSiteServer `
                    -SiteCode $SCCMSiteCode `
                    -SiteCredential $SCCMCredential

                if ($sccmVerification.Available) {
                    $installedCount = $sccmVerification.InstalledCount
                    $pendingCount = $sccmVerification.PendingCount
                    $failedCount = $sccmVerification.FailedCount
                    $collectionCount = @($sccmVerification.CollectionMemberships).Count
                    Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                    Write-Host "✓ " -ForegroundColor Green -NoNewline
                    Write-Host "$collectionCount" -ForegroundColor Cyan -NoNewline
                    Write-Host " collections • " -ForegroundColor Gray -NoNewline
                    Write-Host "$installedCount" -ForegroundColor Green -NoNewline
                    Write-Host " installed, " -ForegroundColor Gray -NoNewline
                    Write-Host "$pendingCount" -ForegroundColor Yellow -NoNewline
                    Write-Host " pending, " -ForegroundColor Gray -NoNewline
                    Write-Host "$failedCount" -ForegroundColor Red -NoNewline
                    Write-Host " failed" -ForegroundColor Gray
                    Write-PolicyLensLog "SCCM Verification: Complete ($installedCount installed, $pendingCount pending, $failedCount failed)" -Level Info
                }
                elseif ($sccmVerification.Message) {
                    Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                    Write-Host "○ " -ForegroundColor Yellow -NoNewline
                    Write-Host "$($sccmVerification.Message)" -ForegroundColor Yellow
                    Write-PolicyLensLog "SCCM Verification: $($sccmVerification.Message)" -Level Warning
                }
            }
            catch {
                Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                Write-Host "⚠ " -ForegroundColor Yellow -NoNewline
                Write-Host "Could not verify SCCM status" -ForegroundColor Yellow
                Write-PolicyLensLog "SCCM Verification: Failed - $_" -Level Warning
            }
            Write-Host "  └────────────────────────────────────────────┘" -ForegroundColor DarkGray
        }

        # --- Analysis ---
        Write-Host ""
        Write-Host "  ┌─" -ForegroundColor DarkGray -NoNewline
        Write-Host " ANALYSIS " -ForegroundColor White -NoNewline
        Write-Host "────────────────────────────────┐" -ForegroundColor DarkGray
        Write-Host "  │ " -ForegroundColor DarkGray -NoNewline
        Write-Host "► " -ForegroundColor Yellow -NoNewline
        Write-Host "Analyzing policy overlap..." -ForegroundColor White
        Write-PolicyLensLog "Analysis: Started" -Level Info
        try {
            $analysis = Compare-PolicyOverlap -GPOData $gpoData -MDMData $mdmData -GraphData $graphData
            $summary = $analysis.Summary
            Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
            Write-Host "✓ " -ForegroundColor Green -NoNewline
            Write-Host "Analysis complete" -ForegroundColor Green
            Write-PolicyLensLog "Analysis: Complete (conflicts=$($summary.ValuesInConflict), migration-ready=$($summary.GPOOnlyWithMapping), unknown=$($summary.GPOOnlyNoMapping))" -Level Info
        }
        catch {
            Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
            Write-Host "✗ " -ForegroundColor Red -NoNewline
            Write-Host "Analysis failed" -ForegroundColor Red
            Write-PolicyLensLog "Analysis: Failed - $_" -Level Error
            throw
        }
        Write-Host "  └────────────────────────────────────────────┘" -ForegroundColor DarkGray

        # --- Mapping Suggestions (Optional) ---
        $mappingSuggestions = $null
        if ($SuggestMappings) {
            Write-Host ""
            $currentStep++
            Write-Host "  ┌─" -ForegroundColor DarkGray -NoNewline
            Write-Host " [Step $currentStep/$totalSteps] " -ForegroundColor White -NoNewline
            Write-Host "MAPPING SUGGESTIONS" -ForegroundColor Cyan -NoNewline
            Write-Host " ────────────┐" -ForegroundColor DarkGray
            Write-Host "  │ " -ForegroundColor DarkGray -NoNewline
            Write-Host "► " -ForegroundColor Yellow -NoNewline
            Write-Host "Finding Settings Catalog matches..." -ForegroundColor White
            Write-PolicyLensLog "Mapping Suggestions: Started (remote scan)" -Level Info

            try {
                $catalogSettings = Get-SettingsCatalogMappings -GraphConnected
                if ($catalogSettings) {
                    $mapPath = Join-Path $PSScriptRoot '..\Config\SettingsMap.psd1'
                    $existingMappings = @{}
                    if (Test-Path $mapPath) {
                        $existingMappings = Import-PowerShellDataFile $mapPath
                    }

                    $unmappedSettings = $analysis.DetailedResults | Where-Object { $_.Status -eq 'GPOOnly_NoMapping' }
                    Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                    Write-Host "Processing " -ForegroundColor Gray -NoNewline
                    Write-Host "$($unmappedSettings.Count)" -ForegroundColor Cyan -NoNewline
                    Write-Host " unmapped settings" -ForegroundColor Gray

                    $mappingSuggestions = @()
                    foreach ($gpoSetting in $unmappedSettings) {
                        $matches = Find-SettingsCatalogMatch -GPOSetting $gpoSetting -CatalogSettings $catalogSettings -ExistingMappings $existingMappings
                        if ($matches) {
                            $mappingSuggestions += [PSCustomObject]@{
                                GPOPath = $gpoSetting.GPOPath
                                GPOValueName = $gpoSetting.GPOValueName
                                GPOCategory = $gpoSetting.Category
                                Matches = $matches
                            }
                        }
                    }

                    $highCount = ($mappingSuggestions.Matches | Where-Object { $_.Confidence -eq 'High' }).Count
                    $medCount = ($mappingSuggestions.Matches | Where-Object { $_.Confidence -eq 'Medium' }).Count

                    Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                    Write-Host "✓ " -ForegroundColor Green -NoNewline
                    Write-Host "Suggestions: " -ForegroundColor Gray -NoNewline
                    Write-Host "$highCount" -ForegroundColor Green -NoNewline
                    Write-Host " high, " -ForegroundColor Gray -NoNewline
                    Write-Host "$medCount" -ForegroundColor Yellow -NoNewline
                    Write-Host " medium" -ForegroundColor Gray
                    Write-PolicyLensLog "Mapping Suggestions: Complete ($($mappingSuggestions.Count) with suggestions)" -Level Info
                }
            }
            catch {
                Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                Write-Host "✗ " -ForegroundColor Red -NoNewline
                Write-Host "Failed: $_" -ForegroundColor Red
                Write-PolicyLensLog "Mapping Suggestions: Failed - $_" -Level Error
            }
            Write-Host "  └────────────────────────────────────────────┘" -ForegroundColor DarkGray
        }

        # --- Output summary ---
        Write-ConsoleSummary -Analysis $analysis -GPOData $gpoData -MDMData $mdmData `
            -AppData $appData -GroupData $groupData

        # Return structured object for pipeline usage
        $result = [PSCustomObject]@{
            GPOData   = $gpoData
            MDMData   = $mdmData
            SCCMData  = $sccmData
            GraphData = $graphData
            AppData   = $appData
            GroupData = $groupData
            Analysis  = $analysis
            MappingSuggestions = $mappingSuggestions
            DeploymentStatus = $deploymentStatus
            GPOVerification = $gpoVerification
            SCCMVerification = $sccmVerification
        }

        # Export to JSON with device metadata from remote
        Write-PolicyLensLog "Export: Started" -Level Info
        try {
            $jsonExportPath = ConvertTo-JsonExport -Result $result -OutputPath $OutputPath -DeviceMetadata $deviceMetadata
            $result | Add-Member -NotePropertyName 'JsonPath' -NotePropertyValue $jsonExportPath
            Write-PolicyLensLog "Export: Complete ($jsonExportPath)" -Level Info
        }
        catch {
            Write-PolicyLensLog "Export: Failed - $_" -Level Error
            throw
        }

        $stopwatch.Stop()
        $duration = [math]::Round($stopwatch.Elapsed.TotalSeconds, 1)

        Write-Host ""
        Write-Host "  ┌──────────────────────────────────────────┐" -ForegroundColor Green
        Write-Host "  │  " -ForegroundColor Green -NoNewline
        Write-Host "✓ REMOTE SCAN COMPLETE" -ForegroundColor White -NoNewline
        Write-Host "                  │" -ForegroundColor Green
        Write-Host "  ├──────────────────────────────────────────┤" -ForegroundColor Green
        Write-Host "  │  " -ForegroundColor Green -NoNewline
        Write-Host "Target: " -ForegroundColor Gray -NoNewline
        Write-Host "$($deviceMetadata.ComputerName)" -ForegroundColor Cyan
        Write-Host "  │  " -ForegroundColor Green -NoNewline
        Write-Host "JSON saved to:" -ForegroundColor Gray
        Write-Host "  │  " -ForegroundColor Green -NoNewline
        Write-Host "$jsonExportPath" -ForegroundColor Cyan
        Write-Host "  ├──────────────────────────────────────────┤" -ForegroundColor Green
        Write-Host "  │  " -ForegroundColor Green -NoNewline
        Write-Host "Duration: " -ForegroundColor Gray -NoNewline
        Write-Host "${duration}s" -ForegroundColor White
        Write-Host "  │  " -ForegroundColor Green -NoNewline
        Write-Host "View results: Open JSON in PolicyLensViewer" -ForegroundColor Gray
        Write-Host "  └──────────────────────────────────────────┘" -ForegroundColor Green
        Write-Host ""

        Write-PolicyLensLog "PolicyLens finished (${duration}s) - Remote scan of $($deviceMetadata.ComputerName)" -Level Info

        # Disconnect from Graph if we connected
        if ($graphConnected) {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
            Write-PolicyLensLog "Graph: Disconnected" -Level Info
        }

        return $result
    }

    # ============================================================
    # LOCAL SCAN PATH (original behavior)
    # ============================================================

    $isAdmin = ([Security.Principal.WindowsPrincipal]`
        [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Write-Host "  ⚠ " -ForegroundColor Yellow -NoNewline
        Write-Host "Running without Administrator privileges" -ForegroundColor Yellow
        Write-Host "    Some data may be incomplete. Run as Admin for full results." -ForegroundColor DarkYellow
        Write-Host ""
        Write-PolicyLensLog "Running without Administrator privileges" -Level Warning
    }
    else {
        Write-Host "  ✓ " -ForegroundColor Green -NoNewline
        Write-Host "Running as Administrator" -ForegroundColor Green
        Write-Host ""
        Write-PolicyLensLog "Running with Administrator privileges" -Level Info
    }

    # --- Graph Authentication (upfront if not skipped) ---
    $graphConnected = $false
    if ($IncludeGraph) {
        $graphModule = Get-Module -ListAvailable Microsoft.Graph.DeviceManagement -ErrorAction SilentlyContinue
        if (-not $graphModule) {
            Write-Host "  ⚠ " -ForegroundColor Yellow -NoNewline
            Write-Host "Microsoft.Graph module not installed" -ForegroundColor Yellow
            Write-Host "    Install: " -ForegroundColor DarkGray -NoNewline
            Write-Host "Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor DarkCyan
            Write-Host "    Continuing without Intune data..." -ForegroundColor DarkYellow
            Write-Host ""
            Write-PolicyLensLog "Graph module not installed - continuing without Intune data" -Level Warning
            $IncludeGraph = $false
        }
        else {
            Write-Host "  ► " -ForegroundColor Yellow -NoNewline
            Write-Host "Connecting to " -ForegroundColor White -NoNewline
            Write-Host "Microsoft Graph" -ForegroundColor Cyan -NoNewline
            Write-Host "..." -ForegroundColor White
            try {
                $connectParams = @{
                    Scopes = @(
                        'DeviceManagementConfiguration.Read.All'
                        'DeviceManagementManagedDevices.Read.All'
                        'DeviceManagementApps.Read.All'
                        'Directory.Read.All'
                        'Device.Read.All'
                    )
                }
                if ($TenantId) { $connectParams['TenantId'] = $TenantId }

                Connect-MgGraph @connectParams -ErrorAction Stop | Out-Null
                $graphConnected = $true
                Write-Host "  ✓ " -ForegroundColor Green -NoNewline
                Write-Host "Connected to Graph API" -ForegroundColor Green
                Write-Host ""
                Write-PolicyLensLog "Graph: Connected successfully (upfront auth)" -Level Info
            }
            catch {
                Write-Host "  ✗ " -ForegroundColor Red -NoNewline
                Write-Host "Graph connection failed: $_" -ForegroundColor Red
                Write-Host "    Continuing without Intune data..." -ForegroundColor DarkYellow
                Write-Host ""
                Write-PolicyLensLog "Graph: Connection failed - $_ (continuing without Intune data)" -Level Warning
                $IncludeGraph = $false
            }
        }
    }

    # --- Phase 1: Collect GPO data ---
    $currentStep++
    Write-Host "  ┌─" -ForegroundColor DarkGray -NoNewline
    Write-Host " [Step $currentStep/$totalSteps] " -ForegroundColor White -NoNewline
    Write-Host "GROUP POLICY" -ForegroundColor Blue -NoNewline
    Write-Host " ─────────────────────┐" -ForegroundColor DarkGray
    Write-Host "  │ " -ForegroundColor DarkGray -NoNewline
    Write-Host "► " -ForegroundColor Yellow -NoNewline
    Write-Host "Running gpresult and scanning registry..." -ForegroundColor White
    Write-PolicyLensLog "Phase 1: GPO collection started" -Level Info
    try {
        $gpoData = Get-GPOPolicyData
        $gpoCount = $gpoData.RegistryPolicies.Count
        Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
        Write-Host "✓ " -ForegroundColor Green -NoNewline
        Write-Host "Collection complete: " -ForegroundColor Gray -NoNewline
        Write-Host "$($gpoData.TotalGPOCount)" -ForegroundColor Green -NoNewline
        Write-Host " GPOs applied, " -ForegroundColor Gray -NoNewline
        Write-Host "$gpoCount" -ForegroundColor Green -NoNewline
        Write-Host " registry settings found" -ForegroundColor Gray
        Write-PolicyLensLog "Phase 1: GPO collection complete ($($gpoData.TotalGPOCount) GPOs, $gpoCount registry policies)" -Level Info

        # Log if RSoP was temporarily enabled
        if ($gpoData.RSoPWasTemporarilyEnabled) {
            Write-PolicyLensLog "Phase 1: RSoP logging was temporarily enabled and has been restored to disabled" -Level Warning
        }
    }
    catch {
        Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
        Write-Host "✗ " -ForegroundColor Red -NoNewline
        Write-Host "Collection failed" -ForegroundColor Red
        Write-PolicyLensLog "Phase 1: GPO collection failed - $_" -Level Error
        throw
    }

    # --- GPO Verification (after GPO collection) ---
    $gpoVerification = $null
    if ($VerifyGPO -and $gpoData.TotalGPOCount -gt 0) {
        $currentStep++
        Write-Host "  ├─" -ForegroundColor DarkGray -NoNewline
        Write-Host " [Step $currentStep/$totalSteps] " -ForegroundColor White -NoNewline
        Write-Host "GPO VERIFICATION" -ForegroundColor Blue -NoNewline
        Write-Host " ──────────────────┤" -ForegroundColor DarkGray
        Write-Host "  │ " -ForegroundColor DarkGray -NoNewline
        Write-Host "► " -ForegroundColor Yellow -NoNewline
        Write-Host "Verifying GPO application status via Active Directory..." -ForegroundColor White
        Write-PolicyLensLog "GPO Verification: Started" -Level Info
        try {
            $allAppliedGPOs = @($gpoData.ComputerGPOs) + @($gpoData.UserGPOs)
            $gpoVerification = Get-GPOVerificationStatus -AppliedGPOs $allAppliedGPOs
            if ($gpoVerification.Available) {
                $appliedCount = $gpoVerification.AppliedCount
                $deniedCount = $gpoVerification.DeniedCount
                $disabledCount = $gpoVerification.DisabledCount
                Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                Write-Host "✓ " -ForegroundColor Green -NoNewline
                Write-Host "$appliedCount" -ForegroundColor Green -NoNewline
                Write-Host " applied, " -ForegroundColor Gray -NoNewline
                Write-Host "$deniedCount" -ForegroundColor Yellow -NoNewline
                Write-Host " filtered, " -ForegroundColor Gray -NoNewline
                Write-Host "$disabledCount" -ForegroundColor Cyan -NoNewline
                Write-Host " disabled" -ForegroundColor Gray
                Write-PolicyLensLog "GPO Verification: Complete ($appliedCount applied, $deniedCount filtered, $disabledCount disabled)" -Level Info
            }
            elseif ($gpoVerification.Message) {
                Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                Write-Host "○ " -ForegroundColor Yellow -NoNewline
                Write-Host "$($gpoVerification.Message)" -ForegroundColor Yellow
                Write-PolicyLensLog "GPO Verification: $($gpoVerification.Message)" -Level Warning
            }
            else {
                Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                Write-Host "○ " -ForegroundColor Yellow -NoNewline
                Write-Host "GPO verification not available" -ForegroundColor Yellow
                Write-PolicyLensLog "GPO Verification: Not available" -Level Warning
            }
        }
        catch {
            Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
            Write-Host "⚠ " -ForegroundColor Yellow -NoNewline
            Write-Host "Could not verify GPO status: $_" -ForegroundColor Yellow
            Write-PolicyLensLog "GPO Verification: Failed - $_" -Level Warning
        }
    }
    elseif (-not $VerifyGPO) {
        Write-Host "  ├─" -ForegroundColor DarkGray -NoNewline
        Write-Host " [Step -/$totalSteps] " -ForegroundColor DarkGray -NoNewline
        Write-Host "GPO VERIFICATION" -ForegroundColor DarkGray -NoNewline
        Write-Host " ──────────────────┤" -ForegroundColor DarkGray
        Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
        Write-Host "○ " -ForegroundColor DarkGray -NoNewline
        Write-Host "Skipped (use without -SkipGPOVerify to enable)" -ForegroundColor DarkGray
        Write-PolicyLensLog "GPO Verification: Skipped (SkipGPOVerify specified)" -Level Info
    }

    # --- Phase 2: Collect MDM data ---
    $currentStep++
    Write-Host "  ├─" -ForegroundColor DarkGray -NoNewline
    Write-Host " [Step $currentStep/$totalSteps] " -ForegroundColor White -NoNewline
    Write-Host "MDM / INTUNE" -ForegroundColor Magenta -NoNewline
    Write-Host " ────────────────────────┤" -ForegroundColor DarkGray
    Write-Host "  │ " -ForegroundColor DarkGray -NoNewline
    Write-Host "► " -ForegroundColor Yellow -NoNewline
    Write-Host "Reading MDM enrollment and PolicyManager registry..." -ForegroundColor White
    Write-PolicyLensLog "Phase 2: MDM collection started" -Level Info
    try {
        $mdmData = Get-MDMPolicyData -SkipMDMDiag:$SkipMDMDiag
        $intuneCount = $mdmData.IntunePolicyCount
        $totalCSP = $mdmData.TotalCSPValueCount
        if ($mdmData.IsEnrolled) {
            Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
            Write-Host "✓ " -ForegroundColor Green -NoNewline
            Write-Host "Device enrolled • " -ForegroundColor Green -NoNewline
            Write-Host "$intuneCount" -ForegroundColor Green -NoNewline
            Write-Host " Intune policies ($totalCSP total CSP values)" -ForegroundColor Gray
            Write-PolicyLensLog "Phase 2: MDM collection complete (enrolled, $intuneCount Intune policies)" -Level Info
        }
        else {
            Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
            Write-Host "○ " -ForegroundColor Yellow -NoNewline
            Write-Host "Device not MDM enrolled" -ForegroundColor Yellow
            Write-PolicyLensLog "Phase 2: MDM collection complete (not enrolled)" -Level Warning
        }
    }
    catch {
        Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
        Write-Host "✗ " -ForegroundColor Red -NoNewline
        Write-Host "Collection failed" -ForegroundColor Red
        Write-PolicyLensLog "Phase 2: MDM collection failed - $_" -Level Error
        throw
    }

    # --- Phase 3: Collect SCCM data ---
    $sccmData = $null
    if (-not $SkipSCCM) {
        $currentStep++
        Write-Host "  ├─" -ForegroundColor DarkGray -NoNewline
        Write-Host " [Step $currentStep/$totalSteps] " -ForegroundColor White -NoNewline
        Write-Host "SCCM / CONFIGMGR" -ForegroundColor DarkYellow -NoNewline
        Write-Host " ───────────────┤" -ForegroundColor DarkGray
        Write-Host "  │ " -ForegroundColor DarkGray -NoNewline
        Write-Host "► " -ForegroundColor Yellow -NoNewline
        Write-Host "Querying SCCM client via WMI..." -ForegroundColor White
        Write-PolicyLensLog "Phase 3: SCCM collection started" -Level Info
        try {
            $sccmData = Get-SCCMPolicyData
            if ($sccmData.IsInstalled) {
                $appCount = $sccmData.Applications.Count
                $baselineCount = $sccmData.Baselines.Count
                Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                Write-Host "✓ " -ForegroundColor Green -NoNewline
                Write-Host "Client installed • " -ForegroundColor Green -NoNewline
                Write-Host "$appCount" -ForegroundColor Green -NoNewline
                Write-Host " apps, " -ForegroundColor Gray -NoNewline
                Write-Host "$baselineCount" -ForegroundColor Green -NoNewline
                Write-Host " baselines retrieved" -ForegroundColor Gray
                Write-PolicyLensLog "Phase 3: SCCM collection complete ($appCount apps, $baselineCount baselines)" -Level Info
            }
            else {
                Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                Write-Host "○ " -ForegroundColor DarkGray -NoNewline
                Write-Host "SCCM client not installed" -ForegroundColor DarkGray
                Write-PolicyLensLog "Phase 3: SCCM client not installed" -Level Info
            }
        }
        catch {
            Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
            Write-Host "⚠ " -ForegroundColor Yellow -NoNewline
            Write-Host "Could not collect SCCM data" -ForegroundColor Yellow
            Write-PolicyLensLog "Phase 3: SCCM collection failed - $_" -Level Warning
        }
    }
    else {
        Write-Host "  ├─" -ForegroundColor DarkGray -NoNewline
        Write-Host " [Step -/$totalSteps] " -ForegroundColor DarkGray -NoNewline
        Write-Host "SCCM / CONFIGMGR" -ForegroundColor DarkGray -NoNewline
        Write-Host " ───────────────┤" -ForegroundColor DarkGray
        Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
        Write-Host "○ " -ForegroundColor DarkGray -NoNewline
        Write-Host "Skipped (use without -SkipSCCM to enable)" -ForegroundColor DarkGray
        Write-PolicyLensLog "Phase 3: Skipped (SkipSCCM specified)" -Level Info
    }

    # --- SCCM Deployment Verification (after SCCM collection) ---
    $sccmVerification = $null
    if ($VerifySCCM -and $sccmData -and $sccmData.IsInstalled) {
        $currentStep++
        Write-Host "  ├─" -ForegroundColor DarkGray -NoNewline
        Write-Host " [Step $currentStep/$totalSteps] " -ForegroundColor White -NoNewline
        Write-Host "SCCM VERIFICATION" -ForegroundColor DarkYellow -NoNewline
        Write-Host " ─────────────────┤" -ForegroundColor DarkGray
        Write-Host "  │ " -ForegroundColor DarkGray -NoNewline
        Write-Host "► " -ForegroundColor Yellow -NoNewline
        Write-Host "Verifying SCCM deployment status via site server..." -ForegroundColor White
        Write-PolicyLensLog "SCCM Verification: Started" -Level Info
        try {
            $sccmVerification = Get-SCCMVerificationStatus `
                -SCCMData $sccmData `
                -SiteServer $SCCMSiteServer `
                -SiteCode $SCCMSiteCode `
                -SiteCredential $SCCMCredential

            if ($sccmVerification.Available) {
                $installedCount = $sccmVerification.InstalledCount
                $pendingCount = $sccmVerification.PendingCount
                $failedCount = $sccmVerification.FailedCount
                $collectionCount = @($sccmVerification.CollectionMemberships).Count
                Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                Write-Host "✓ " -ForegroundColor Green -NoNewline
                Write-Host "$collectionCount" -ForegroundColor Cyan -NoNewline
                Write-Host " collections • " -ForegroundColor Gray -NoNewline
                Write-Host "$installedCount" -ForegroundColor Green -NoNewline
                Write-Host " installed, " -ForegroundColor Gray -NoNewline
                Write-Host "$pendingCount" -ForegroundColor Yellow -NoNewline
                Write-Host " pending, " -ForegroundColor Gray -NoNewline
                Write-Host "$failedCount" -ForegroundColor Red -NoNewline
                Write-Host " failed" -ForegroundColor Gray
                Write-PolicyLensLog "SCCM Verification: Complete ($installedCount installed, $pendingCount pending, $failedCount failed)" -Level Info
            }
            elseif ($sccmVerification.SiteServerReachable -and -not $sccmVerification.DeviceFound) {
                Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                Write-Host "○ " -ForegroundColor Yellow -NoNewline
                Write-Host "Device not found in SCCM database" -ForegroundColor Yellow
                Write-PolicyLensLog "SCCM Verification: Device not found in SCCM" -Level Warning
            }
            elseif ($sccmVerification.Message) {
                Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                Write-Host "○ " -ForegroundColor Yellow -NoNewline
                Write-Host "$($sccmVerification.Message)" -ForegroundColor Yellow
                Write-PolicyLensLog "SCCM Verification: $($sccmVerification.Message)" -Level Warning
            }
        }
        catch {
            Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
            Write-Host "⚠ " -ForegroundColor Yellow -NoNewline
            Write-Host "Could not verify SCCM deployment status: $_" -ForegroundColor Yellow
            Write-PolicyLensLog "SCCM Verification: Failed - $_" -Level Warning
        }
    }
    elseif (-not $VerifySCCM -and -not $SkipSCCM) {
        Write-Host "  ├─" -ForegroundColor DarkGray -NoNewline
        Write-Host " [Step -/$totalSteps] " -ForegroundColor DarkGray -NoNewline
        Write-Host "SCCM VERIFICATION" -ForegroundColor DarkGray -NoNewline
        Write-Host " ─────────────────┤" -ForegroundColor DarkGray
        Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
        Write-Host "○ " -ForegroundColor DarkGray -NoNewline
        Write-Host "Skipped (use -SCCMCredential to enable)" -ForegroundColor DarkGray
        Write-PolicyLensLog "SCCM Verification: Skipped (no credential provided)" -Level Info
    }

    # --- Phase 4: Optionally collect Graph data ---
    $graphData = $null
    $appData = $null
    $groupData = $null
    $deploymentStatus = $null

    if ($IncludeGraph -and $graphConnected) {
        Write-PolicyLensLog "Phase 4: Graph collection started" -Level Info
        $currentStep++
        Write-Host "  ├─" -ForegroundColor DarkGray -NoNewline
        Write-Host " [Step $currentStep/$totalSteps] " -ForegroundColor White -NoNewline
        Write-Host "MICROSOFT GRAPH API" -ForegroundColor Cyan -NoNewline
        Write-Host " ──────────────┤" -ForegroundColor DarkGray

        # Get policy data
        Write-Host "  │ " -ForegroundColor DarkGray -NoNewline
        Write-Host "► " -ForegroundColor Yellow -NoNewline
        Write-Host "Fetching Intune configuration profiles..." -ForegroundColor White
        $graphData = Get-GraphPolicyData -TenantId $TenantId -GraphConnected
        if ($graphData.Available) {
            $totalProfiles = $graphData.Profiles.Count + $graphData.CompliancePolicies.Count + $graphData.SettingsCatalog.Count
            Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
            Write-Host "✓ " -ForegroundColor Green -NoNewline
            Write-Host "$totalProfiles" -ForegroundColor Green -NoNewline
            Write-Host " profiles/policies" -ForegroundColor Gray
            Write-PolicyLensLog "Phase 4: Intune profiles retrieved ($totalProfiles profiles)" -Level Info
        }
        else {
            Write-PolicyLensLog "Phase 4: Intune profiles not available" -Level Warning
        }

        # Get app assignments
        Write-Host "  │ " -ForegroundColor DarkGray -NoNewline
        Write-Host "► " -ForegroundColor Yellow -NoNewline
        Write-Host "Fetching " -ForegroundColor White -NoNewline
        Write-Host "Intune app assignments" -ForegroundColor Cyan -NoNewline
        Write-Host "..." -ForegroundColor White
        Write-PolicyLensLog "Phase 4: App assignments started" -Level Info
        $appData = Get-DeviceAppAssignments -GraphConnected
        $appCount = $appData.Apps.Count
        $assignedCount = @($appData.AssignedApps).Count
        Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
        Write-Host "✓ " -ForegroundColor Green -NoNewline
        Write-Host "$appCount" -ForegroundColor Green -NoNewline
        Write-Host " apps (" -ForegroundColor Gray -NoNewline
        Write-Host "$assignedCount" -ForegroundColor Cyan -NoNewline
        Write-Host " assigned)" -ForegroundColor Gray
        Write-PolicyLensLog "Phase 4: App assignments complete ($appCount apps, $assignedCount assigned)" -Level Info

        # Get group memberships
        Write-Host "  │ " -ForegroundColor DarkGray -NoNewline
        Write-Host "► " -ForegroundColor Yellow -NoNewline
        Write-Host "Fetching " -ForegroundColor White -NoNewline
        Write-Host "Azure AD group memberships" -ForegroundColor Cyan -NoNewline
        Write-Host "..." -ForegroundColor White
        Write-PolicyLensLog "Phase 4: Group memberships started" -Level Info
        $groupData = Get-DeviceGroupMemberships -GraphConnected
        if ($groupData.DeviceFound) {
            $groupCount = $groupData.Groups.Count
            Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
            Write-Host "✓ " -ForegroundColor Green -NoNewline
            Write-Host "Device found • Member of " -ForegroundColor Gray -NoNewline
            Write-Host "$groupCount" -ForegroundColor Green -NoNewline
            Write-Host " groups" -ForegroundColor Gray
            Write-PolicyLensLog "Phase 4: Group memberships complete ($groupCount groups)" -Level Info
        }
        else {
            Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
            Write-Host "○ " -ForegroundColor Yellow -NoNewline
            Write-Host "Device not found in Azure AD" -ForegroundColor Yellow
            Write-PolicyLensLog "Phase 4: Device not found in Azure AD" -Level Warning
        }

        # --- Deployment Verification (Optional) ---
        if ($VerifyDeployment -and $groupData.DeviceFound -and $groupData.Device.DeviceId) {
            Write-Host "  │ " -ForegroundColor DarkGray -NoNewline
            Write-Host "► " -ForegroundColor Yellow -NoNewline
            Write-Host "Verifying " -ForegroundColor White -NoNewline
            Write-Host "deployment status" -ForegroundColor Cyan -NoNewline
            Write-Host "..." -ForegroundColor White
            Write-PolicyLensLog "Deployment Verification: Started" -Level Info
            try {
                $deploymentStatus = Get-DeviceDeploymentStatus -AzureADDeviceId $groupData.Device.DeviceId -GraphConnected
                if ($deploymentStatus.DeviceFound) {
                    $profileCount = @($deploymentStatus.ProfileStates).Count
                    $complianceCount = @($deploymentStatus.ComplianceStates).Count
                    $appliedCount = @($deploymentStatus.ProfileStates | Where-Object { $_.State -eq 'applied' }).Count
                    Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                    Write-Host "✓ " -ForegroundColor Green -NoNewline
                    Write-Host "$profileCount" -ForegroundColor Green -NoNewline
                    Write-Host " profiles (" -ForegroundColor Gray -NoNewline
                    Write-Host "$appliedCount" -ForegroundColor Cyan -NoNewline
                    Write-Host " applied), " -ForegroundColor Gray -NoNewline
                    Write-Host "$complianceCount" -ForegroundColor Green -NoNewline
                    Write-Host " compliance policies" -ForegroundColor Gray
                    Write-PolicyLensLog "Deployment Verification: Complete ($profileCount profiles, $complianceCount compliance)" -Level Info
                }
                else {
                    Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                    Write-Host "○ " -ForegroundColor Yellow -NoNewline
                    Write-Host "Device not found in Intune" -ForegroundColor Yellow
                    Write-PolicyLensLog "Deployment Verification: Device not in Intune" -Level Warning
                }
            }
            catch {
                Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                Write-Host "⚠ " -ForegroundColor Yellow -NoNewline
                Write-Host "Could not verify deployment status" -ForegroundColor Yellow
                Write-PolicyLensLog "Deployment Verification: Failed - $_" -Level Warning
            }
        }
    }
    elseif (-not $IncludeGraph) {
        Write-Host "  ├─" -ForegroundColor DarkGray -NoNewline
        Write-Host " [Step -/$totalSteps] " -ForegroundColor DarkGray -NoNewline
        Write-Host "MICROSOFT GRAPH API" -ForegroundColor DarkGray -NoNewline
        Write-Host " ──────────────┤" -ForegroundColor DarkGray
        Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
        Write-Host "○ " -ForegroundColor DarkGray -NoNewline
        Write-Host "Skipped (remove -SkipIntune to enable)" -ForegroundColor DarkGray
        Write-PolicyLensLog "Phase 4: Skipped (IncludeGraph not specified)" -Level Info
    }

    # --- Phase 5: Analyze overlap ---
    $currentStep++
    Write-Host "  ├─" -ForegroundColor DarkGray -NoNewline
    Write-Host " [Step $currentStep/$totalSteps] " -ForegroundColor White -NoNewline
    Write-Host "POLICY OVERLAP ANALYSIS" -ForegroundColor White -NoNewline
    Write-Host " ─────────┤" -ForegroundColor DarkGray
    Write-Host "  │ " -ForegroundColor DarkGray -NoNewline
    Write-Host "► " -ForegroundColor Yellow -NoNewline
    Write-Host "Cross-referencing GPO and MDM settings..." -ForegroundColor White
    Write-PolicyLensLog "Analysis: Started" -Level Info
    try {
        $analysis = Compare-PolicyOverlap -GPOData $gpoData -MDMData $mdmData -GraphData $graphData
        $summary = $analysis.Summary
        Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
        Write-Host "✓ " -ForegroundColor Green -NoNewline
        Write-Host "Analysis complete" -ForegroundColor Green
        Write-PolicyLensLog "Analysis: Complete (conflicts=$($summary.ValuesInConflict), migration-ready=$($summary.GPOOnlyWithMapping), unknown=$($summary.GPOOnlyNoMapping))" -Level Info
    }
    catch {
        Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
        Write-Host "✗ " -ForegroundColor Red -NoNewline
        Write-Host "Analysis failed" -ForegroundColor Red
        Write-PolicyLensLog "Analysis: Failed - $_" -Level Error
        throw
    }
    Write-Host "  └────────────────────────────────────────────┘" -ForegroundColor DarkGray

    # --- Phase 6 (Optional): Suggest mappings for unmapped GPO settings ---
    $mappingSuggestions = $null
    if ($SuggestMappings) {
        Write-Host ""
        $currentStep++
        Write-Host "  ┌─" -ForegroundColor DarkGray -NoNewline
        Write-Host " [Step $currentStep/$totalSteps] " -ForegroundColor White -NoNewline
        Write-Host "MAPPING SUGGESTIONS" -ForegroundColor Cyan -NoNewline
        Write-Host " ────────────┐" -ForegroundColor DarkGray
        Write-Host "  │ " -ForegroundColor DarkGray -NoNewline
        Write-Host "► " -ForegroundColor Yellow -NoNewline
        Write-Host "Finding Settings Catalog matches for unmapped GPO settings..." -ForegroundColor White
        Write-PolicyLensLog "Mapping Suggestions: Started" -Level Info

        try {
            # Get Settings Catalog definitions
            $catalogSettings = Get-SettingsCatalogMappings -GraphConnected

            if ($catalogSettings) {
                # Load existing mappings from SettingsMap.psd1
                $mapPath = Join-Path $PSScriptRoot '..\Config\SettingsMap.psd1'
                $existingMappings = @{}
                if (Test-Path $mapPath) {
                    $existingMappings = Import-PowerShellDataFile $mapPath
                }

                # Find unmapped GPO settings (Status = 'GPOOnly_NoMapping')
                $unmappedSettings = $analysis.DetailedResults | Where-Object { $_.Status -eq 'GPOOnly_NoMapping' }

                Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                Write-Host "Found " -ForegroundColor Gray -NoNewline
                Write-Host "$($unmappedSettings.Count)" -ForegroundColor Cyan -NoNewline
                Write-Host " unmapped GPO settings" -ForegroundColor Gray

                # Find matches for each unmapped setting
                $mappingSuggestions = @()
                $processed = 0
                foreach ($gpoSetting in $unmappedSettings) {
                    $processed++
                    if ($processed % 50 -eq 0) {
                        Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                        Write-Host "Processing: $processed / $($unmappedSettings.Count)" -ForegroundColor Gray
                    }

                    $matches = Find-SettingsCatalogMatch -GPOSetting $gpoSetting -CatalogSettings $catalogSettings -ExistingMappings $existingMappings

                    if ($matches) {
                        $mappingSuggestions += [PSCustomObject]@{
                            GPOPath = $gpoSetting.GPOPath
                            GPOValueName = $gpoSetting.GPOValueName
                            GPOCategory = $gpoSetting.Category
                            Matches = $matches
                        }
                    }
                }

                $highConfidenceCount = ($mappingSuggestions.Matches | Where-Object { $_.Confidence -eq 'High' }).Count
                $mediumConfidenceCount = ($mappingSuggestions.Matches | Where-Object { $_.Confidence -eq 'Medium' }).Count

                Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                Write-Host "✓ " -ForegroundColor Green -NoNewline
                Write-Host "Found suggestions: " -ForegroundColor Gray -NoNewline
                Write-Host "$highConfidenceCount" -ForegroundColor Green -NoNewline
                Write-Host " high, " -ForegroundColor Gray -NoNewline
                Write-Host "$mediumConfidenceCount" -ForegroundColor Yellow -NoNewline
                Write-Host " medium confidence" -ForegroundColor Gray
                Write-PolicyLensLog "Mapping Suggestions: Complete ($($mappingSuggestions.Count) settings with suggestions)" -Level Info
            }
            else {
                Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                Write-Host "✗ " -ForegroundColor Red -NoNewline
                Write-Host "Could not retrieve Settings Catalog" -ForegroundColor Red
                Write-PolicyLensLog "Mapping Suggestions: Failed to retrieve catalog" -Level Error
            }
        }
        catch {
            Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
            Write-Host "✗ " -ForegroundColor Red -NoNewline
            Write-Host "Mapping suggestions failed: $_" -ForegroundColor Red
            Write-PolicyLensLog "Mapping Suggestions: Failed - $_" -Level Error
        }
        Write-Host "  └────────────────────────────────────────────┘" -ForegroundColor DarkGray
    }

    # --- Output summary ---
    Write-ConsoleSummary -Analysis $analysis -GPOData $gpoData -MDMData $mdmData `
        -AppData $appData -GroupData $groupData

    # Return structured object for pipeline usage
    $result = [PSCustomObject]@{
        GPOData   = $gpoData
        MDMData   = $mdmData
        SCCMData  = $sccmData
        GraphData = $graphData
        AppData   = $appData
        GroupData = $groupData
        Analysis  = $analysis
        MappingSuggestions = $mappingSuggestions
        DeploymentStatus = $deploymentStatus
        GPOVerification = $gpoVerification
        SCCMVerification = $sccmVerification
    }

    # Export to JSON
    Write-PolicyLensLog "Export: Started" -Level Info
    try {
        $jsonExportPath = ConvertTo-JsonExport -Result $result -OutputPath $OutputPath
        $result | Add-Member -NotePropertyName 'JsonPath' -NotePropertyValue $jsonExportPath
        Write-PolicyLensLog "Export: Complete ($jsonExportPath)" -Level Info
    }
    catch {
        Write-PolicyLensLog "Export: Failed - $_" -Level Error
        throw
    }

    $stopwatch.Stop()
    $duration = [math]::Round($stopwatch.Elapsed.TotalSeconds, 1)

    Write-Host ""
    Write-Host "  ┌──────────────────────────────────────────┐" -ForegroundColor Green
    Write-Host "  │  " -ForegroundColor Green -NoNewline
    Write-Host "✓ SCAN COMPLETE" -ForegroundColor White -NoNewline
    Write-Host "                         │" -ForegroundColor Green
    Write-Host "  ├──────────────────────────────────────────┤" -ForegroundColor Green
    Write-Host "  │  " -ForegroundColor Green -NoNewline
    Write-Host "JSON saved to:" -ForegroundColor Gray
    Write-Host "  │  " -ForegroundColor Green -NoNewline
    Write-Host "$jsonExportPath" -ForegroundColor Cyan
    Write-Host "  ├──────────────────────────────────────────┤" -ForegroundColor Green
    Write-Host "  │  " -ForegroundColor Green -NoNewline
    Write-Host "Duration: " -ForegroundColor Gray -NoNewline
    Write-Host "${duration}s" -ForegroundColor White
    Write-Host "  │  " -ForegroundColor Green -NoNewline
    Write-Host "View results: Open JSON in PolicyLensViewer" -ForegroundColor Gray
    Write-Host "  └──────────────────────────────────────────┘" -ForegroundColor Green
    Write-Host ""

    Write-PolicyLensLog "PolicyLens finished (${duration}s)" -Level Info

    # Disconnect from Graph if we connected
    if ($graphConnected) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        Write-PolicyLensLog "Graph: Disconnected" -Level Info
    }

    return $result
}
