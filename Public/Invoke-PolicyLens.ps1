function Invoke-PolicyLens {
    <#
    .SYNOPSIS
        Runs a full policy scan on the local or remote device.
    .DESCRIPTION
        Orchestrates collection of Group Policy data, MDM/Intune policy data,
        SCCM/ConfigMgr data, and optionally Microsoft Graph API data. Performs
        overlap analysis and exports results to JSON for the web viewer tool.
        When scanning remote machines, device data is collected via WinRM while
        Graph API calls run locally for simpler authentication.
    .PARAMETER ComputerName
        Name of a remote computer to scan via WinRM. If not specified, scans the local machine.
    .PARAMETER Credential
        PSCredential object for authenticating to the remote computer. If not specified,
        uses the current user's credentials.
    .PARAMETER IncludeGraph
        Connect to Microsoft Graph API to retrieve Intune profile metadata,
        app assignments, and Azure AD group memberships.
    .PARAMETER TenantId
        Azure AD tenant ID for Graph authentication.
    .PARAMETER SkipMDMDiag
        Skip running mdmdiagnosticstool (can be slow on some devices).
    .PARAMETER OutputPath
        Path for the JSON export file. Defaults to a timestamped file in the current directory.
    .PARAMETER LogPath
        Path for the operational log file. Defaults to PolicyLens.log in LocalAppData.
    .EXAMPLE
        Invoke-PolicyLens
        Runs a local-only scan and exports results to JSON.
    .EXAMPLE
        Invoke-PolicyLens -ComputerName SERVER1
        Runs a remote scan on SERVER1 using current credentials.
    .EXAMPLE
        Invoke-PolicyLens -ComputerName SERVER1 -Credential (Get-Credential)
        Runs a remote scan on SERVER1 with explicit credentials.
    .EXAMPLE
        Invoke-PolicyLens -ComputerName SERVER1 -IncludeGraph
        Runs a remote scan with Graph API queries (auth happens locally).
    .EXAMPLE
        Invoke-PolicyLens -IncludeGraph -TenantId "contoso.onmicrosoft.com"
        Runs a full scan including Graph API queries for Intune metadata.
    .EXAMPLE
        Invoke-PolicyLens -OutputPath "C:\Reports\device1.json"
        Runs a local scan and exports results to a specific path.
    .OUTPUTS
        PSCustomObject with all collected data and analysis results.
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName,

        [PSCredential]$Credential,

        [switch]$IncludeGraph,

        [string]$TenantId,

        [switch]$SkipMDMDiag,

        [string]$OutputPath,

        [string]$LogPath = "$env:LOCALAPPDATA\PolicyLens\PolicyLens.log"
    )

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

    # --- Start logging ---
    Write-PolicyLensLog "========================================" -Level Info
    Write-PolicyLensLog "PolicyLens started (v1.0.0)" -Level Info
    $logParams = "IncludeGraph=$IncludeGraph, SkipMDMDiag=$SkipMDMDiag"
    if ($isRemoteScan) { $logParams += ", ComputerName=$ComputerName" }
    Write-PolicyLensLog "Parameters: $logParams" -Level Info

    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║  " -ForegroundColor Cyan -NoNewline
    Write-Host "PolicyLens v1.0.0" -ForegroundColor White -NoNewline
    Write-Host "                       ║" -ForegroundColor Cyan
    Write-Host "  ║  " -ForegroundColor Cyan -NoNewline
    Write-Host "GPO • Intune • SCCM Policy Scanner" -ForegroundColor DarkCyan -NoNewline
    Write-Host "     ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════╝" -ForegroundColor Cyan
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

            $mdmTotal = @($mdmData.DevicePolicies).Count + @($mdmData.UserPolicies).Count
            Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
            Write-Host "  MDM: " -ForegroundColor Gray -NoNewline
            if ($mdmData.IsEnrolled) {
                Write-Host "Enrolled" -ForegroundColor Green -NoNewline
                Write-Host " • " -ForegroundColor Gray -NoNewline
                Write-Host "$mdmTotal" -ForegroundColor Cyan -NoNewline
                Write-Host " policies" -ForegroundColor Gray
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

        if ($IncludeGraph) {
            Write-PolicyLensLog "Phase 4: Graph collection started (for remote device)" -Level Info
            $graphModule = Get-Module -ListAvailable Microsoft.Graph.DeviceManagement -ErrorAction SilentlyContinue
            if (-not $graphModule) {
                Write-Host ""
                Write-Host "  ┌─" -ForegroundColor DarkGray -NoNewline
                Write-Host " GRAPH " -ForegroundColor Cyan -NoNewline
                Write-Host "───────────────────────────────────┐" -ForegroundColor DarkGray
                Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                Write-Host "⚠ " -ForegroundColor Yellow -NoNewline
                Write-Host "Microsoft.Graph module not installed" -ForegroundColor Yellow
                Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                Write-Host "  Install: " -ForegroundColor DarkGray -NoNewline
                Write-Host "Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor DarkCyan
                Write-Host "  └────────────────────────────────────────────┘" -ForegroundColor DarkGray
                Write-PolicyLensLog "Phase 4: Microsoft.Graph module not installed - skipping" -Level Warning
            }
            else {
                Write-Host ""
                Write-Host "  ┌─" -ForegroundColor DarkGray -NoNewline
                Write-Host " GRAPH " -ForegroundColor Cyan -NoNewline
                Write-Host "───────────────────────────────────┐" -ForegroundColor DarkGray
                Write-Host "  │ " -ForegroundColor DarkGray -NoNewline
                Write-Host "► " -ForegroundColor Yellow -NoNewline
                Write-Host "Connecting to " -ForegroundColor White -NoNewline
                Write-Host "Microsoft Graph" -ForegroundColor Cyan -NoNewline
                Write-Host "...          │" -ForegroundColor White
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
                    Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                    Write-Host "✓ " -ForegroundColor Green -NoNewline
                    Write-Host "Connected to Graph API" -ForegroundColor Green
                    Write-PolicyLensLog "Phase 4: Graph connected successfully" -Level Info

                    # Get policy data
                    Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                    Write-Host "  Fetching Intune configuration profiles..." -ForegroundColor Gray
                    $graphData = Get-GraphPolicyData -TenantId $TenantId -GraphConnected
                    if ($graphData.Available) {
                        $totalProfiles = $graphData.Profiles.Count + $graphData.CompliancePolicies.Count + $graphData.SettingsCatalog.Count
                        Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                        Write-Host "  ✓ " -ForegroundColor Green -NoNewline
                        Write-Host "$totalProfiles" -ForegroundColor Green -NoNewline
                        Write-Host " profiles/policies" -ForegroundColor Gray
                        Write-PolicyLensLog "Phase 4: Intune profiles retrieved ($totalProfiles profiles)" -Level Info
                    }

                    # Get app assignments (skip local apps for remote scan)
                    Write-Host "  │ " -ForegroundColor DarkGray -NoNewline
                    Write-Host "► " -ForegroundColor Yellow -NoNewline
                    Write-Host "Fetching " -ForegroundColor White -NoNewline
                    Write-Host "Intune app assignments" -ForegroundColor Cyan -NoNewline
                    Write-Host "...          │" -ForegroundColor White
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
                    Write-Host "...  │" -ForegroundColor White
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

                    Write-Host "  └────────────────────────────────────────────┘" -ForegroundColor DarkGray
                }
                catch {
                    Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                    Write-Host "✗ " -ForegroundColor Red -NoNewline
                    Write-Host "Graph connection failed: $_" -ForegroundColor Red
                    Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                    Write-Host "  Continuing with device data only" -ForegroundColor DarkYellow
                    Write-Host "  └────────────────────────────────────────────┘" -ForegroundColor DarkGray
                    Write-PolicyLensLog "Phase 4: Graph connection failed - $_" -Level Error
                }
                finally {
                    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
                    Write-PolicyLensLog "Graph: Disconnected" -Level Info
                }
            }
        }
        else {
            Write-Host ""
            Write-Host "  ┌─" -ForegroundColor DarkGray -NoNewline
            Write-Host " GRAPH " -ForegroundColor DarkGray -NoNewline
            Write-Host "───────────────────────────────────┐" -ForegroundColor DarkGray
            Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
            Write-Host "○ " -ForegroundColor DarkGray -NoNewline
            Write-Host "Graph API skipped " -ForegroundColor DarkGray -NoNewline
            Write-Host "(use -IncludeGraph)" -ForegroundColor DarkCyan
            Write-Host "  └────────────────────────────────────────────┘" -ForegroundColor DarkGray
            Write-PolicyLensLog "Phase 4: Skipped (IncludeGraph not specified)" -Level Info
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
        Write-Host "  ╔══════════════════════════════════════════╗" -ForegroundColor Green
        Write-Host "  ║  " -ForegroundColor Green -NoNewline
        Write-Host "✓ REMOTE SCAN COMPLETE" -ForegroundColor White -NoNewline
        Write-Host "                  ║" -ForegroundColor Green
        Write-Host "  ╠══════════════════════════════════════════╣" -ForegroundColor Green
        Write-Host "  ║  " -ForegroundColor Green -NoNewline
        Write-Host "Target: " -ForegroundColor Gray -NoNewline
        Write-Host "$($deviceMetadata.ComputerName)" -ForegroundColor Cyan
        Write-Host "  ║  " -ForegroundColor Green -NoNewline
        Write-Host "JSON saved to:" -ForegroundColor Gray -NoNewline
        Write-Host "                         ║" -ForegroundColor Green
        Write-Host "  ║  " -ForegroundColor Green -NoNewline
        Write-Host "$jsonExportPath" -ForegroundColor Cyan
        Write-Host "  ╠══════════════════════════════════════════╣" -ForegroundColor Green
        Write-Host "  ║  " -ForegroundColor Green -NoNewline
        Write-Host "Duration: " -ForegroundColor Gray -NoNewline
        Write-Host "${duration}s" -ForegroundColor White -NoNewline
        Write-Host "                             ║" -ForegroundColor Green
        Write-Host "  ║  " -ForegroundColor Green -NoNewline
        Write-Host "View results: Open JSON in PolicyLensViewer" -ForegroundColor Gray -NoNewline
        Write-Host "  ║" -ForegroundColor Green
        Write-Host "  ╚══════════════════════════════════════════╝" -ForegroundColor Green
        Write-Host ""

        Write-PolicyLensLog "PolicyLens finished (${duration}s) - Remote scan of $($deviceMetadata.ComputerName)" -Level Info

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

    # --- Phase 1: Collect GPO data ---
    Write-Host "  ┌─" -ForegroundColor DarkGray -NoNewline
    Write-Host " PHASE 1 " -ForegroundColor Blue -NoNewline
    Write-Host "─────────────────────────────────┐" -ForegroundColor DarkGray
    Write-Host "  │ " -ForegroundColor DarkGray -NoNewline
    Write-Host "► " -ForegroundColor Yellow -NoNewline
    Write-Host "Collecting " -ForegroundColor White -NoNewline
    Write-Host "Group Policy" -ForegroundColor Blue -NoNewline
    Write-Host " data...          │" -ForegroundColor White
    Write-PolicyLensLog "Phase 1: GPO collection started" -Level Info
    try {
        $gpoData = Get-GPOPolicyData
        $gpoCount = $gpoData.RegistryPolicies.Count
        Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
        Write-Host "✓ " -ForegroundColor Green -NoNewline
        Write-Host "Found " -ForegroundColor Gray -NoNewline
        Write-Host "$($gpoData.TotalGPOCount)" -ForegroundColor Green -NoNewline
        Write-Host " GPOs, " -ForegroundColor Gray -NoNewline
        Write-Host "$gpoCount" -ForegroundColor Green -NoNewline
        Write-Host " registry policies" -ForegroundColor Gray
        Write-PolicyLensLog "Phase 1: GPO collection complete ($($gpoData.TotalGPOCount) GPOs, $gpoCount registry policies)" -Level Info
    }
    catch {
        Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
        Write-Host "✗ " -ForegroundColor Red -NoNewline
        Write-Host "Collection failed" -ForegroundColor Red
        Write-PolicyLensLog "Phase 1: GPO collection failed - $_" -Level Error
        throw
    }

    # --- Phase 2: Collect MDM data ---
    Write-Host "  ├─" -ForegroundColor DarkGray -NoNewline
    Write-Host " PHASE 2 " -ForegroundColor Magenta -NoNewline
    Write-Host "─────────────────────────────────┤" -ForegroundColor DarkGray
    Write-Host "  │ " -ForegroundColor DarkGray -NoNewline
    Write-Host "► " -ForegroundColor Yellow -NoNewline
    Write-Host "Collecting " -ForegroundColor White -NoNewline
    Write-Host "MDM/Intune" -ForegroundColor Magenta -NoNewline
    Write-Host " data...            │" -ForegroundColor White
    Write-PolicyLensLog "Phase 2: MDM collection started" -Level Info
    try {
        $mdmData = Get-MDMPolicyData -SkipMDMDiag:$SkipMDMDiag
        $mdmTotal = $mdmData.DevicePolicies.Count + $mdmData.UserPolicies.Count
        if ($mdmData.IsEnrolled) {
            Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
            Write-Host "✓ " -ForegroundColor Green -NoNewline
            Write-Host "Enrolled • " -ForegroundColor Green -NoNewline
            Write-Host "$mdmTotal" -ForegroundColor Green -NoNewline
            Write-Host " MDM policies found" -ForegroundColor Gray
            Write-PolicyLensLog "Phase 2: MDM collection complete (enrolled, $mdmTotal policies)" -Level Info
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
    Write-Host "  ├─" -ForegroundColor DarkGray -NoNewline
    Write-Host " PHASE 3 " -ForegroundColor DarkYellow -NoNewline
    Write-Host "─────────────────────────────────┤" -ForegroundColor DarkGray
    Write-Host "  │ " -ForegroundColor DarkGray -NoNewline
    Write-Host "► " -ForegroundColor Yellow -NoNewline
    Write-Host "Collecting " -ForegroundColor White -NoNewline
    Write-Host "SCCM/ConfigMgr" -ForegroundColor DarkYellow -NoNewline
    Write-Host " data...        │" -ForegroundColor White
    Write-PolicyLensLog "Phase 3: SCCM collection started" -Level Info
    $sccmData = $null
    try {
        $sccmData = Get-SCCMPolicyData
        if ($sccmData.IsInstalled) {
            $appCount = $sccmData.Applications.Count
            $baselineCount = $sccmData.Baselines.Count
            Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
            Write-Host "✓ " -ForegroundColor Green -NoNewline
            Write-Host "Installed • " -ForegroundColor Green -NoNewline
            Write-Host "$appCount" -ForegroundColor Green -NoNewline
            Write-Host " apps, " -ForegroundColor Gray -NoNewline
            Write-Host "$baselineCount" -ForegroundColor Green -NoNewline
            Write-Host " baselines" -ForegroundColor Gray
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

    # --- Phase 4: Optionally collect Graph data ---
    $graphData = $null
    $appData = $null
    $groupData = $null

    if ($IncludeGraph) {
        Write-PolicyLensLog "Phase 4: Graph collection started" -Level Info
        # Connect to Graph once for all Graph-dependent functions
        $graphModule = Get-Module -ListAvailable Microsoft.Graph.DeviceManagement -ErrorAction SilentlyContinue
        if (-not $graphModule) {
            Write-Host "  ├─" -ForegroundColor DarkGray -NoNewline
            Write-Host " PHASE 4 " -ForegroundColor Cyan -NoNewline
            Write-Host "─────────────────────────────────┤" -ForegroundColor DarkGray
            Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
            Write-Host "⚠ " -ForegroundColor Yellow -NoNewline
            Write-Host "Microsoft.Graph module not installed" -ForegroundColor Yellow
            Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
            Write-Host "  Install: " -ForegroundColor DarkGray -NoNewline
            Write-Host "Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor DarkCyan
            Write-PolicyLensLog "Phase 4: Microsoft.Graph module not installed - skipping" -Level Warning
        }
        else {
            # Connect once
            Write-Host "  ├─" -ForegroundColor DarkGray -NoNewline
            Write-Host " PHASE 4 " -ForegroundColor Cyan -NoNewline
            Write-Host "─────────────────────────────────┤" -ForegroundColor DarkGray
            Write-Host "  │ " -ForegroundColor DarkGray -NoNewline
            Write-Host "► " -ForegroundColor Yellow -NoNewline
            Write-Host "Connecting to " -ForegroundColor White -NoNewline
            Write-Host "Microsoft Graph" -ForegroundColor Cyan -NoNewline
            Write-Host "...          │" -ForegroundColor White
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
                Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                Write-Host "✓ " -ForegroundColor Green -NoNewline
                Write-Host "Connected to Graph API" -ForegroundColor Green
                Write-PolicyLensLog "Phase 4: Graph connected successfully" -Level Info

                # Get policy data
                Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                Write-Host "  Fetching Intune configuration profiles..." -ForegroundColor Gray
                $graphData = Get-GraphPolicyData -TenantId $TenantId -GraphConnected
                if ($graphData.Available) {
                    $totalProfiles = $graphData.Profiles.Count + $graphData.CompliancePolicies.Count + $graphData.SettingsCatalog.Count
                    Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                    Write-Host "  ✓ " -ForegroundColor Green -NoNewline
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
                Write-Host "...          │" -ForegroundColor White
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
                Write-Host "...  │" -ForegroundColor White
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

            }
            catch {
                Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                Write-Host "✗ " -ForegroundColor Red -NoNewline
                Write-Host "Graph connection failed: $_" -ForegroundColor Red
                Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
                Write-Host "  Continuing with local data only" -ForegroundColor DarkYellow
                Write-PolicyLensLog "Phase 4: Graph connection failed - $_" -Level Error
            }
            finally {
                # Always disconnect from Graph if we connected
                Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
                Write-PolicyLensLog "Graph: Disconnected" -Level Info
            }
        }
    }
    else {
        Write-Host "  ├─" -ForegroundColor DarkGray -NoNewline
        Write-Host " PHASE 4 " -ForegroundColor DarkGray -NoNewline
        Write-Host "─────────────────────────────────┤" -ForegroundColor DarkGray
        Write-Host "  │   " -ForegroundColor DarkGray -NoNewline
        Write-Host "○ " -ForegroundColor DarkGray -NoNewline
        Write-Host "Graph API skipped " -ForegroundColor DarkGray -NoNewline
        Write-Host "(use -IncludeGraph)" -ForegroundColor DarkCyan
        Write-PolicyLensLog "Phase 4: Skipped (IncludeGraph not specified)" -Level Info
    }

    # --- Phase 5: Analyze overlap ---
    Write-Host "  ├─" -ForegroundColor DarkGray -NoNewline
    Write-Host " ANALYSIS " -ForegroundColor White -NoNewline
    Write-Host "────────────────────────────────┤" -ForegroundColor DarkGray
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
    Write-Host "  ╔══════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "  ║  " -ForegroundColor Green -NoNewline
    Write-Host "✓ SCAN COMPLETE" -ForegroundColor White -NoNewline
    Write-Host "                         ║" -ForegroundColor Green
    Write-Host "  ╠══════════════════════════════════════════╣" -ForegroundColor Green
    Write-Host "  ║  " -ForegroundColor Green -NoNewline
    Write-Host "JSON saved to:" -ForegroundColor Gray -NoNewline
    Write-Host "                         ║" -ForegroundColor Green
    Write-Host "  ║  " -ForegroundColor Green -NoNewline
    Write-Host "$jsonExportPath" -ForegroundColor Cyan
    Write-Host "  ╠══════════════════════════════════════════╣" -ForegroundColor Green
    Write-Host "  ║  " -ForegroundColor Green -NoNewline
    Write-Host "Duration: " -ForegroundColor Gray -NoNewline
    Write-Host "${duration}s" -ForegroundColor White -NoNewline
    Write-Host "                             ║" -ForegroundColor Green
    Write-Host "  ║  " -ForegroundColor Green -NoNewline
    Write-Host "View results: Open JSON in PolicyLensViewer" -ForegroundColor Gray -NoNewline
    Write-Host "  ║" -ForegroundColor Green
    Write-Host "  ╚══════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""

    Write-PolicyLensLog "PolicyLens finished (${duration}s)" -Level Info

    return $result
}
