function Invoke-PolicyLens {
    <#
    .SYNOPSIS
        Runs a full policy scan on the local device.
    .DESCRIPTION
        Orchestrates collection of Group Policy data, MDM/Intune policy data,
        SCCM/ConfigMgr data, and optionally Microsoft Graph API data. Performs
        overlap analysis and exports results to JSON for the web viewer tool.
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
        [switch]$IncludeGraph,

        [string]$TenantId,

        [switch]$SkipMDMDiag,

        [string]$OutputPath = ".\PolicyLens_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd_HHmmss').json",

        [string]$LogPath = "$env:LOCALAPPDATA\PolicyLens\PolicyLens.log"
    )

    # Set script-scoped log path for Write-PolicyLensLog
    $Script:LogPath = $LogPath

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    # --- Start logging ---
    Write-PolicyLensLog "========================================" -Level Info
    Write-PolicyLensLog "PolicyLens started (v1.0.0)" -Level Info
    Write-PolicyLensLog "Parameters: IncludeGraph=$IncludeGraph, SkipMDMDiag=$SkipMDMDiag" -Level Info

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

    # --- Check elevation ---
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
