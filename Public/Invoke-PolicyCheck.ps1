function Invoke-PolicyCheck {
    <#
    .SYNOPSIS
        Runs a full policy check on the local device.
    .DESCRIPTION
        Orchestrates collection of Group Policy data, MDM/Intune policy data,
        and optionally Microsoft Graph API data. Performs overlap analysis and
        exports results to JSON for the web viewer tool.
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
        Path for the operational log file. Defaults to PolicyCheck.log in LocalAppData.
    .EXAMPLE
        Invoke-PolicyCheck
        Runs a local-only scan and exports results to JSON.
    .EXAMPLE
        Invoke-PolicyCheck -IncludeGraph -TenantId "contoso.onmicrosoft.com"
        Runs a full scan including Graph API queries for Intune metadata.
    .EXAMPLE
        Invoke-PolicyCheck -OutputPath "C:\Reports\device1.json"
        Runs a local scan and exports results to a specific path.
    .OUTPUTS
        PSCustomObject with all collected data and analysis results.
    #>
    [CmdletBinding()]
    param(
        [switch]$IncludeGraph,

        [string]$TenantId,

        [switch]$SkipMDMDiag,

        [string]$OutputPath = ".\PolicyCheck_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd_HHmmss').json",

        [string]$LogPath = "$env:LOCALAPPDATA\PolicyCheck\PolicyCheck.log"
    )

    # Set script-scoped log path for Write-PolicyCheckLog
    $Script:LogPath = $LogPath

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    # --- Start logging ---
    Write-PolicyCheckLog "========================================" -Level Info
    Write-PolicyCheckLog "PolicyCheck started (v1.0.0)" -Level Info
    Write-PolicyCheckLog "Parameters: IncludeGraph=$IncludeGraph, SkipMDMDiag=$SkipMDMDiag" -Level Info

    Write-Host ""
    Write-Host "  PolicyCheck v1.0.0" -ForegroundColor Cyan
    Write-Host "  GPO & Intune Policy Scanner" -ForegroundColor Gray
    Write-Host "  ─────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""

    # --- Check elevation ---
    $isAdmin = ([Security.Principal.WindowsPrincipal]`
        [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Write-Host "  [!] Running without Administrator privileges." -ForegroundColor Yellow
        Write-Host "      Some data may be incomplete. Run as Admin for full results." -ForegroundColor Yellow
        Write-Host ""
        Write-PolicyCheckLog "Running without Administrator privileges" -Level Warning
    }
    else {
        Write-PolicyCheckLog "Running with Administrator privileges" -Level Info
    }

    # --- Phase 1: Collect GPO data ---
    Write-Host "  [1/5] Collecting Group Policy data..." -ForegroundColor White
    Write-PolicyCheckLog "Phase 1: GPO collection started" -Level Info
    try {
        $gpoData = Get-GPOPolicyData
        $gpoCount = $gpoData.RegistryPolicies.Count
        Write-Host "        Found $($gpoData.TotalGPOCount) GPOs, $gpoCount registry policies" -ForegroundColor Gray
        Write-PolicyCheckLog "Phase 1: GPO collection complete ($($gpoData.TotalGPOCount) GPOs, $gpoCount registry policies)" -Level Info
    }
    catch {
        Write-PolicyCheckLog "Phase 1: GPO collection failed - $_" -Level Error
        throw
    }

    # --- Phase 2: Collect MDM data ---
    Write-Host "  [2/5] Collecting MDM/Intune data..." -ForegroundColor White
    Write-PolicyCheckLog "Phase 2: MDM collection started" -Level Info
    try {
        $mdmData = Get-MDMPolicyData -SkipMDMDiag:$SkipMDMDiag
        $mdmTotal = $mdmData.DevicePolicies.Count + $mdmData.UserPolicies.Count
        if ($mdmData.IsEnrolled) {
            Write-Host "        Device enrolled. $mdmTotal MDM policies found" -ForegroundColor Gray
            Write-PolicyCheckLog "Phase 2: MDM collection complete (enrolled, $mdmTotal policies)" -Level Info
        }
        else {
            Write-Host "        Device not MDM enrolled" -ForegroundColor Yellow
            Write-PolicyCheckLog "Phase 2: MDM collection complete (not enrolled)" -Level Warning
        }
    }
    catch {
        Write-PolicyCheckLog "Phase 2: MDM collection failed - $_" -Level Error
        throw
    }

    # --- Phase 3: Optionally collect Graph data ---
    $graphData = $null
    $appData = $null
    $groupData = $null

    if ($IncludeGraph) {
        Write-PolicyCheckLog "Phase 3: Graph collection started" -Level Info
        # Connect to Graph once for all Graph-dependent functions
        $graphModule = Get-Module -ListAvailable Microsoft.Graph.DeviceManagement -ErrorAction SilentlyContinue
        if (-not $graphModule) {
            Write-Host "  [!] Microsoft.Graph module not installed. Skipping Graph queries." -ForegroundColor Yellow
            Write-Host "      Install with: Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor Yellow
            Write-PolicyCheckLog "Phase 3: Microsoft.Graph module not installed - skipping" -Level Warning
        }
        else {
            # Connect once
            Write-Host "  [3/5] Connecting to Microsoft Graph..." -ForegroundColor White
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

                Connect-MgGraph @connectParams -ErrorAction Stop
                Write-Host "        Connected successfully" -ForegroundColor Gray
                Write-PolicyCheckLog "Phase 3: Graph connected successfully" -Level Info

                # Get policy data
                Write-Host "        Fetching Intune configuration profiles..." -ForegroundColor Gray
                $graphData = Get-GraphPolicyData -TenantId $TenantId -GraphConnected
                if ($graphData.Available) {
                    $totalProfiles = $graphData.Profiles.Count + $graphData.CompliancePolicies.Count + $graphData.SettingsCatalog.Count
                    Write-Host "        Found $totalProfiles profiles/policies" -ForegroundColor Gray
                    Write-PolicyCheckLog "Phase 3: Intune profiles retrieved ($totalProfiles profiles)" -Level Info
                }
                else {
                    Write-PolicyCheckLog "Phase 3: Intune profiles not available" -Level Warning
                }

                # Get app assignments
                Write-Host "  [4/5] Fetching app assignments..." -ForegroundColor White
                Write-PolicyCheckLog "Phase 4: App assignments started" -Level Info
                $appData = Get-DeviceAppAssignments -GraphConnected
                $appCount = $appData.Apps.Count
                $assignedCount = @($appData.AssignedApps).Count
                Write-Host "        Found $appCount apps ($assignedCount assigned)" -ForegroundColor Gray
                Write-PolicyCheckLog "Phase 4: App assignments complete ($appCount apps, $assignedCount assigned)" -Level Info

                # Get group memberships
                Write-Host "  [5/5] Fetching device group memberships..." -ForegroundColor White
                Write-PolicyCheckLog "Phase 5: Group memberships started" -Level Info
                $groupData = Get-DeviceGroupMemberships -GraphConnected
                if ($groupData.DeviceFound) {
                    $groupCount = $groupData.Groups.Count
                    Write-Host "        Device found. Member of $groupCount groups" -ForegroundColor Gray
                    Write-PolicyCheckLog "Phase 5: Group memberships complete ($groupCount groups)" -Level Info
                }
                else {
                    Write-Host "        Device not found in Azure AD" -ForegroundColor Yellow
                    Write-PolicyCheckLog "Phase 5: Device not found in Azure AD" -Level Warning
                }

            }
            catch {
                Write-Host "  [!] Graph connection failed: $_" -ForegroundColor Red
                Write-Host "      Continuing with local data only." -ForegroundColor Yellow
                Write-PolicyCheckLog "Phase 3: Graph connection failed - $_" -Level Error
            }
            finally {
                # Always disconnect from Graph if we connected
                Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
                Write-PolicyCheckLog "Graph: Disconnected" -Level Info
            }
        }
    }
    else {
        Write-Host "  [3/5] Skipping Graph API (use -IncludeGraph to enable)" -ForegroundColor DarkGray
        Write-Host "  [4/5] Skipping app assignments (requires -IncludeGraph)" -ForegroundColor DarkGray
        Write-Host "  [5/5] Skipping group memberships (requires -IncludeGraph)" -ForegroundColor DarkGray
        Write-PolicyCheckLog "Phase 3-5: Skipped (IncludeGraph not specified)" -Level Info
    }

    # --- Phase 4: Analyze overlap ---
    Write-Host ""
    Write-Host "  Analyzing policy overlap..." -ForegroundColor White
    Write-PolicyCheckLog "Analysis: Started" -Level Info
    try {
        $analysis = Compare-PolicyOverlap -GPOData $gpoData -MDMData $mdmData -GraphData $graphData
        $summary = $analysis.Summary
        Write-PolicyCheckLog "Analysis: Complete (conflicts=$($summary.ValuesInConflict), migration-ready=$($summary.GPOOnlyWithMapping), no-mapping=$($summary.GPOOnlyNoMapping))" -Level Info
    }
    catch {
        Write-PolicyCheckLog "Analysis: Failed - $_" -Level Error
        throw
    }

    # --- Phase 5: Output ---
    Write-ConsoleSummary -Analysis $analysis -GPOData $gpoData -MDMData $mdmData `
        -AppData $appData -GroupData $groupData

    # Return structured object for pipeline usage
    $result = [PSCustomObject]@{
        GPOData   = $gpoData
        MDMData   = $mdmData
        GraphData = $graphData
        AppData   = $appData
        GroupData = $groupData
        Analysis  = $analysis
    }

    # Export to JSON
    Write-PolicyCheckLog "Export: Started" -Level Info
    try {
        $jsonExportPath = ConvertTo-JsonExport -Result $result -OutputPath $OutputPath
        $result | Add-Member -NotePropertyName 'JsonPath' -NotePropertyValue $jsonExportPath
        Write-PolicyCheckLog "Export: Complete ($jsonExportPath)" -Level Info
    }
    catch {
        Write-PolicyCheckLog "Export: Failed - $_" -Level Error
        throw
    }

    $stopwatch.Stop()
    $duration = [math]::Round($stopwatch.Elapsed.TotalSeconds, 1)

    Write-Host ""
    Write-Host "  ─────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  JSON export saved to:" -ForegroundColor White
    Write-Host "  $jsonExportPath" -ForegroundColor Green
    Write-Host "  Completed in ${duration}s" -ForegroundColor Gray
    Write-Host ""

    Write-PolicyCheckLog "PolicyCheck finished (${duration}s)" -Level Info

    return $result
}
