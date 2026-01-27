function Invoke-PolicyCheck {
    <#
    .SYNOPSIS
        Runs a full policy check on the local device.
    .DESCRIPTION
        Orchestrates collection of Group Policy data, MDM/Intune policy data,
        and optionally Microsoft Graph API data. Performs overlap analysis and
        generates both a console summary and HTML report.
    .PARAMETER IncludeGraph
        Connect to Microsoft Graph API to retrieve Intune profile metadata,
        app assignments, and Azure AD group memberships.
    .PARAMETER TenantId
        Azure AD tenant ID for Graph authentication.
    .PARAMETER OutputPath
        Path for the HTML report file. Defaults to a timestamped file in the current directory.
    .PARAMETER SkipMDMDiag
        Skip running mdmdiagnosticstool (can be slow on some devices).
    .EXAMPLE
        Invoke-PolicyCheck
        Runs a local-only scan and generates an HTML report.
    .EXAMPLE
        Invoke-PolicyCheck -IncludeGraph -TenantId "contoso.onmicrosoft.com"
        Runs a full scan including Graph API queries for Intune metadata.
    .OUTPUTS
        PSCustomObject with all collected data, analysis results, and report path.
    #>
    [CmdletBinding()]
    param(
        [switch]$IncludeGraph,

        [string]$TenantId,

        [string]$OutputPath = ".\PolicyCheck_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

        [switch]$SkipMDMDiag
    )

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

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
    }

    # --- Phase 1: Collect GPO data ---
    Write-Host "  [1/5] Collecting Group Policy data..." -ForegroundColor White
    $gpoData = Get-GPOPolicyData
    Write-Host "        Found $($gpoData.TotalGPOCount) GPOs, $($gpoData.RegistryPolicies.Count) registry policies" -ForegroundColor Gray

    # --- Phase 2: Collect MDM data ---
    Write-Host "  [2/5] Collecting MDM/Intune data..." -ForegroundColor White
    $mdmData = Get-MDMPolicyData -SkipMDMDiag:$SkipMDMDiag
    $mdmTotal = $mdmData.DevicePolicies.Count + $mdmData.UserPolicies.Count
    if ($mdmData.IsEnrolled) {
        Write-Host "        Device enrolled. $mdmTotal MDM policies found" -ForegroundColor Gray
    }
    else {
        Write-Host "        Device not MDM enrolled" -ForegroundColor Yellow
    }

    # --- Phase 3: Optionally collect Graph data ---
    $graphData = $null
    $appData = $null
    $groupData = $null

    if ($IncludeGraph) {
        # Connect to Graph once for all Graph-dependent functions
        $graphModule = Get-Module -ListAvailable Microsoft.Graph.DeviceManagement -ErrorAction SilentlyContinue
        if (-not $graphModule) {
            Write-Host "  [!] Microsoft.Graph module not installed. Skipping Graph queries." -ForegroundColor Yellow
            Write-Host "      Install with: Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor Yellow
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
                    NoWelcome = $true
                }
                if ($TenantId) { $connectParams['TenantId'] = $TenantId }

                Connect-MgGraph @connectParams -ErrorAction Stop
                Write-Host "        Connected successfully" -ForegroundColor Gray

                # Get policy data
                Write-Host "        Fetching Intune configuration profiles..." -ForegroundColor Gray
                $graphData = Get-GraphPolicyData -TenantId $TenantId
                if ($graphData.Available) {
                    $totalProfiles = $graphData.Profiles.Count + $graphData.CompliancePolicies.Count + $graphData.SettingsCatalog.Count
                    Write-Host "        Found $totalProfiles profiles/policies" -ForegroundColor Gray
                }

                # Get app assignments
                Write-Host "  [4/5] Fetching app assignments..." -ForegroundColor White
                $appData = Get-DeviceAppAssignments -GraphConnected
                Write-Host "        Found $($appData.Apps.Count) apps ($(@($appData.AssignedApps).Count) assigned)" -ForegroundColor Gray

                # Get group memberships
                Write-Host "  [5/5] Fetching device group memberships..." -ForegroundColor White
                $groupData = Get-DeviceGroupMemberships -GraphConnected
                if ($groupData.DeviceFound) {
                    Write-Host "        Device found. Member of $($groupData.Groups.Count) groups" -ForegroundColor Gray
                }
                else {
                    Write-Host "        Device not found in Azure AD" -ForegroundColor Yellow
                }

                # Disconnect
                Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
            }
            catch {
                Write-Host "  [!] Graph connection failed: $_" -ForegroundColor Red
                Write-Host "      Continuing with local data only." -ForegroundColor Yellow
            }
        }
    }
    else {
        Write-Host "  [3/5] Skipping Graph API (use -IncludeGraph to enable)" -ForegroundColor DarkGray
        Write-Host "  [4/5] Skipping app assignments (requires -IncludeGraph)" -ForegroundColor DarkGray
        Write-Host "  [5/5] Skipping group memberships (requires -IncludeGraph)" -ForegroundColor DarkGray
    }

    # --- Phase 4: Analyze overlap ---
    Write-Host ""
    Write-Host "  Analyzing policy overlap..." -ForegroundColor White
    $analysis = Compare-PolicyOverlap -GPOData $gpoData -MDMData $mdmData -GraphData $graphData

    # --- Phase 5: Output ---
    Write-ConsoleSummary -Analysis $analysis -GPOData $gpoData -MDMData $mdmData `
        -AppData $appData -GroupData $groupData

    $reportPath = ConvertTo-HtmlReport -Analysis $analysis -GPOData $gpoData `
        -MDMData $mdmData -GraphData $graphData -AppData $appData `
        -GroupData $groupData -OutputPath $OutputPath

    $stopwatch.Stop()

    Write-Host ""
    Write-Host "  ─────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  HTML report saved to:" -ForegroundColor White
    Write-Host "  $reportPath" -ForegroundColor Green
    Write-Host "  Completed in $([math]::Round($stopwatch.Elapsed.TotalSeconds, 1))s" -ForegroundColor Gray
    Write-Host ""

    # Return structured object for pipeline usage
    [PSCustomObject]@{
        GPOData    = $gpoData
        MDMData    = $mdmData
        GraphData  = $graphData
        AppData    = $appData
        GroupData  = $groupData
        Analysis   = $analysis
        ReportPath = $reportPath
    }
}
