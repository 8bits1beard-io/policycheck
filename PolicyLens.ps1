<#
.SYNOPSIS
    PolicyLens - GPO, Intune & SCCM Policy Scanner
.DESCRIPTION
    Scans the local Windows device for applied Group Policies, Intune/MDM policies,
    and SCCM configurations. Provides visibility into policy sources, analyzes overlap,
    and exports results to JSON for the web viewer tool.
.PARAMETER IncludeGraph
    Connect to Microsoft Graph API to retrieve Intune profile metadata,
    app assignments, and Azure AD group memberships.
.PARAMETER TenantId
    Azure AD tenant ID or domain for Graph authentication (e.g., "contoso.onmicrosoft.com").
.PARAMETER SkipMDMDiag
    Skip running mdmdiagnosticstool (can be slow on some devices).
.PARAMETER OutputPath
    Path for the JSON export file. Defaults to a timestamped file in the current directory.
.PARAMETER LogPath
    Path for the operational log file. Defaults to PolicyLens.log in LocalAppData.
.EXAMPLE
    .\PolicyLens.ps1
    Runs a local-only scan and exports results to JSON.
.EXAMPLE
    .\PolicyLens.ps1 -IncludeGraph
    Runs a full scan with Graph API queries (browser auth prompt).
.EXAMPLE
    .\PolicyLens.ps1 -OutputPath "C:\Reports\device1.json"
    Runs a local scan and exports results to a specific path.
#>
[CmdletBinding()]
param(
    [switch]$IncludeGraph,
    [string]$TenantId,
    [switch]$SkipMDMDiag,
    [string]$OutputPath,
    [string]$LogPath
)

# Add System.Web for HTML encoding in report generation
Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

# Import the module from the script's directory
Import-Module "$PSScriptRoot\PolicyLens.psd1" -Force

# Build parameters, excluding empty ones
$params = @{}
if ($IncludeGraph) { $params['IncludeGraph'] = $true }
if ($TenantId) { $params['TenantId'] = $TenantId }
if ($SkipMDMDiag) { $params['SkipMDMDiag'] = $true }
if ($OutputPath) { $params['OutputPath'] = $OutputPath }
if ($LogPath) { $params['LogPath'] = $LogPath }

Invoke-PolicyLens @params
