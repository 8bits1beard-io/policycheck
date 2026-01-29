<#
.SYNOPSIS
    PolicyCheck - GPO & Intune Policy Scanner
.DESCRIPTION
    Scans the local Windows device for applied Group Policies and Intune/MDM policies.
    Analyzes overlap between GPO and MDM settings, identifies migration candidates,
    and generates a detailed HTML report.
.PARAMETER IncludeGraph
    Connect to Microsoft Graph API to retrieve Intune profile metadata,
    app assignments, and Azure AD group memberships.
.PARAMETER TenantId
    Azure AD tenant ID or domain for Graph authentication (e.g., "contoso.onmicrosoft.com").
.PARAMETER OutputPath
    Path for the HTML report file. Defaults to a timestamped file in the current directory.
.PARAMETER SkipMDMDiag
    Skip running mdmdiagnosticstool (can be slow on some devices).
.PARAMETER ExportJson
    Export results to a JSON file for use with the PolicyCheck Viewer web tool.
.PARAMETER JsonPath
    Path for the JSON export file. Defaults to a timestamped file in the current directory.
.EXAMPLE
    .\PolicyCheck.ps1
    Runs a local-only scan.
.EXAMPLE
    .\PolicyCheck.ps1 -IncludeGraph
    Runs a full scan with Graph API queries (browser auth prompt).
.EXAMPLE
    .\PolicyCheck.ps1 -IncludeGraph -TenantId "contoso.onmicrosoft.com" -OutputPath "C:\Reports\scan.html"
    Full scan with specified tenant and output path.
.EXAMPLE
    .\PolicyCheck.ps1 -ExportJson -JsonPath "C:\Reports\device1.json"
    Runs a local scan and exports results to a JSON file for the PolicyCheck Viewer web tool.
#>
[CmdletBinding()]
param(
    [switch]$IncludeGraph,
    [string]$TenantId,
    [string]$OutputPath,
    [switch]$SkipMDMDiag,
    [switch]$ExportJson,
    [string]$JsonPath
)

# Add System.Web for HTML encoding in report generation
Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

# Import the module from the script's directory
Import-Module "$PSScriptRoot\PolicyCheck.psd1" -Force

# Build parameters, excluding empty ones
$params = @{}
if ($IncludeGraph) { $params['IncludeGraph'] = $true }
if ($TenantId) { $params['TenantId'] = $TenantId }
if ($OutputPath) { $params['OutputPath'] = $OutputPath }
if ($SkipMDMDiag) { $params['SkipMDMDiag'] = $true }
if ($ExportJson) { $params['ExportJson'] = $true }
if ($JsonPath) { $params['JsonPath'] = $JsonPath }

Invoke-PolicyCheck @params
