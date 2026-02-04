<#
.SYNOPSIS
    PolicyLens - GPO, Intune & SCCM Policy Scanner
.DESCRIPTION
    Scans a Windows device for applied Group Policies, Intune/MDM policies,
    and SCCM configurations. Provides visibility into policy sources, analyzes overlap,
    verifies deployment status, and exports results to JSON for the web viewer tool.
    By default, queries Graph API for Intune profiles, apps, groups, and deployment
    verification. Use -SkipIntune or -SkipVerify to disable these features.
    Supports both local and remote scanning via WinRM.
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
    Azure AD tenant ID or domain for Graph authentication (e.g., "contoso.onmicrosoft.com").
.PARAMETER SuggestMappings
    Find Intune Settings Catalog matches for unmapped GPO settings.
.PARAMETER SkipSCCM
    Skip SCCM/ConfigMgr client data collection via WMI.
.PARAMETER SCCMSiteServer
    SCCM site server (SMS Provider) for deployment verification. Auto-discovered if not specified.
.PARAMETER SCCMSiteCode
    SCCM site code for deployment verification. Auto-discovered if not specified.
.PARAMETER SCCMCredential
    PSCredential for authenticating to the SCCM site server. Required for deployment verification.
.PARAMETER SkipSCCMVerify
    Skip SCCM deployment verification. Client-side SCCM data is still collected.
.PARAMETER SkipMDMDiag
    Skip running mdmdiagnosticstool (can be slow on some devices).
.PARAMETER OutputPath
    Path for the JSON export file. Defaults to a timestamped file in the current directory.
.PARAMETER LogPath
    Path for the operational log file. Defaults to PolicyLens.log in LocalAppData.
.EXAMPLE
    .\PolicyLens.ps1
    Runs a full scan with Graph API and deployment verification (default).
.EXAMPLE
    .\PolicyLens.ps1 -SkipIntune
    Runs a local-only scan without Graph API queries.
.EXAMPLE
    .\PolicyLens.ps1 -SkipVerify
    Runs a scan with Graph API but skips deployment verification.
.EXAMPLE
    .\PolicyLens.ps1 -ComputerName SERVER1
    Runs a remote scan on SERVER1 with Graph API queries.
.EXAMPLE
    .\PolicyLens.ps1 -ComputerName SERVER1 -SkipIntune
    Runs a remote scan on SERVER1 without Graph API queries.
.EXAMPLE
    .\PolicyLens.ps1 -OutputPath "C:\Reports\device1.json"
    Runs a full scan and exports results to a specific path.
#>
[CmdletBinding()]
param(
    [string]$ComputerName,
    [PSCredential]$Credential,
    [switch]$SkipIntune,
    [switch]$SkipVerify,
    [switch]$SkipGPOVerify,
    [switch]$SuggestMappings,
    [string]$TenantId,
    [switch]$SkipSCCM,
    [string]$SCCMSiteServer,
    [string]$SCCMSiteCode,
    [PSCredential]$SCCMCredential,
    [switch]$SkipSCCMVerify,
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
if ($ComputerName) { $params['ComputerName'] = $ComputerName }
if ($Credential) { $params['Credential'] = $Credential }
if ($SkipIntune) { $params['SkipIntune'] = $true }
if ($SkipVerify) { $params['SkipVerify'] = $true }
if ($SkipGPOVerify) { $params['SkipGPOVerify'] = $true }
if ($SuggestMappings) { $params['SuggestMappings'] = $true }
if ($TenantId) { $params['TenantId'] = $TenantId }
if ($SkipSCCM) { $params['SkipSCCM'] = $true }
if ($SCCMSiteServer) { $params['SCCMSiteServer'] = $SCCMSiteServer }
if ($SCCMSiteCode) { $params['SCCMSiteCode'] = $SCCMSiteCode }
if ($SCCMCredential) { $params['SCCMCredential'] = $SCCMCredential }
if ($SkipSCCMVerify) { $params['SkipSCCMVerify'] = $true }
if ($SkipMDMDiag) { $params['SkipMDMDiag'] = $true }
if ($OutputPath) { $params['OutputPath'] = $OutputPath }
if ($LogPath) { $params['LogPath'] = $LogPath }

Invoke-PolicyLens @params
