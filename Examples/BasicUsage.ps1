<#
.SYNOPSIS
    Example usage patterns for PolicyLens module.
.DESCRIPTION
    Demonstrates common scenarios for scanning and analyzing
    GPO, Intune, and SCCM policies using PolicyLens.
#>

# Import the module
Import-Module "$PSScriptRoot\..\PolicyLens.psd1"

# ============================================================
# Example 1: Basic local scan
# ============================================================
# Scans GPO, MDM, and SCCM on the local machine
$result = Invoke-PolicyLens
Write-Host "JSON exported to: $($result.JsonPath)"

# ============================================================
# Example 2: Scan with Graph API (Intune profiles, apps, groups)
# ============================================================
# Requires Microsoft.Graph module and appropriate permissions
# Will prompt for interactive authentication
$result = Invoke-PolicyLens -IncludeGraph

# ============================================================
# Example 3: Remote scan via WinRM
# ============================================================
# Scan a remote machine (requires WinRM enabled on target)
$result = Invoke-PolicyLens -ComputerName "SERVER01"

# With explicit credentials:
$cred = Get-Credential
$result = Invoke-PolicyLens -ComputerName "SERVER01" -Credential $cred

# ============================================================
# Example 4: Programmatic access to results
# ============================================================
Import-Module "$PSScriptRoot\..\PolicyLens.psd1"

# Collect data from individual sources
$gpoData = Get-GPOPolicyData
$mdmData = Get-MDMPolicyData
$sccmData = Get-SCCMPolicyData

# Analyze overlap between GPO and MDM
$analysis = Compare-PolicyOverlap -GPOData $gpoData -MDMData $mdmData

# View summary
$analysis.Summary

# View detailed results
$analysis.DetailedResults | Where-Object Status -eq 'BothConfigured'

# ============================================================
# Example 5: Export to custom location
# ============================================================
$result = Invoke-PolicyLens -OutputPath "C:\Reports\PolicyScan_$(Get-Date -Format 'yyyyMMdd').json"
