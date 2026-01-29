# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PolicyLens is a PowerShell module that scans Windows devices for applied Group Policy (GPO), Intune/MDM policies, and SCCM/ConfigMgr configurations. It analyzes overlap between policy sources and exports results to JSON for the web viewer tool to assist with GPO-to-Intune migration.

## Running the Tool

```powershell
# Basic local scan (using wrapper script)
.\PolicyLens.ps1

# With Graph API (Intune profiles, apps, groups)
.\PolicyLens.ps1 -IncludeGraph

# Export to specific path
.\PolicyLens.ps1 -OutputPath "C:\Reports\device1.json"
```

Requires Windows 10/11 and PowerShell 5.1+. Run as Administrator for full results.

## Module Architecture

**Entry Points:**
- `PolicyLens.ps1` - Standalone script wrapper that imports the module and runs `Invoke-PolicyLens`
- `PolicyLens.psd1` / `PolicyLens.psm1` - Module manifest and loader (dot-sources Public/ and Private/ scripts)

**Public Functions** (exported, in `Public/`):
- `Invoke-PolicyLens` - Main orchestrator that runs all phases and exports JSON
- `Get-GPOPolicyData` - Collects GPO data via gpresult and registry scanning
- `Get-MDMPolicyData` - Reads MDM enrollment and PolicyManager registry keys
- `Get-SCCMPolicyData` - Collects SCCM client data via WMI
- `Get-GraphPolicyData` - Fetches Intune profiles via Microsoft Graph
- `Get-DeviceAppAssignments` - Gets Intune app assignments via Graph
- `Get-DeviceGroupMemberships` - Gets Azure AD group memberships via Graph
- `Compare-PolicyOverlap` - Cross-references GPO settings against MDM using SettingsMap

**Private Functions** (internal, in `Private/`):
- `ConvertTo-JsonExport` - Exports results to JSON for the web viewer tool
- `Write-ConsoleSummary` - Outputs color-coded summary to console
- `Write-PolicyLensLog` - Writes operational log entries

**Data Flow:**
1. `Invoke-PolicyLens` calls data collection functions (GPO, MDM, SCCM, optionally Graph)
2. `Compare-PolicyOverlap` analyzes settings using `Config/SettingsMap.psd1` mapping
3. Results flow to `Write-ConsoleSummary` and `ConvertTo-JsonExport`

## Key Files

| Path | Purpose |
|------|---------|
| `Config/SettingsMap.psd1` | GPO-to-Intune CSP mapping definitions (extensible) |
| `Tools/PolicyLensViewer.html` | Self-contained web viewer for JSON exports |

## Extending the Settings Map

Add entries to `Config/SettingsMap.psd1`:
```powershell
@{
    CategoryName = @(
        @{
            GPOPathPattern = 'Registry\\Path\\Pattern'  # Regex to match GPO registry path
            MDMArea        = 'CSPAreaName'              # Intune CSP area
            MDMSetting     = 'SettingName'              # Intune CSP setting name
            CSPURI         = './Device/Vendor/MSFT/...' # Full CSP URI
        }
    )
}
```

## Output Formats

- **JSON Export** - Always generated, view with `Tools/PolicyLensViewer.html`
- **PSCustomObject** - Returned to pipeline for programmatic access
