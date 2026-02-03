# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PolicyLens is a PowerShell module that scans Windows devices for applied Group Policy (GPO), Intune/MDM policies, and SCCM/ConfigMgr configurations. It analyzes overlap between policy sources and exports results to JSON for the web viewer tool to assist with GPO-to-Intune migration.

## Running the Tool

```powershell
# Import the module and run a basic local scan
Import-Module .\PolicyLens.psd1
Invoke-PolicyLens

# Or use the wrapper script
.\PolicyLens.ps1

# With Graph API (Intune profiles, apps, groups)
Invoke-PolicyLens -IncludeGraph

# With mapping suggestions for unmapped GPO settings
Invoke-PolicyLens -IncludeGraph -SuggestMappings

# Remote scan via WinRM
Invoke-PolicyLens -ComputerName SERVER1

# Export to specific path
Invoke-PolicyLens -OutputPath "C:\Reports\device1.json"
```

Requires Windows 10/11 and PowerShell 5.1+. Run as Administrator for full results.

## Folder Structure

```
PolicyLens/
├── PolicyLens.psd1          # Module manifest
├── PolicyLens.psm1          # Module loader
├── PolicyLens.ps1           # Wrapper script (optional entry point)
├── Public/                  # Exported functions
├── Private/                 # Internal helper functions
├── Config/                  # Configuration files (SettingsMap.psd1)
├── Viewer/                  # Web-based JSON viewer
├── Tests/                   # Pester tests and test helpers
│   └── Helpers/             # Test utility scripts
├── Examples/                # Sample outputs and usage scripts
└── docs/                    # Documentation and planning
```

## Module Architecture

**Public Functions** (exported, in `Public/`):
- `Invoke-PolicyLens` - Main orchestrator that runs all phases and exports JSON
- `Get-GPOPolicyData` - Collects GPO data via gpresult and registry scanning
- `Get-MDMPolicyData` - Reads MDM enrollment and PolicyManager registry keys
- `Get-SCCMPolicyData` - Collects SCCM client data via WMI
- `Get-GraphPolicyData` - Fetches Intune profiles via Microsoft Graph
- `Get-DeviceAppAssignments` - Gets Intune app assignments via Graph
- `Get-DeviceGroupMemberships` - Gets Azure AD group memberships via Graph
- `Get-SettingsCatalogMappings` - Fetches Intune Settings Catalog definitions via Graph (cached)
- `Compare-PolicyOverlap` - Cross-references GPO settings against MDM using SettingsMap

**Private Functions** (internal, in `Private/`):
- `ConvertTo-JsonExport` - Exports results to JSON for the web viewer tool
- `Write-ConsoleSummary` - Outputs color-coded summary to console
- `Write-PolicyLensLog` - Writes operational log entries
- `Find-SettingsCatalogMatch` - Matches GPO settings to Settings Catalog items
- `Get-RemoteCollectionScriptBlock` - Generates script block for WinRM remote scans

**Data Flow:**
1. `Invoke-PolicyLens` calls data collection functions (GPO, MDM, SCCM, optionally Graph)
2. `Compare-PolicyOverlap` analyzes settings using `Config/SettingsMap.psd1` mapping
3. Results flow to `Write-ConsoleSummary` and `ConvertTo-JsonExport`

## Key Files

| Path | Purpose |
|------|---------|
| `Config/SettingsMap.psd1` | GPO-to-Intune CSP mapping definitions (extensible) |
| `Viewer/PolicyLensViewer.html` | Self-contained web viewer for JSON exports |
| `Tests/Helpers/Test-SettingsCatalogMapping.ps1` | Test script for validating mapping suggestions |
| `Examples/BasicUsage.ps1` | Common usage patterns and examples |

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

- **JSON Export** - Always generated, view with `Viewer/PolicyLensViewer.html`
- **PSCustomObject** - Returned to pipeline for programmatic access

## Testing

```powershell
# Test individual data collection functions
Import-Module .\PolicyLens.psd1
$gpo = Get-GPOPolicyData
$mdm = Get-MDMPolicyData
$analysis = Compare-PolicyOverlap -GPOData $gpo -MDMData $mdm

# Test mapping suggestion matching
.\Tests\Helpers\Test-SettingsCatalogMapping.ps1
```
