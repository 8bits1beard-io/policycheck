# Changelog

All notable changes to PolicyLens are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-02-02

### Added
- GPO source attribution via RSoP WMI - each registry setting now shows which GPO configured it
- New `Get-RSoPPolicySource` private function for querying RSoP data
- `SourceGPO` and `SourceOU` fields on GPO registry policies

### Changed
- MDM data collection now reads from `Providers/{Intune-GUID}/default/Device` for accuracy
- Shows only Intune-configured policies instead of all CSP values (was showing ~1900, now shows actual configured count)
- Graph policy assignments now display friendly names (All Devices, All Users, Group: Name)
- Apps section in viewer uses table format matching other policy sections
- Added `IntunePolicies`, `IntunePolicyCount`, `TotalCSPValueCount` to MDM output

### Fixed
- MDM section no longer shows thousands of default CSP values
- Graph policy filtering now works correctly with group membership data

## [1.0.0] - 2026-02-02

### Added
- **Mapping Suggestions** - New `-SuggestMappings` parameter to find Settings Catalog matches for unmapped GPO settings
- **Remote Scanning** - Scan remote machines via WinRM with `-ComputerName` and `-Credential` parameters
- **RSOP Auto-Enable** - Automatically enables RSOP logging when disabled by GPO
- **Viewer Enhancements** - Copy-to-clipboard for mapping suggestions, grouped summary cards
- **Settings Catalog Integration** - `Get-SettingsCatalogMappings` function to query Intune definitions via Graph API

### Changed
- Redesigned web viewer with clearer sections and improved layout
- Improved console output with consistent styling and progress tracking
- Use `/scope:computer` for gpresult for more reliable results

### Fixed
- gpupdate /force now runs after enabling RSOP for immediate effect

## [0.9.0] - 2026-01-15

### Added
- Initial public release
- GPO data collection via gpresult and registry scanning
- MDM/Intune policy collection from PolicyManager registry
- SCCM/ConfigMgr client data collection via WMI
- Microsoft Graph API integration for Intune profiles, apps, and group memberships
- Policy overlap analysis with GPO-to-CSP mapping
- Web-based viewer for JSON exports
- Comprehensive SettingsMap.psd1 with common GPO-to-Intune mappings
