# PolicyLens TODO

## Completed Features

### Settings Catalog Lookup via Graph API
**Status:** Completed in v1.0.0

Implemented via the `-SuggestMappings` parameter. When a GPO setting isn't found in our local `Config/SettingsMap.psd1`, the tool can query Microsoft Graph API to search Settings Catalog definitions for potential matches.

**Implementation:**
- `Get-SettingsCatalogMappings` function queries Graph API
- `Find-SettingsCatalogMatch` performs fuzzy matching against GPO settings
- Viewer displays suggestions with confidence levels (High, Medium, Low)
- Copy-to-clipboard for easy addition to SettingsMap.psd1

### GPO Application Verification
**Status:** Completed in v1.3.0

Queries Active Directory to compare linked GPOs against applied GPOs, detecting:
- Security filtering (GPO linked but not applied due to permissions)
- Disabled GPO links
- WMI filtering

### SCCM Deployment Verification
**Status:** Completed in v1.3.0

Queries SCCM site server (SMS Provider) to compare assigned deployments against installed state:
- Collection memberships
- Application deployments (Installed, Pending, Failed)
- Baseline compliance
- Software updates

---

## Future Enhancements

### Service Principal Authentication
**Priority:** Medium
**Status:** Planned

Currently Graph API requires interactive authentication. Add support for service principal (app registration) authentication for automated/scheduled scans.

### Multi-Device Batch Scanning
**Priority:** Low
**Status:** Planned

Add support for scanning multiple devices in a batch and generating a consolidated report.

### Export to Excel/CSV
**Priority:** Low
**Status:** Planned

Add export formats beyond JSON for easier sharing with non-technical stakeholders.
