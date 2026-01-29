# PolicyLens TODO

## Future Enhancements

### Settings Catalog Lookup via Graph API
**Priority:** Medium
**Status:** Planned

Currently, when a GPO setting isn't found in our local `Config/SettingsMap.psd1`, the tool labels it as "No Mapping". This may be inaccurate - the setting might have an Intune equivalent that we just haven't mapped yet.

**Proposed solution:**
1. Query Microsoft Graph API endpoint: `deviceManagement/configurationPolicySettings/settingDefinitions`
2. Search the Settings Catalog definitions for potential matches when a GPO setting isn't in our local map
3. Change labeling:
   - "Matched" - Found in local map and confirmed
   - "No Mapping" - Confirmed no Intune equivalent exists
   - "Unknown" - Not in local map, couldn't determine from Graph API

**Graph endpoint:** `GET https://graph.microsoft.com/beta/deviceManagement/configurationPolicySettings/settingDefinitions`

**Files to modify:**
- `Public/Compare-PolicyOverlap.ps1` - Add Graph lookup logic
- `Tools/PolicyLensViewer.html` - Update status colors/labels for "Unknown"
