# PolicyLens Technical Debt

Code review completed: 2026-01-28

## Critical/High Priority

### No Graceful Degradation on Phase Failure
- **File:** `Public/Invoke-PolicyLens.ps1` lines 96-113
- **Issue:** If GPO collection fails (e.g., on non-domain-joined device), the entire scan stops instead of continuing with MDM/SCCM data
- **Fix:** Wrap each phase in try-catch, continue with partial results, report what failed

---

## Medium Priority

### Graph Module Check Incomplete
- **File:** `Public/Get-GraphPolicyData.ps1` lines 43-69
- **Issue:** Checks for `Microsoft.Graph` module with `-ListAvailable` but doesn't verify required submodules (`Microsoft.Graph.Authentication`, `Microsoft.Graph.DeviceManagement`)
- **Fix:** Check for specific submodules before attempting connection

### Duplicated Graph Connection Code
- **Files:** `Get-GraphPolicyData.ps1`, `Invoke-PolicyLens.ps1`, `Get-DeviceAppAssignments.ps1`, `Get-DeviceGroupMemberships.ps1`
- **Issue:** Same connection parameters and error handling repeated in multiple places
- **Fix:** Extract to `Private/Connect-PolicyLensGraph.ps1`

### Duplicated Pagination Code
- **File:** `Public/Get-GraphPolicyData.ps1` lines 78-82, 119-122, 157-160
- **Issue:** Nearly identical pagination loop repeated 5+ times across Graph functions
- **Fix:** Extract to `Private/Get-GraphApiPagedResults.ps1`

### Invoke-PolicyLens Too Large
- **File:** `Public/Invoke-PolicyLens.ps1` (404 lines)
- **Issue:** Single function handles elevation checking, phase orchestration, console output, error handling, JSON export, duration calculation
- **Fix:** Split into smaller functions:
  - `Invoke-PolicyLens` - parameter handling & orchestration (20 lines)
  - `Invoke-PolicyCollectionPhase` - data collection
  - `Invoke-PolicyAnalysisPhase` - overlap analysis
  - `Invoke-PolicyExportPhase` - JSON export

### Array += in Loops (Performance)
- **File:** `Public/Get-GraphPolicyData.ps1` lines 78-82
- **Issue:** Using `+=` to append to arrays in pagination loops creates new array each iteration (O(n²))
- **Fix:** Use `[System.Collections.Generic.List[object]]` and `.Add()`, or collect with `ForEach-Object` pipeline

### Slow Recursive Registry Scan
- **File:** `Public/Get-GPOPolicyData.ps1` line 125
- **Issue:** `Get-ChildItem -Recurse` on large registry hives can take 30+ seconds with no depth limit
- **Fix:** Add `-Depth` parameter or implement iterative enumeration with progress

### Missing Unified MDM Schema
- **File:** `Public/Get-MDMPolicyData.ps1`
- **Issue:** Returns three separate hashtables (DevicePolicies, UserPolicies, PolicyProviders) making cross-referencing harder
- **Fix:** Create unified policy object structure

### No Log Sanitization
- **File:** `Private/Write-PolicyLensLog.ps1` line 41
- **Issue:** No filter exists to prevent sensitive data from being written to log files
- **Fix:** Add sanitization for known sensitive patterns (tokens, credentials)

---

## Low Priority

### Unused Function
- **File:** `Private/Merge-PolicyData.ps1`
- **Issue:** Function exists but is never called from any public function
- **Fix:** Remove or implement usage

### Hardcoded Version
- **Files:** `Invoke-PolicyLens.ps1`, `ConvertTo-JsonExport.ps1`
- **Issue:** Version string hardcoded in multiple places (currently "1.3.0")
- **Fix:** Read from module manifest (`PolicyLens.psd1`) or create `Config/PolicyLens.config.psd1`

### Missing Inline Comments
- **File:** `Public/Compare-PolicyOverlap.ps1` lines 66-102
- **Issue:** Complex comparison logic has no comments explaining the algorithm
- **Fix:** Add inline comments explaining status determination

### Temp File Cleanup
- **File:** `Public/Get-MDMPolicyData.ps1` lines 146-161
- **Issue:** CAB file and extracted contents remain in `$env:TEMP` if script is interrupted
- **Fix:** Use try-finally or register cleanup with `Register-EngineEvent`

### Inconsistent Output Levels
- **File:** `Public/Get-DeviceGroupMemberships.ps1` lines 150-152
- **Issue:** Some messages use `Write-Warning`, others use `Write-Verbose` inconsistently
- **Fix:** Establish and document logging level conventions

### Magic Numbers in SCCM
- **File:** `Public/Get-SCCMPolicyData.ps1` lines 104-110, 135-161
- **Issue:** Numeric status codes (0, 1, 2) without explanation
- **Fix:** Add comments or use named constants

### Path Traversal Not Validated
- **File:** `Private/ConvertTo-JsonExport.ps1` line 110
- **Issue:** `OutputPath` parameter not validated for path traversal (`../../sensitive.json`)
- **Fix:** Validate path is within expected directory

### Missing -Quiet Parameter
- **File:** `Public/Invoke-PolicyLens.ps1`
- **Issue:** No way to suppress console output for automation scenarios
- **Fix:** Add `-Quiet` switch parameter

### Missing Graph Scopes in Help
- **File:** `Public/Invoke-PolicyLens.ps1`
- **Issue:** Function help doesn't document which Graph scopes are requested
- **Fix:** Add scopes list to `.NOTES` section

### Registry Path Assumptions
- **File:** `Public/Get-DeviceGroupMemberships.ps1` lines 45, 70
- **Issue:** Assumes specific registry paths exist without fallback for older Windows versions
- **Fix:** Add version checking or fallback paths

---

## Refactoring Recommendations

### 1. Extract Graph Helpers
Create private functions to consolidate Graph API logic:
```
Private/Connect-PolicyLensGraph.ps1    - Connection management
Private/Get-GraphApiPagedResults.ps1   - Pagination helper
```

### 2. Create Configuration File
Move hardcoded values to `Config/PolicyLens.config.psd1`:
```powershell
@{
    Version = '1.0.0'
    DefaultLogPath = "$env:LOCALAPPDATA\PolicyLens\PolicyLens.log"
    DefaultMDMDiagAreas = 'DeviceEnrollment;DeviceProvisioning;Autopilot'
}
```

### 3. Add Integration Tests
Create tests for edge cases:
- Non-domain-joined device
- No admin privileges
- No Graph module installed
- Graph auth fails
- Empty policy results

### 4. Schema Validation for SettingsMap
Add validation that regex patterns in `Config/SettingsMap.psd1` are valid before runtime comparison.

---

## Summary

| Priority | Count |
|----------|-------|
| Critical/High | 1 |
| Medium | 8 |
| Low | 10 |
| **Total** | **19** |
