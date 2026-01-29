# PolicyLens

A tool I built to help answer: **"What's actually being applied to this device, and where is it coming from?"**

## What It Does

Run a PowerShell script on a Windows device and it collects:

- **Group Policy** - All applied GPOs and their registry-based settings
- **Intune/MDM** - Policies pushed via MDM enrollment
- **SCCM** - ConfigMgr apps, baselines, and updates
- **Azure AD Groups** - Which groups the device belongs to (with `-IncludeGraph`)
- **Intune Assignments** - Which Intune policies and apps target this device based on group membership

Everything exports to a JSON file that you open in the included web viewer.

## What the Viewer Shows

- Summary of policy counts from each source
- GPO vs Intune overlap analysis (what's configured in both, what conflicts)
- Intune policies filtered to only those assigned to the scanned device
- Intune apps filtered the same way
- Azure AD group memberships (separated by Dynamic vs Assigned)
- Side-by-side comparison when you load two device exports

## How to Run

```powershell
# Basic scan
.\PolicyLens.ps1

# Full scan with Intune assignments and group memberships
.\PolicyLens.ps1 -IncludeGraph
```

Requires admin rights for full results. The `-IncludeGraph` flag connects to Microsoft Graph (opens browser for auth).

## Coming Soon

**Settings Catalog Lookup** - Query Microsoft's Graph API to check if a GPO setting has an Intune equivalent, instead of relying only on our local mapping file. This will improve accuracy of the migration readiness analysis.

---

Questions or feedback welcome.
