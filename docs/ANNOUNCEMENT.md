# PolicyLens

A tool I built to help answer: **"What's actually being applied to this device, and where is it coming from?"**

## What It Does

Run a PowerShell script on a Windows device and it collects:

- **Group Policy** - All applied GPOs and their registry-based settings (with source GPO attribution)
- **Intune/MDM** - Policies pushed via MDM enrollment
- **SCCM** - ConfigMgr apps, baselines, and updates
- **Azure AD Groups** - Which groups the device belongs to
- **Intune Assignments** - Which Intune policies and apps target this device based on group membership

Everything exports to a JSON file that you open in the included web viewer.

## Verification Features (v1.3)

PolicyLens doesn't just show what's *assigned* - it verifies what's actually *applied*:

- **GPO Verification** - Queries Active Directory to compare linked GPOs against applied GPOs (detects security filtering, disabled links)
- **Intune Verification** - Compares assigned profiles against device deployment status
- **SCCM Verification** - Queries site server to compare deployments against installed state

## What the Viewer Shows

- Summary of policy counts from each source
- GPO vs Intune overlap analysis (what's configured in both, what conflicts)
- Intune policies filtered to only those assigned to the scanned device
- Intune apps filtered the same way
- Azure AD group memberships (separated by Dynamic vs Assigned)
- Verification status for GPO, Intune, and SCCM deployments
- Side-by-side comparison when you load two device exports

## How to Run

```powershell
# Full scan with verification (default)
.\PolicyLens.ps1

# Skip Intune/Graph queries (local-only scan)
.\PolicyLens.ps1 -SkipIntune

# With SCCM deployment verification
.\PolicyLens.ps1 -SCCMCredential (Get-Credential)

# Find Intune equivalents for unmapped GPO settings
.\PolicyLens.ps1 -SuggestMappings
```

Requires admin rights for full results. Graph API features connect to Microsoft Graph (opens browser for auth).

---

Questions or feedback welcome.
