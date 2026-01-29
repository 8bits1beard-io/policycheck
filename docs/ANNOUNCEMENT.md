# Introducing PolicyLens

We are pleased to announce **PolicyLens**, a new PowerShell diagnostic tool designed to simplify policy management and GPO-to-Intune migration planning.

## What It Does

PolicyLens scans Windows devices to collect and analyze policies from multiple sources:

- **Group Policy (GPO)** - Local and domain-applied policies
- **Intune/MDM** - Mobile Device Management policies and configurations
- **SCCM** - Configuration Manager policies

The tool identifies conflicts between GPO and Intune settings, shows which Intune policies and apps are assigned to a device through group membership, and exports results to JSON for review in the included web viewer.

## Key Benefits

- **Migration Planning** - Understand policy overlap before transitioning from GPO to Intune
- **Conflict Detection** - Identify settings configured in both GPO and Intune
- **Device Comparison** - Use the web viewer to compare policies across multiple devices
- **Safe to Run** - Read-only operation; no changes are made to the device

## How to Use

Run from an elevated PowerShell prompt on the target device:

```powershell
# Basic scan (GPO and local MDM policies)
.\PolicyLens.ps1

# Include Intune assignments via Microsoft Graph
.\PolicyLens.ps1 -IncludeGraph
```

Results are exported to JSON and can be viewed using the included web viewer in the Tools folder.

---

For questions or feedback, please reach out to the team.
