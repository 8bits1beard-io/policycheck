@{
    RootModule        = 'PolicyCheck.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'a3e8f7c1-2d4b-4e6a-9f8c-1b3d5e7a9c2f'
    Author            = 'Joshua Walderbach'
    Description       = 'Scans a Windows device for applied Group Policy and Intune/MDM policies, analyzes overlap, and generates a migration-ready report.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Invoke-PolicyCheck'
        'Get-GPOPolicyData'
        'Get-MDMPolicyData'
        'Get-GraphPolicyData'
        'Get-DeviceAppAssignments'
        'Get-DeviceGroupMemberships'
        'Compare-PolicyOverlap'
    )
    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @()
    PrivateData        = @{
        PSData = @{
            Tags       = @('Intune', 'GPO', 'GroupPolicy', 'MDM', 'Migration', 'PolicyCheck')
            ProjectUri = ''
        }
    }
}
