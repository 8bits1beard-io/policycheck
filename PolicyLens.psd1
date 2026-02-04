@{
    RootModule        = 'PolicyLens.psm1'
    ModuleVersion     = '1.2.0'
    GUID              = 'a3e8f7c1-2d4b-4e6a-9f8c-1b3d5e7a9c2f'
    Author            = 'Joshua Walderbach'
    Description       = 'Scans a Windows device for applied Group Policy, Intune/MDM, and SCCM policies. Provides visibility into policy sources and helps plan GPO-to-Intune migration.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Invoke-PolicyLens'
        'Get-GPOPolicyData'
        'Get-MDMPolicyData'
        'Get-GraphPolicyData'
        'Get-DeviceAppAssignments'
        'Get-DeviceGroupMemberships'
        'Get-SettingsCatalogMappings'
        'Get-DeviceDeploymentStatus'
        'Get-GPOVerificationStatus'
        'Compare-PolicyOverlap'
        'Get-SCCMPolicyData'
    )
    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @()
    PrivateData        = @{
        PSData = @{
            Tags       = @('Intune', 'GPO', 'GroupPolicy', 'MDM', 'SCCM', 'Migration', 'PolicyLens')
            ProjectUri = ''
        }
    }
}
