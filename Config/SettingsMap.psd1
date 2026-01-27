@{
    BitLocker = @(
        @{
            GPOPathPattern = 'FVE\\EncryptionMethodWithXtsOs'
            GPODescription = 'Choose drive encryption method and cipher strength - OS Drive (XTS-AES)'
            MDMArea        = 'BitLocker'
            MDMSetting     = 'EncryptionMethodByDriveType'
            CSPURI         = './Device/Vendor/MSFT/BitLocker/EncryptionMethodByDriveType'
            Notes          = 'ADMX-backed; encodes all three drive types in one value'
        }
        @{
            GPOPathPattern = 'FVE\\EncryptionMethodWithXtsFdv'
            GPODescription = 'Choose drive encryption method - Fixed Data Drive (XTS-AES)'
            MDMArea        = 'BitLocker'
            MDMSetting     = 'EncryptionMethodByDriveType'
            CSPURI         = './Device/Vendor/MSFT/BitLocker/EncryptionMethodByDriveType'
            Notes          = 'Same CSP setting covers all drive types'
        }
        @{
            GPOPathPattern = 'FVE\\EncryptionMethodWithXtsRdv'
            GPODescription = 'Choose drive encryption method - Removable Data Drive (XTS-AES)'
            MDMArea        = 'BitLocker'
            MDMSetting     = 'EncryptionMethodByDriveType'
            CSPURI         = './Device/Vendor/MSFT/BitLocker/EncryptionMethodByDriveType'
            Notes          = 'Same CSP setting covers all drive types'
        }
        @{
            GPOPathPattern = 'FVE\\UseAdvancedStartup'
            GPODescription = 'Require additional authentication at startup'
            MDMArea        = 'BitLocker'
            MDMSetting     = 'SystemDrivesRequireStartupAuthentication'
            CSPURI         = './Device/Vendor/MSFT/BitLocker/SystemDrivesRequireStartupAuthentication'
            Notes          = ''
        }
        @{
            GPOPathPattern = 'FVE\\OSRecovery'
            GPODescription = 'Choose how BitLocker-protected OS drives can be recovered'
            MDMArea        = 'BitLocker'
            MDMSetting     = 'SystemDrivesRecoveryOptions'
            CSPURI         = './Device/Vendor/MSFT/BitLocker/SystemDrivesRecoveryOptions'
            Notes          = ''
        }
        @{
            GPOPathPattern = 'FVE\\FDVRecovery'
            GPODescription = 'Choose how BitLocker-protected fixed drives can be recovered'
            MDMArea        = 'BitLocker'
            MDMSetting     = 'FixedDrivesRecoveryOptions'
            CSPURI         = './Device/Vendor/MSFT/BitLocker/FixedDrivesRecoveryOptions'
            Notes          = ''
        }
        @{
            GPOPathPattern = 'FVE\\ActiveDirectoryBackup'
            GPODescription = 'Store BitLocker recovery information in AD DS'
            MDMArea        = 'BitLocker'
            MDMSetting     = 'SystemDrivesRecoveryOptions'
            CSPURI         = './Device/Vendor/MSFT/BitLocker/SystemDrivesRecoveryOptions'
            Notes          = 'Recovery backup target is part of the recovery options CSP'
        }
    )

    WindowsUpdate = @(
        @{
            GPOPathPattern = 'WindowsUpdate\\AU\\NoAutoUpdate'
            GPODescription = 'Configure Automatic Updates'
            MDMArea        = 'Update'
            MDMSetting     = 'AllowAutoUpdate'
            CSPURI         = './Device/Vendor/MSFT/Policy/Config/Update/AllowAutoUpdate'
            Notes          = 'Value mapping differs: GPO 0=enable auto, MDM 0-5 scale'
        }
        @{
            GPOPathPattern = 'WindowsUpdate\\AU\\AUOptions'
            GPODescription = 'Configure auto-update behavior (notify/download/install)'
            MDMArea        = 'Update'
            MDMSetting     = 'AllowAutoUpdate'
            CSPURI         = './Device/Vendor/MSFT/Policy/Config/Update/AllowAutoUpdate'
            Notes          = ''
        }
        @{
            GPOPathPattern = 'WindowsUpdate\\AU\\ScheduledInstallDay'
            GPODescription = 'Scheduled install day'
            MDMArea        = 'Update'
            MDMSetting     = 'ScheduledInstallDay'
            CSPURI         = './Device/Vendor/MSFT/Policy/Config/Update/ScheduledInstallDay'
            Notes          = ''
        }
        @{
            GPOPathPattern = 'WindowsUpdate\\AU\\ScheduledInstallTime'
            GPODescription = 'Scheduled install time'
            MDMArea        = 'Update'
            MDMSetting     = 'ScheduledInstallTime'
            CSPURI         = './Device/Vendor/MSFT/Policy/Config/Update/ScheduledInstallTime'
            Notes          = ''
        }
        @{
            GPOPathPattern = 'WindowsUpdate\\DeferFeatureUpdates'
            GPODescription = 'Defer feature updates'
            MDMArea        = 'Update'
            MDMSetting     = 'DeferFeatureUpdatesPeriodInDays'
            CSPURI         = './Device/Vendor/MSFT/Policy/Config/Update/DeferFeatureUpdatesPeriodInDays'
            Notes          = ''
        }
        @{
            GPOPathPattern = 'WindowsUpdate\\DeferQualityUpdates'
            GPODescription = 'Defer quality updates'
            MDMArea        = 'Update'
            MDMSetting     = 'DeferQualityUpdatesPeriodInDays'
            CSPURI         = './Device/Vendor/MSFT/Policy/Config/Update/DeferQualityUpdatesPeriodInDays'
            Notes          = ''
        }
        @{
            GPOPathPattern = 'WindowsUpdate\\WUServer'
            GPODescription = 'Specify intranet Microsoft update service location (WSUS)'
            MDMArea        = 'Update'
            MDMSetting     = 'UpdateServiceUrl'
            CSPURI         = './Device/Vendor/MSFT/Policy/Config/Update/UpdateServiceUrl'
            Notes          = 'WSUS URL - may not be needed in cloud-only'
        }
        @{
            GPOPathPattern = 'WindowsUpdate\\SetActiveHours'
            GPODescription = 'Turn off auto-restart during active hours'
            MDMArea        = 'Update'
            MDMSetting     = 'ActiveHoursStart'
            CSPURI         = './Device/Vendor/MSFT/Policy/Config/Update/ActiveHoursStart'
            Notes          = 'MDM uses separate ActiveHoursStart and ActiveHoursEnd'
        }
    )

    Firewall = @(
        @{
            GPOPathPattern = 'Windows Firewall\\DomainProfile\\EnableFirewall'
            GPODescription = 'Windows Firewall: Domain profile - Firewall state'
            MDMArea        = 'Firewall'
            MDMSetting     = 'MdmStore/DomainProfile/EnableFirewall'
            CSPURI         = './Vendor/MSFT/Firewall/MdmStore/DomainProfile/EnableFirewall'
            Notes          = 'Firewall CSP uses MdmStore path'
        }
        @{
            GPOPathPattern = 'Windows Firewall\\PrivateProfile\\EnableFirewall'
            GPODescription = 'Windows Firewall: Private profile - Firewall state'
            MDMArea        = 'Firewall'
            MDMSetting     = 'MdmStore/PrivateProfile/EnableFirewall'
            CSPURI         = './Vendor/MSFT/Firewall/MdmStore/PrivateProfile/EnableFirewall'
            Notes          = ''
        }
        @{
            GPOPathPattern = 'Windows Firewall\\PublicProfile\\EnableFirewall'
            GPODescription = 'Windows Firewall: Public profile - Firewall state'
            MDMArea        = 'Firewall'
            MDMSetting     = 'MdmStore/PublicProfile/EnableFirewall'
            CSPURI         = './Vendor/MSFT/Firewall/MdmStore/PublicProfile/EnableFirewall'
            Notes          = ''
        }
        @{
            GPOPathPattern = 'Windows Firewall\\DomainProfile\\DefaultInboundAction'
            GPODescription = 'Windows Firewall: Domain - Inbound connections'
            MDMArea        = 'Firewall'
            MDMSetting     = 'MdmStore/DomainProfile/DefaultInboundAction'
            CSPURI         = './Vendor/MSFT/Firewall/MdmStore/DomainProfile/DefaultInboundAction'
            Notes          = ''
        }
    )

    WindowsDefender = @(
        @{
            GPOPathPattern = 'Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring'
            GPODescription = 'Turn off real-time protection'
            MDMArea        = 'Defender'
            MDMSetting     = 'AllowRealtimeMonitoring'
            CSPURI         = './Device/Vendor/MSFT/Policy/Config/Defender/AllowRealtimeMonitoring'
            Notes          = 'Inverted logic: GPO Disable=1 maps to MDM Allow=0'
        }
        @{
            GPOPathPattern = 'Windows Defender\\Real-Time Protection\\DisableBehaviorMonitoring'
            GPODescription = 'Turn off behavior monitoring'
            MDMArea        = 'Defender'
            MDMSetting     = 'AllowBehaviorMonitoring'
            CSPURI         = './Device/Vendor/MSFT/Policy/Config/Defender/AllowBehaviorMonitoring'
            Notes          = 'Inverted logic'
        }
        @{
            GPOPathPattern = 'Windows Defender\\Scan\\ScheduleDay'
            GPODescription = 'Specify the day of the week to run a scheduled scan'
            MDMArea        = 'Defender'
            MDMSetting     = 'ScheduleScanDay'
            CSPURI         = './Device/Vendor/MSFT/Policy/Config/Defender/ScheduleScanDay'
            Notes          = ''
        }
        @{
            GPOPathPattern = 'Windows Defender\\Scan\\ScheduleTime'
            GPODescription = 'Specify the time of day to run a scheduled scan'
            MDMArea        = 'Defender'
            MDMSetting     = 'ScheduleScanTime'
            CSPURI         = './Device/Vendor/MSFT/Policy/Config/Defender/ScheduleScanTime'
            Notes          = ''
        }
        @{
            GPOPathPattern = 'Windows Defender\\Signature Updates\\SignatureUpdateInterval'
            GPODescription = 'Specify the interval to check for definition updates'
            MDMArea        = 'Defender'
            MDMSetting     = 'SignatureUpdateInterval'
            CSPURI         = './Device/Vendor/MSFT/Policy/Config/Defender/SignatureUpdateInterval'
            Notes          = ''
        }
        @{
            GPOPathPattern = 'Windows Defender\\Windows Defender Exploit Guard\\ASR\\ExploitGuard_ASR_Rules'
            GPODescription = 'Configure Attack Surface Reduction rules'
            MDMArea        = 'Defender'
            MDMSetting     = 'AttackSurfaceReductionRules'
            CSPURI         = './Device/Vendor/MSFT/Policy/Config/Defender/AttackSurfaceReductionRules'
            Notes          = 'ASR rule GUIDs and actions must match'
        }
    )

    RemoteDesktop = @(
        @{
            GPOPathPattern = 'Terminal Services\\fDenyTSConnections'
            GPODescription = 'Allow users to connect remotely by using Remote Desktop Services'
            MDMArea        = 'RemoteDesktopServices'
            MDMSetting     = 'AllowUsersToConnectRemotely'
            CSPURI         = './Device/Vendor/MSFT/Policy/Config/RemoteDesktopServices/AllowUsersToConnectRemotely'
            Notes          = 'Limited RDP CSP coverage compared to GPO'
        }
        @{
            GPOPathPattern = 'Terminal Services\\fAllowToGetHelp'
            GPODescription = 'Configure Remote Assistance'
            MDMArea        = 'RemoteAssistance'
            MDMSetting     = 'SolicitedRemoteAssistance'
            CSPURI         = './Device/Vendor/MSFT/Policy/Config/RemoteAssistance/SolicitedRemoteAssistance'
            Notes          = ''
        }
    )

    DeviceLock = @(
        @{
            GPOPathPattern = 'Policies\\.*MinimumPasswordLength'
            GPODescription = 'Minimum password length'
            MDMArea        = 'DeviceLock'
            MDMSetting     = 'MinDevicePasswordLength'
            CSPURI         = './Device/Vendor/MSFT/Policy/Config/DeviceLock/MinDevicePasswordLength'
            Notes          = ''
        }
        @{
            GPOPathPattern = 'Policies\\.*PasswordComplexity'
            GPODescription = 'Password must meet complexity requirements'
            MDMArea        = 'DeviceLock'
            MDMSetting     = 'MinDevicePasswordComplexCharacters'
            CSPURI         = './Device/Vendor/MSFT/Policy/Config/DeviceLock/MinDevicePasswordComplexCharacters'
            Notes          = 'GPO is boolean, MDM is character count'
        }
        @{
            GPOPathPattern = 'Policies\\.*MaximumPasswordAge'
            GPODescription = 'Maximum password age'
            MDMArea        = 'DeviceLock'
            MDMSetting     = 'DevicePasswordExpiration'
            CSPURI         = './Device/Vendor/MSFT/Policy/Config/DeviceLock/DevicePasswordExpiration'
            Notes          = ''
        }
        @{
            GPOPathPattern = 'Policies\\.*LockoutBadCount'
            GPODescription = 'Account lockout threshold'
            MDMArea        = 'DeviceLock'
            MDMSetting     = 'MaxDevicePasswordFailedAttempts'
            CSPURI         = './Device/Vendor/MSFT/Policy/Config/DeviceLock/MaxDevicePasswordFailedAttempts'
            Notes          = ''
        }
        @{
            GPOPathPattern = 'Policies\\.*InactivityTimeoutSecs'
            GPODescription = 'Interactive logon: Machine inactivity limit'
            MDMArea        = 'DeviceLock'
            MDMSetting     = 'MaxInactivityTimeDeviceLock'
            CSPURI         = './Device/Vendor/MSFT/Policy/Config/DeviceLock/MaxInactivityTimeDeviceLock'
            Notes          = 'GPO in seconds, MDM in minutes'
        }
    )

    Power = @(
        @{
            GPOPathPattern = 'Power\\PowerSettings\\.*ACSettingIndex'
            GPODescription = 'Power plan settings (plugged in)'
            MDMArea        = 'Power'
            MDMSetting     = 'DisplayOffTimeoutPluggedIn'
            CSPURI         = './Device/Vendor/MSFT/Policy/Config/Power/DisplayOffTimeoutPluggedIn'
            Notes          = 'Multiple GPO settings map to different Power CSP settings'
        }
        @{
            GPOPathPattern = 'Power\\PowerSettings\\.*DCSettingIndex'
            GPODescription = 'Power plan settings (on battery)'
            MDMArea        = 'Power'
            MDMSetting     = 'DisplayOffTimeoutOnBattery'
            CSPURI         = './Device/Vendor/MSFT/Policy/Config/Power/DisplayOffTimeoutOnBattery'
            Notes          = ''
        }
    )

    Edge = @(
        @{
            GPOPathPattern = 'Edge\\HomepageLocation'
            GPODescription = 'Configure the home page URL'
            MDMArea        = 'Browser'
            MDMSetting     = 'HomepageLocation'
            CSPURI         = './Device/Vendor/MSFT/Policy/Config/Browser/HomepageLocation'
            Notes          = 'Edge ADMX maps well to Browser CSP'
        }
        @{
            GPOPathPattern = 'Edge\\DefaultSearchProviderEnabled'
            GPODescription = 'Enable the default search provider'
            MDMArea        = 'Browser'
            MDMSetting     = 'DefaultSearchProviderEnabled'
            CSPURI         = './Device/Vendor/MSFT/Policy/Config/Browser/DefaultSearchProviderEnabled'
            Notes          = ''
        }
        @{
            GPOPathPattern = 'Edge\\SmartScreenEnabled'
            GPODescription = 'Configure Microsoft Defender SmartScreen'
            MDMArea        = 'Browser'
            MDMSetting     = 'AllowSmartScreen'
            CSPURI         = './Device/Vendor/MSFT/Policy/Config/Browser/AllowSmartScreen'
            Notes          = ''
        }
        @{
            GPOPathPattern = 'Edge\\PasswordManagerEnabled'
            GPODescription = 'Enable saving passwords to the password manager'
            MDMArea        = 'Browser'
            MDMSetting     = 'AllowPasswordManager'
            CSPURI         = './Device/Vendor/MSFT/Policy/Config/Browser/AllowPasswordManager'
            Notes          = ''
        }
    )

    WindowsHelloForBusiness = @(
        @{
            GPOPathPattern = 'PassportForWork\\.*\\Policies\\UsePassportForWork'
            GPODescription = 'Use Windows Hello for Business'
            MDMArea        = 'PassportForWork'
            MDMSetting     = 'UsePassportForWork'
            CSPURI         = './Device/Vendor/MSFT/PassportForWork/{TenantId}/Policies/UsePassportForWork'
            Notes          = 'Tenant-specific CSP path'
        }
        @{
            GPOPathPattern = 'PassportForWork\\.*\\Policies\\RequireSecurityDevice'
            GPODescription = 'Use a hardware security device (TPM)'
            MDMArea        = 'PassportForWork'
            MDMSetting     = 'RequireSecurityDevice'
            CSPURI         = './Device/Vendor/MSFT/PassportForWork/{TenantId}/Policies/RequireSecurityDevice'
            Notes          = ''
        }
        @{
            GPOPathPattern = 'PassportForWork\\.*\\Policies\\PINComplexity\\MinimumPINLength'
            GPODescription = 'Minimum PIN length'
            MDMArea        = 'PassportForWork'
            MDMSetting     = 'MinimumPINLength'
            CSPURI         = './Device/Vendor/MSFT/PassportForWork/{TenantId}/Policies/PINComplexity/MinimumPINLength'
            Notes          = ''
        }
    )

    NetworkAccess = @(
        @{
            GPOPathPattern = 'Lanman.*\\RequireSecuritySignature'
            GPODescription = 'Digitally sign communications (SMB signing)'
            MDMArea        = 'LanmanWorkstation'
            MDMSetting     = 'EnableInsecureGuestLogons'
            CSPURI         = './Device/Vendor/MSFT/Policy/Config/LanmanWorkstation/EnableInsecureGuestLogons'
            Notes          = 'Limited SMB CSP coverage; GPO has more granular signing controls'
        }
    )

    UserRightsAssignment = @(
        @{
            GPOPathPattern = 'Policies\\.*\\UserRights\\SeDenyNetworkLogonRight'
            GPODescription = 'Deny access to this computer from the network'
            MDMArea        = 'UserRights'
            MDMSetting     = 'DenyAccessFromNetwork'
            CSPURI         = './Device/Vendor/MSFT/Policy/Config/UserRights/DenyAccessFromNetwork'
            Notes          = 'User Rights CSP available via Settings Catalog'
        }
        @{
            GPOPathPattern = 'Policies\\.*\\UserRights\\SeRemoteInteractiveLogonRight'
            GPODescription = 'Allow log on through Remote Desktop Services'
            MDMArea        = 'UserRights'
            MDMSetting     = 'AllowLogOnThroughRemoteDesktop'
            CSPURI         = './Device/Vendor/MSFT/Policy/Config/UserRights/AllowLogOnThroughRemoteDesktop'
            Notes          = ''
        }
    )

    Audit = @(
        @{
            GPOPathPattern = 'Audit\\.*AccountLogon'
            GPODescription = 'Audit account logon events'
            MDMArea        = 'Audit'
            MDMSetting     = 'AccountLogon_AuditCredentialValidation'
            CSPURI         = './Device/Vendor/MSFT/Policy/Config/Audit/AccountLogon_AuditCredentialValidation'
            Notes          = 'MDM has more granular audit sub-categories'
        }
    )

    Connectivity = @(
        @{
            GPOPathPattern = 'Policies\\.*\\EnableAutoproxyResultCache'
            GPODescription = 'Proxy auto-configuration settings'
            MDMArea        = 'NetworkProxy'
            MDMSetting     = 'ProxySettingsPerUser'
            CSPURI         = './Device/Vendor/MSFT/NetworkProxy/ProxySettingsPerUser'
            Notes          = 'CSP uses NetworkProxy path, different structure from GPO'
        }
    )

    Delivery = @(
        @{
            GPOPathPattern = 'DeliveryOptimization\\DODownloadMode'
            GPODescription = 'Delivery Optimization download mode'
            MDMArea        = 'DeliveryOptimization'
            MDMSetting     = 'DODownloadMode'
            CSPURI         = './Device/Vendor/MSFT/Policy/Config/DeliveryOptimization/DODownloadMode'
            Notes          = 'Direct 1:1 mapping'
        }
    )

    Privacy = @(
        @{
            GPOPathPattern = 'DataCollection\\AllowTelemetry'
            GPODescription = 'Allow diagnostic data (telemetry level)'
            MDMArea        = 'System'
            MDMSetting     = 'AllowTelemetry'
            CSPURI         = './Device/Vendor/MSFT/Policy/Config/System/AllowTelemetry'
            Notes          = 'Direct 1:1 mapping'
        }
    )

    AppLocker = @(
        @{
            GPOPathPattern = 'Safer\\CodeIdentifiers'
            GPODescription = 'Software Restriction Policies / AppLocker rules'
            MDMArea        = 'ApplicationControl'
            MDMSetting     = 'Policies'
            CSPURI         = './Vendor/MSFT/ApplicationControl/Policies'
            Notes          = 'AppLocker XML rules can be deployed via CSP; significant migration effort'
        }
    )
}
