function Get-GraphPolicyData {
    <#
    .SYNOPSIS
        Queries Microsoft Graph API for Intune policy metadata.
    .DESCRIPTION
        Connects to Microsoft Graph and retrieves device configuration profiles,
        compliance policies, and Settings Catalog policies with their assignments.
    .PARAMETER TenantId
        Azure AD tenant ID for authentication.
    .PARAMETER GraphConnected
        Skip connecting/disconnecting from Graph (caller manages the connection).
    .OUTPUTS
        PSCustomObject with profiles, compliance policies, and settings catalog data.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [string]$TenantId,

        [switch]$GraphConnected
    )

    Write-Verbose "Querying Microsoft Graph API for Intune policy data..."

    # --- 1. Check for Microsoft.Graph module ---
    $graphModule = Get-Module -ListAvailable Microsoft.Graph.DeviceManagement -ErrorAction SilentlyContinue
    if (-not $graphModule) {
        Write-Warning @"
Microsoft.Graph.DeviceManagement module not found.
Install it with: Install-Module Microsoft.Graph -Scope CurrentUser
Then re-run with -IncludeGraph to fetch Intune policy details.
"@
        return [PSCustomObject]@{
            Available          = $false
            Profiles           = @()
            CompliancePolicies = @()
            SettingsCatalog    = @()
            CollectedAt        = Get-Date
        }
    }

    # --- 2. Connect to Graph (if not already connected) ---
    if (-not $GraphConnected) {
        try {
            $connectParams = @{
                Scopes = @(
                    'DeviceManagementConfiguration.Read.All'
                    'DeviceManagementManagedDevices.Read.All'
                )
            }
            if ($TenantId) {
                $connectParams['TenantId'] = $TenantId
            }

            Write-Host "  Connecting to Microsoft Graph (browser auth)..." -ForegroundColor Gray
            Connect-MgGraph @connectParams -ErrorAction Stop
            Write-Verbose "Connected to Microsoft Graph successfully."
        }
        catch {
            Write-Warning "Failed to connect to Microsoft Graph: $_"
            return [PSCustomObject]@{
                Available          = $false
                Profiles           = @()
                CompliancePolicies = @()
                SettingsCatalog    = @()
                CollectedAt        = Get-Date
            }
        }
    }

    # --- 3. Get device configuration profiles ---
    $profiles = @()
    try {
        $configs = Get-MgDeviceManagementDeviceConfiguration -All -ErrorAction Stop

        $profiles = @(foreach ($config in $configs) {
            # Get assignments for each profile
            $assignments = @()
            try {
                $assignments = @(Get-MgDeviceManagementDeviceConfigurationAssignment `
                    -DeviceConfigurationId $config.Id -ErrorAction SilentlyContinue |
                    ForEach-Object {
                        [PSCustomObject]@{
                            TargetType = $_.Target.AdditionalProperties.'@odata.type'
                            GroupId    = $_.Target.AdditionalProperties.groupId
                        }
                    })
            }
            catch {
                Write-Verbose "Could not get assignments for profile $($config.DisplayName): $_"
            }

            [PSCustomObject]@{
                Id              = $config.Id
                DisplayName     = $config.DisplayName
                Description     = $config.Description
                OdataType       = $config.AdditionalProperties.'@odata.type'
                CreatedDateTime = $config.CreatedDateTime
                LastModified    = $config.LastModifiedDateTime
                Assignments     = $assignments
            }
        })

        Write-Verbose "Retrieved $($profiles.Count) device configuration profiles."
    }
    catch {
        Write-Warning "Failed to retrieve device configuration profiles: $_"
    }

    # --- 4. Get compliance policies ---
    $compliancePolicies = @()
    try {
        $compliancePolicies = @(Get-MgDeviceManagementDeviceCompliancePolicy -All -ErrorAction Stop |
            ForEach-Object {
                $assignments = @()
                try {
                    $assignments = @(Get-MgDeviceManagementDeviceCompliancePolicyAssignment `
                        -DeviceCompliancePolicyId $_.Id -ErrorAction SilentlyContinue |
                        ForEach-Object {
                            [PSCustomObject]@{
                                TargetType = $_.Target.AdditionalProperties.'@odata.type'
                                GroupId    = $_.Target.AdditionalProperties.groupId
                            }
                        })
                }
                catch {
                    Write-Verbose "Could not get compliance policy assignments: $_"
                }

                [PSCustomObject]@{
                    Id          = $_.Id
                    DisplayName = $_.DisplayName
                    Description = $_.Description
                    OdataType   = $_.AdditionalProperties.'@odata.type'
                    Assignments = $assignments
                }
            })

        Write-Verbose "Retrieved $($compliancePolicies.Count) compliance policies."
    }
    catch {
        Write-Warning "Failed to retrieve compliance policies: $_"
    }

    # --- 5. Get Settings Catalog policies (beta endpoint) ---
    $settingsCatalog = @()
    try {
        $uri = 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?$top=999'
        $response = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop

        $settingsCatalog = @($response.value | ForEach-Object {
            # Get assignments
            $assignments = @()
            try {
                $assignUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$($_.id)/assignments"
                $assignResponse = Invoke-MgGraphRequest -Uri $assignUri -Method GET -ErrorAction SilentlyContinue
                $assignments = @($assignResponse.value | ForEach-Object {
                    [PSCustomObject]@{
                        TargetType = $_.target.'@odata.type'
                        GroupId    = $_.target.groupId
                    }
                })
            }
            catch {
                Write-Verbose "Could not get Settings Catalog assignments: $_"
            }

            [PSCustomObject]@{
                Id           = $_.id
                Name         = $_.name
                Description  = $_.description
                Platforms    = $_.platforms
                Technologies = $_.technologies
                Assignments  = $assignments
            }
        })

        Write-Verbose "Retrieved $($settingsCatalog.Count) Settings Catalog policies."
    }
    catch {
        Write-Verbose "Could not retrieve Settings Catalog policies (beta): $_"
    }

    # --- 6. Disconnect (only if we connected) ---
    if (-not $GraphConnected) {
        try {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        }
        catch { }
    }

    [PSCustomObject]@{
        Available          = $true
        Profiles           = $profiles
        CompliancePolicies = $compliancePolicies
        SettingsCatalog    = $settingsCatalog
        CollectedAt        = Get-Date
    }
}
