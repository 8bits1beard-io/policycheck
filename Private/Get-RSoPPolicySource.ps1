function Get-RSoPPolicySource {
    <#
    .SYNOPSIS
        Queries RSoP WMI to get source GPO information for registry policy settings.
    .DESCRIPTION
        Uses the Resultant Set of Policy (RSoP) WMI classes to build a lookup table
        that maps registry settings to their source GPO. This allows correlating
        each registry policy value with the GPO that configured it.
    .OUTPUTS
        Hashtable with keys in format "Scope|RegistryKey|ValueName" mapping to
        source GPO information including GPO name, GUID, and scope of management.
    .NOTES
        Requires Administrator privileges to query RSoP data.
        RSoP logging must be enabled (it is by default unless disabled by policy).
    .AUTHOR
        Joshua Walderbach
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    Write-Verbose "Querying RSoP WMI for GPO source attribution..."

    $rsopLookup = @{}

    # Process both Computer and User scopes
    $scopes = @(
        @{
            Scope = 'Machine'
            Namespace = 'root\rsop\computer'
        }
    )

    # Add user scope with current user's SID
    try {
        $userSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $userNamespace = "root\rsop\user\$($userSid -replace '-', '_')"
        $scopes += @{
            Scope = 'User'
            Namespace = $userNamespace
        }
    }
    catch {
        Write-Verbose "Could not determine current user SID: $_"
    }

    foreach ($scopeInfo in $scopes) {
        $scope = $scopeInfo.Scope
        $namespace = $scopeInfo.Namespace

        try {
            # First, build a GPO name lookup table from RSOP_GPO
            $gpoLookup = @{}

            $gpos = Get-CimInstance -Namespace $namespace -ClassName 'RSOP_GPO' -ErrorAction Stop
            foreach ($gpo in $gpos) {
                if ($gpo.id) {
                    $gpoLookup[$gpo.id] = @{
                        Name = $gpo.name
                        GuidName = $gpo.guidName
                        FileSystemPath = $gpo.fileSystemPath
                    }
                }
            }

            Write-Verbose "Found $($gpoLookup.Count) GPOs in $scope RSoP namespace"

            # Now get registry policy settings with their GPO attribution
            $regSettings = Get-CimInstance -Namespace $namespace -ClassName 'RSOP_RegistryPolicySetting' -ErrorAction Stop

            foreach ($setting in $regSettings) {
                # Only include winning policies (precedence = 1)
                if ($setting.precedence -ne 1) {
                    continue
                }

                $regKey = $setting.registryKey
                $valueName = $setting.valueName

                # Build the lookup key
                $lookupKey = "$scope|$regKey|$valueName"

                # Get GPO name from lookup table
                $gpoInfo = $gpoLookup[$setting.GPOID]
                $gpoName = if ($gpoInfo) {
                    $gpoInfo.Name
                }
                elseif ($setting.GPOID -eq 'LocalGPO') {
                    'Local Group Policy'
                }
                else {
                    'Unknown GPO'
                }

                $rsopLookup[$lookupKey] = @{
                    SourceGPO = $gpoName
                    GPOID = $setting.GPOID
                    GPOGuid = if ($gpoInfo) { $gpoInfo.GuidName } else { $null }
                    SOMID = $setting.SOMID
                    Precedence = $setting.precedence
                    CreationTime = $setting.creationTime
                }
            }

            Write-Verbose "Found $(@($regSettings | Where-Object { $_.precedence -eq 1 }).Count) winning registry settings in $scope RSoP"
        }
        catch [Microsoft.Management.Infrastructure.CimException] {
            if ($_.Exception.Message -match 'Invalid namespace') {
                Write-Verbose "RSoP namespace not available for $scope - this is normal if RSoP logging is disabled"
            }
            else {
                Write-Warning "Failed to query RSoP for $scope scope: $_"
            }
        }
        catch {
            Write-Warning "Failed to query RSoP for $scope scope: $_"
        }
    }

    Write-Verbose "Built RSoP lookup table with $($rsopLookup.Count) entries"

    return $rsopLookup
}
