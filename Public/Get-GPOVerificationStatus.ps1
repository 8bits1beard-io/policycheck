function Get-GPOVerificationStatus {
    <#
    .SYNOPSIS
        Verifies GPO application status by comparing linked vs applied GPOs.
    .DESCRIPTION
        Queries Active Directory via LDAP to enumerate GPOs linked to the device's
        OU hierarchy, then compares against GPOs that actually applied (from gpresult).
        Returns verification states: applied, denied (security filtered), not-applied,
        or disabled (link disabled).

        This function requires the device to be domain-joined and have network access
        to a domain controller. If AD is unreachable, it returns partial data with warnings.
    .PARAMETER AppliedGPOs
        Array of applied GPO objects from Get-GPOPolicyData (ComputerGPOs + UserGPOs).
        Each object should have Name and Guid properties.
    .PARAMETER ComputerName
        Name of the computer to verify. Defaults to the local computer.
    .OUTPUTS
        PSCustomObject with verification status for each linked GPO.
    .EXAMPLE
        $gpoData = Get-GPOPolicyData
        $allApplied = @($gpoData.ComputerGPOs) + @($gpoData.UserGPOs)
        $verification = Get-GPOVerificationStatus -AppliedGPOs $allApplied
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]$AppliedGPOs,

        [string]$ComputerName = $env:COMPUTERNAME
    )

    Write-Verbose "Verifying GPO application status for $ComputerName..."

    # Initialize result object
    $result = [PSCustomObject]@{
        Available          = $false
        ADReachable        = $false
        DeviceFound        = $false
        DomainJoined       = $false
        DeviceDN           = $null
        LinkedGPOs         = @()
        VerificationStates = @()
        AppliedCount       = 0
        DeniedCount        = 0
        NotAppliedCount    = 0
        DisabledCount      = 0
        CollectedAt        = Get-Date
        Message            = $null
    }

    # Check if domain-joined
    try {
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        if (-not $computerSystem.PartOfDomain) {
            $result.Message = "Device is not domain-joined. GPO verification requires Active Directory."
            Write-Verbose $result.Message
            return $result
        }
        $result.DomainJoined = $true
    }
    catch {
        $result.Message = "Could not determine domain join status: $_"
        Write-Warning $result.Message
        return $result
    }

    # Build lookup of applied GPOs by GUID and name (normalized)
    $appliedByGuid = @{}
    $appliedByName = @{}
    foreach ($gpo in $AppliedGPOs) {
        if ($gpo.Guid) {
            $normalizedGuid = $gpo.Guid.Trim().ToUpper()
            if (-not $normalizedGuid.StartsWith('{')) {
                $normalizedGuid = "{$normalizedGuid}"
            }
            $appliedByGuid[$normalizedGuid] = $gpo
        }
        if ($gpo.Name) {
            $appliedByName[$gpo.Name.ToLower()] = $gpo
        }
    }

    # Try to connect to AD and find the computer object
    try {
        # Get the current domain
        $rootDSE = [ADSI]"LDAP://RootDSE"
        $defaultNC = $rootDSE.defaultNamingContext[0]
        $result.ADReachable = $true
        Write-Verbose "Connected to AD. Default naming context: $defaultNC"
    }
    catch {
        $result.Message = "Could not connect to Active Directory: $_"
        Write-Warning $result.Message
        return $result
    }

    # Find the computer object in AD
    try {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = [ADSI]"LDAP://$defaultNC"
        $searcher.Filter = "(&(objectClass=computer)(name=$ComputerName))"
        $searcher.PropertiesToLoad.AddRange(@('distinguishedName', 'name'))

        $computerObj = $searcher.FindOne()
        if (-not $computerObj) {
            $result.Message = "Computer '$ComputerName' not found in Active Directory."
            Write-Warning $result.Message
            return $result
        }

        $deviceDN = $computerObj.Properties['distinguishedname'][0]
        $result.DeviceFound = $true
        $result.DeviceDN = $deviceDN
        Write-Verbose "Found computer at: $deviceDN"
    }
    catch {
        $result.Message = "Error searching for computer in AD: $_"
        Write-Warning $result.Message
        return $result
    }

    # Walk up the OU hierarchy and collect all gPLink values
    $linkedGPOs = @()
    $gpoDisplayNames = @{}  # Cache GPO GUID -> Display Name

    try {
        # Start from the computer's parent container (the OU it's in)
        # Remove the computer's CN to get the parent OU
        $parentDN = ($deviceDN -split ',', 2)[1]

        # Build list of containers from computer's OU up to domain root
        $containerDNs = @()
        $currentDN = $parentDN

        while ($currentDN) {
            $containerDNs += $currentDN
            # Move up one level
            $parts = $currentDN -split ',', 2
            if ($parts.Count -gt 1) {
                $currentDN = $parts[1]
            }
            else {
                break
            }
        }

        Write-Verbose "Walking OU hierarchy: $($containerDNs.Count) containers to check"

        # Process containers from domain root down (reverse order for proper precedence)
        [array]::Reverse($containerDNs)

        foreach ($containerDN in $containerDNs) {
            try {
                $container = [ADSI]"LDAP://$containerDN"
                $gPLink = $container.Properties['gPLink']

                if ($gPLink -and $gPLink.Count -gt 0 -and $gPLink[0]) {
                    $parsedLinks = Parse-GPLink -GPLinkValue $gPLink[0] -LinkLocation $containerDN
                    $linkedGPOs += $parsedLinks
                    Write-Verbose "  $containerDN : $($parsedLinks.Count) GPOs linked"
                }
            }
            catch {
                Write-Verbose "  Could not read gPLink from $containerDN : $_"
            }
        }

        Write-Verbose "Total linked GPOs found: $($linkedGPOs.Count)"
    }
    catch {
        $result.Message = "Error walking OU hierarchy: $_"
        Write-Warning $result.Message
        # Continue with partial data
    }

    # Get display names for all linked GPOs
    foreach ($link in $linkedGPOs) {
        if ($link.GPOGuid -and -not $gpoDisplayNames.ContainsKey($link.GPOGuid)) {
            try {
                $gpoSearcher = New-Object System.DirectoryServices.DirectorySearcher
                $gpoSearcher.SearchRoot = [ADSI]"LDAP://CN=Policies,CN=System,$defaultNC"
                $gpoSearcher.Filter = "(&(objectClass=groupPolicyContainer)(name=$($link.GPOGuid)))"
                $gpoSearcher.PropertiesToLoad.AddRange(@('displayName', 'name'))

                $gpoObj = $gpoSearcher.FindOne()
                if ($gpoObj -and $gpoObj.Properties['displayname']) {
                    $gpoDisplayNames[$link.GPOGuid] = $gpoObj.Properties['displayname'][0]
                }
                else {
                    $gpoDisplayNames[$link.GPOGuid] = $link.GPOGuid
                }
            }
            catch {
                Write-Verbose "Could not get display name for GPO $($link.GPOGuid): $_"
                $gpoDisplayNames[$link.GPOGuid] = $link.GPOGuid
            }
        }
    }

    # Build verification states
    $verificationStates = @()
    $appliedCount = 0
    $deniedCount = 0
    $notAppliedCount = 0
    $disabledCount = 0

    foreach ($link in $linkedGPOs) {
        $gpoName = $gpoDisplayNames[$link.GPOGuid]
        $normalizedGuid = $link.GPOGuid.ToUpper()

        # Check if this GPO was applied
        $appliedGPO = $appliedByGuid[$normalizedGuid]
        if (-not $appliedGPO -and $gpoName) {
            $appliedGPO = $appliedByName[$gpoName.ToLower()]
        }

        # Determine status
        $status = 'not-applied'
        $statusLabel = 'Not Applicable'
        $scope = 'Computer'  # Default; we're checking computer policies

        if (-not $link.LinkEnabled) {
            $status = 'disabled'
            $statusLabel = 'Link Disabled'
            $disabledCount++
        }
        elseif ($appliedGPO) {
            # GPO was linked and applied
            if ($appliedGPO.AccessDenied) {
                $status = 'denied'
                $statusLabel = 'Security Filtered'
                $deniedCount++
            }
            else {
                $status = 'applied'
                $statusLabel = 'Applied'
                $appliedCount++
            }
            $scope = $appliedGPO.Scope
        }
        else {
            # GPO linked but not applied - check if it's security filtered
            # (We can infer this if link is enabled but GPO didn't apply)
            $status = 'denied'
            $statusLabel = 'Security Filtered'
            $deniedCount++
        }

        $verificationStates += [PSCustomObject]@{
            GPOName      = $gpoName
            GPOGuid      = $link.GPOGuid
            LinkLocation = $link.LinkLocation
            LinkEnabled  = $link.LinkEnabled
            Enforced     = $link.Enforced
            Status       = $status
            StatusLabel  = $statusLabel
            Scope        = $scope
        }
    }

    # Check for GPOs that applied but weren't in our linked list (e.g., user GPOs from user's OU)
    foreach ($gpo in $AppliedGPOs) {
        $normalizedGuid = if ($gpo.Guid) { $gpo.Guid.Trim().ToUpper() } else { '' }
        if (-not $normalizedGuid.StartsWith('{') -and $normalizedGuid) {
            $normalizedGuid = "{$normalizedGuid}"
        }

        $alreadyListed = $verificationStates | Where-Object { $_.GPOGuid -eq $normalizedGuid }
        if (-not $alreadyListed) {
            $verificationStates += [PSCustomObject]@{
                GPOName      = $gpo.Name
                GPOGuid      = $normalizedGuid
                LinkLocation = $gpo.LinkLocation
                LinkEnabled  = $true
                Enforced     = $false
                Status       = 'applied'
                StatusLabel  = 'Applied'
                Scope        = $gpo.Scope
            }
            $appliedCount++
        }
    }

    # Update result
    $result.Available = $true
    $result.LinkedGPOs = $linkedGPOs
    $result.VerificationStates = $verificationStates
    $result.AppliedCount = $appliedCount
    $result.DeniedCount = $deniedCount
    $result.NotAppliedCount = $notAppliedCount
    $result.DisabledCount = $disabledCount

    Write-Verbose "GPO verification complete: $appliedCount applied, $deniedCount filtered, $disabledCount disabled"

    return $result
}
