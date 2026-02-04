function Parse-GPLink {
    <#
    .SYNOPSIS
        Parses the gPLink attribute from Active Directory.
    .DESCRIPTION
        Parses the gPLink attribute format used by Active Directory to store
        GPO link information. Each link is formatted as:
        [LDAP://cn={GUID},cn=policies,cn=system,DC=domain,DC=com;options]

        Options is a bitmask:
        - 0 = Link enabled, not enforced
        - 1 = Link disabled
        - 2 = Link enforced
        - 3 = Link disabled and enforced
    .PARAMETER GPLinkValue
        The raw gPLink attribute value from Active Directory.
    .PARAMETER LinkLocation
        The distinguished name of the container (OU/domain) where this gPLink is defined.
    .OUTPUTS
        Array of PSCustomObjects with GPO link details.
    .EXAMPLE
        Parse-GPLink -GPLinkValue $ou.Properties['gplink'][0] -LinkLocation $ou.Properties['distinguishedname'][0]
    .AUTHOR
        Joshua Walderbach
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$GPLinkValue,

        [Parameter(Mandatory)]
        [string]$LinkLocation
    )

    $links = @()

    if ([string]::IsNullOrWhiteSpace($GPLinkValue)) {
        return $links
    }

    # gPLink format: [LDAP://cn={GUID},cn=policies,cn=system,DC=...;options][LDAP://...;options]
    # Extract each [LDAP://...;options] block
    $pattern = '\[LDAP://([^;]+);(\d+)\]'
    $matches = [regex]::Matches($GPLinkValue, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

    foreach ($match in $matches) {
        $ldapPath = $match.Groups[1].Value
        $options = [int]$match.Groups[2].Value

        # Extract GUID from the LDAP path
        # Path format: cn={GUID},cn=policies,cn=system,DC=domain,DC=com
        $guidMatch = [regex]::Match($ldapPath, '\{([0-9A-Fa-f\-]+)\}')
        $gpoGuid = if ($guidMatch.Success) { "{$($guidMatch.Groups[1].Value)}" } else { '' }

        # Parse options bitmask
        $linkEnabled = ($options -band 1) -eq 0  # Bit 0: 1=disabled, 0=enabled
        $enforced = ($options -band 2) -ne 0     # Bit 1: 1=enforced

        $links += [PSCustomObject]@{
            GPOGuid      = $gpoGuid.ToUpper()
            LDAPPath     = "LDAP://$ldapPath"
            LinkLocation = $LinkLocation
            LinkEnabled  = $linkEnabled
            Enforced     = $enforced
            Options      = $options
        }
    }

    return $links
}
