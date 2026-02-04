function Merge-PolicyData {
    <#
    .SYNOPSIS
        Normalizes and deduplicates policy data from multiple sources.
    .DESCRIPTION
        Combines GPO registry policies found via gpresult XML and direct registry
        enumeration, removing duplicates while preserving source information.
    .PARAMETER RegistryPolicies
        Array of registry policy objects from direct enumeration.
    .PARAMETER XmlPolicies
        Array of policy objects extracted from gpresult XML (if available).
    .OUTPUTS
        Deduplicated array of policy objects.
    .AUTHOR
        Joshua Walderbach
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [PSCustomObject[]]$RegistryPolicies,

        [AllowEmptyCollection()]
        [PSCustomObject[]]$XmlPolicies = @()
    )

    $merged = @{}

    # Registry policies take precedence (ground truth of what is actually applied)
    foreach ($pol in $RegistryPolicies) {
        $key = "$($pol.Path)\$($pol.ValueName)"
        if (-not $merged.ContainsKey($key)) {
            $merged[$key] = $pol
        }
    }

    # Add XML policies only if they weren't already found in registry
    foreach ($pol in $XmlPolicies) {
        $key = "$($pol.Path)\$($pol.ValueName)"
        if (-not $merged.ContainsKey($key)) {
            $merged[$key] = $pol
        }
    }

    @($merged.Values | Sort-Object Category, Path)
}
