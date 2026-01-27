function Compare-PolicyOverlap {
    <#
    .SYNOPSIS
        Analyzes overlap between GPO and MDM/Intune policies.
    .DESCRIPTION
        Cross-references Group Policy registry settings against MDM PolicyManager
        settings using the SettingsMap configuration file. Identifies settings that
        are configured in both, GPO-only, or MDM-only.
    .PARAMETER GPOData
        Output from Get-GPOPolicyData.
    .PARAMETER MDMData
        Output from Get-MDMPolicyData.
    .PARAMETER GraphData
        Optional output from Get-GraphPolicyData.
    .OUTPUTS
        PSCustomObject with DetailedResults, MDMOnlyPolicies, and Summary.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$GPOData,

        [Parameter(Mandatory)]
        [PSCustomObject]$MDMData,

        [PSCustomObject]$GraphData
    )

    Write-Verbose "Analyzing policy overlap..."

    # --- 1. Load the settings map ---
    $mapPath = Join-Path $PSScriptRoot '..\Config\SettingsMap.psd1'
    $settingsMap = @{}

    if (Test-Path $mapPath) {
        try {
            $settingsMap = Import-PowerShellDataFile $mapPath
            Write-Verbose "Loaded settings map with $($settingsMap.Keys.Count) categories."
        }
        catch {
            Write-Warning "Failed to load SettingsMap.psd1: $_"
        }
    }
    else {
        Write-Warning "SettingsMap.psd1 not found at: $mapPath"
    }

    # Flatten the map for easier lookup
    $flatMap = @()
    foreach ($category in $settingsMap.Keys) {
        foreach ($entry in $settingsMap[$category]) {
            $flatMap += [PSCustomObject]@{
                Category       = $category
                GPOPathPattern = $entry.GPOPathPattern
                GPODescription = $entry.GPODescription
                MDMArea        = $entry.MDMArea
                MDMSetting     = $entry.MDMSetting
                CSPURI         = $entry.CSPURI
                Notes          = $entry.Notes
            }
        }
    }

    # --- 2. Cross-reference GPO registry policies against MDM ---
    $detailedResults = @()
    $matchedMDMKeys = @()  # Track which MDM settings have been matched

    foreach ($gpoPol in $GPOData.RegistryPolicies) {
        # Find matching map entry
        $mapMatch = $null
        foreach ($entry in $flatMap) {
            if ($gpoPol.Path -match $entry.GPOPathPattern) {
                $mapMatch = $entry
                break
            }
        }

        $mdmMatch = $null
        $status = 'GPOOnly_NoMapping'

        if ($mapMatch) {
            # Look for matching MDM policy
            $mdmMatch = $MDMData.DevicePolicies | Where-Object {
                $_.Area -eq $mapMatch.MDMArea -and $_.Setting -eq $mapMatch.MDMSetting
            } | Select-Object -First 1

            if (-not $mdmMatch) {
                # Also check user policies
                $mdmMatch = $MDMData.UserPolicies | Where-Object {
                    $_.Area -eq $mapMatch.MDMArea -and $_.Setting -eq $mapMatch.MDMSetting
                } | Select-Object -First 1
            }

            if ($mdmMatch) {
                $status = 'BothConfigured'
                $matchedMDMKeys += "$($mdmMatch.Area)/$($mdmMatch.Setting)"
            }
            else {
                $status = 'GPOOnly_MappingExists'
            }
        }

        $valuesMatch = $null
        if ($mdmMatch) {
            # Simple comparison - may need type coercion in real scenarios
            $valuesMatch = ("$($gpoPol.Data)" -eq "$($mdmMatch.Value)")
        }

        $detailedResults += [PSCustomObject]@{
            Category        = if ($mapMatch) { $mapMatch.Category } else { $gpoPol.Category }
            GPOPath         = $gpoPol.Path
            GPOValueName    = $gpoPol.ValueName
            GPOValue        = $gpoPol.Data
            GPOScope        = $gpoPol.Scope
            MDMArea         = if ($mapMatch) { $mapMatch.MDMArea } else { $null }
            MDMSetting      = if ($mapMatch) { $mapMatch.MDMSetting } else { $null }
            MDMValue        = if ($mdmMatch) { $mdmMatch.Value } else { $null }
            CSPURI          = if ($mapMatch) { $mapMatch.CSPURI } else { $null }
            Status          = $status
            ValuesMatch     = $valuesMatch
            MappingNotes    = if ($mapMatch) { $mapMatch.Notes } else { $null }
            GPODescription  = if ($mapMatch) { $mapMatch.GPODescription } else { $null }
        }
    }

    # --- 3. Identify MDM-only policies (not matched to any GPO) ---
    $mdmOnlyPolicies = @()
    $allMDMPolicies = @($MDMData.DevicePolicies) + @($MDMData.UserPolicies)

    foreach ($mdmPol in $allMDMPolicies) {
        $key = "$($mdmPol.Area)/$($mdmPol.Setting)"
        if ($key -notin $matchedMDMKeys) {
            $mdmOnlyPolicies += $mdmPol
        }
    }

    # --- 4. Enrich with Graph profile names if available ---
    if ($GraphData -and $GraphData.Available -and $GraphData.Profiles.Count -gt 0) {
        Write-Verbose "Enriching results with Graph profile data..."
        # This is a best-effort enrichment: map CSP areas to known profile types
        # Full mapping would require reading each profile's settings, which is expensive
    }

    # --- 5. Build summary ---
    $bothConfigured = @($detailedResults | Where-Object Status -eq 'BothConfigured')
    $gpoOnlyMapping = @($detailedResults | Where-Object Status -eq 'GPOOnly_MappingExists')
    $gpoOnlyNoMap   = @($detailedResults | Where-Object Status -eq 'GPOOnly_NoMapping')
    $conflicts      = @($detailedResults | Where-Object { $_.Status -eq 'BothConfigured' -and $_.ValuesMatch -eq $false })

    $summary = [PSCustomObject]@{
        TotalGPOSettings       = $GPOData.RegistryPolicies.Count
        TotalMDMSettings       = $MDMData.DevicePolicies.Count + $MDMData.UserPolicies.Count
        TotalGPOs              = $GPOData.TotalGPOCount
        BothConfigured         = $bothConfigured.Count
        BothConfiguredMatch    = ($bothConfigured | Where-Object ValuesMatch -eq $true).Count
        GPOOnlyWithMapping     = $gpoOnlyMapping.Count
        GPOOnlyNoMapping       = $gpoOnlyNoMap.Count
        MDMOnlySettings        = $mdmOnlyPolicies.Count
        ValuesInConflict       = $conflicts.Count
        CategoriesCovered      = @($detailedResults | Select-Object -ExpandProperty Category -Unique)
    }

    [PSCustomObject]@{
        DetailedResults  = $detailedResults
        MDMOnlyPolicies  = $mdmOnlyPolicies
        Summary          = $summary
    }
}
