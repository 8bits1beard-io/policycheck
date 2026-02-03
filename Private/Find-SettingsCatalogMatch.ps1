function Find-SettingsCatalogMatch {
    <#
    .SYNOPSIS
        Finds potential Settings Catalog matches for a GPO registry setting.
    .DESCRIPTION
        Uses multiple matching strategies to find Intune Settings Catalog items
        that correspond to a given GPO registry setting. Returns ranked matches
        with confidence scores and reasoning.
    .PARAMETER GPOSetting
        The GPO registry setting to match (PSCustomObject with Path, ValueName, Category).
    .PARAMETER CatalogSettings
        Array of Settings Catalog definitions from Get-SettingsCatalogMappings.
    .PARAMETER ExistingMappings
        Hashtable of existing static mappings from SettingsMap.psd1.
    .OUTPUTS
        Array of match objects with Setting, Confidence, Score, and Reasons.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$GPOSetting,

        [Parameter(Mandatory)]
        [array]$CatalogSettings,

        [hashtable]$ExistingMappings
    )

    # Phase 1: Check if already mapped in SettingsMap.psd1
    if ($ExistingMappings) {
        foreach ($category in $ExistingMappings.Keys) {
            foreach ($mapping in $ExistingMappings[$category]) {
                if ($GPOSetting.Path -match $mapping.GPOPathPattern) {
                    Write-Verbose "Found static mapping for: $($GPOSetting.Path)"
                    return @([PSCustomObject]@{
                        Setting = [PSCustomObject]@{
                            DisplayName = $mapping.MDMSetting
                            FullCspUri = $mapping.CSPURI
                            Category = $category
                        }
                        Confidence = 'High'
                        Score = 100
                        Strategies = @('StaticMapping')
                        Reasons = @("Pre-defined mapping in SettingsMap.psd1")
                    })
                }
            }
        }
    }

    # Phase 2: Multi-strategy matching
    $candidates = @()

    # Extract path components for matching
    $pathComponents = $GPOSetting.Path -split '\\' | Where-Object { $_ }

    # Strategy 1: CSP URI path matching
    foreach ($setting in $CatalogSettings) {
        if (-not $setting.FullCspUri) { continue }

        $score = 0
        $reasons = @()

        # Check for path component overlap
        foreach ($component in $pathComponents) {
            if ($setting.FullCspUri -match [regex]::Escape($component)) {
                $score += 20
                $reasons += "CSP URI contains path component: $component"
            }
        }

        # Check value name match
        if ($GPOSetting.ValueName -and $setting.FullCspUri -match [regex]::Escape($GPOSetting.ValueName)) {
            $score += 25
            $reasons += "CSP URI contains value name: $($GPOSetting.ValueName)"
        }

        # Check display name token overlap
        $gpoTokens = @($GPOSetting.ValueName, $pathComponents) | Where-Object { $_ } | ForEach-Object { $_.ToLower() }
        $settingTokens = ($setting.DisplayName -split '\s+' | ForEach-Object { $_.ToLower() })

        $matchedTokens = $gpoTokens | Where-Object { $token = $_; $settingTokens -contains $token }
        if ($matchedTokens) {
            $score += ($matchedTokens.Count * 10)
            $reasons += "Matched tokens: $($matchedTokens -join ', ')"
        }

        # Detect inverse polarity (Disable vs Allow)
        $gpoHasDisable = $GPOSetting.ValueName -match '(Disable|Deny|Prevent|Block)'
        $settingHasAllow = $setting.DisplayName -match '(Allow|Enable|Turn on)'
        if ($gpoHasDisable -and $settingHasAllow) {
            $score += 10
            $reasons += "Inverse polarity detected (GPO Disable → MDM Allow)"
        }

        # Add candidate if score meets threshold
        if ($score -ge 30) {
            $candidates += [PSCustomObject]@{
                Setting = $setting
                Score = [Math]::Min($score, 100)
                Strategies = @('CspUriMatch', 'SemanticMatch')
                Reasons = $reasons
            }
        }
    }

    # Phase 3: Aggregate duplicates and rank
    $grouped = @{}
    foreach ($candidate in $candidates) {
        $settingId = $candidate.Setting.Id
        if (-not $grouped.ContainsKey($settingId)) {
            $grouped[$settingId] = $candidate
        }
        else {
            # Combine scores and reasons
            $grouped[$settingId].Score += ($candidate.Score * 0.5) # Diminishing returns
            $grouped[$settingId].Reasons += $candidate.Reasons
        }
    }

    # Convert to array and assign confidence
    $rankedMatches = $grouped.Values | ForEach-Object {
        $confidence = if ($_.Score -ge 90) { 'High' }
                     elseif ($_.Score -ge 60) { 'Medium' }
                     elseif ($_.Score -ge 30) { 'Low' }
                     else { 'Insufficient' }

        $_.Confidence = $confidence
        $_
    } | Sort-Object Score -Descending | Select-Object -First 5

    return $rankedMatches
}
