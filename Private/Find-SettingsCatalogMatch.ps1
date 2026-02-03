function Find-SettingsCatalogMatch {
    <#
    .SYNOPSIS
        Finds potential Settings Catalog matches for a GPO registry setting.
    .DESCRIPTION
        Uses multiple matching strategies to find Intune Settings Catalog items
        that correspond to a given GPO registry setting. Returns ranked matches
        with confidence scores and reasoning.
    .PARAMETER GPOSetting
        The GPO registry setting to match. Supports both formats:
        - From DetailedResults: GPOPath, GPOValueName, Category
        - Direct: Path, ValueName, Category
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

    # Normalize property names (DetailedResults uses GPOPath/GPOValueName, but we support both)
    $gpoPath = if ($GPOSetting.PSObject.Properties['GPOPath']) { $GPOSetting.GPOPath } else { $GPOSetting.Path }
    $gpoValueName = if ($GPOSetting.PSObject.Properties['GPOValueName']) { $GPOSetting.GPOValueName } else { $GPOSetting.ValueName }
    $gpoCategory = $GPOSetting.Category

    # Phase 1: Check if already mapped in SettingsMap.psd1
    if ($ExistingMappings) {
        foreach ($category in $ExistingMappings.Keys) {
            foreach ($mapping in $ExistingMappings[$category]) {
                if ($gpoPath -match $mapping.GPOPathPattern) {
                    Write-Verbose "Found static mapping for: $gpoPath"
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

    # Extract and normalize path components for matching
    # Remove common non-meaningful prefixes
    $ignoreComponents = @('microsoft', 'windows', 'policies', 'software', 'currentversion', 'current', 'version')
    $pathComponents = $gpoPath -split '\\' | Where-Object { $_ } | ForEach-Object { $_.ToLower() } | Where-Object { $_ -notin $ignoreComponents }

    # Also split camelCase/PascalCase into separate words
    $expandedComponents = @()
    foreach ($component in $pathComponents) {
        # Split on camelCase boundaries: "WindowsUpdate" -> "windows", "update"
        $split = $component -creplace '([a-z])([A-Z])', '$1 $2' -split '\s+' | ForEach-Object { $_.ToLower() }
        $expandedComponents += $split
    }
    $expandedComponents = $expandedComponents | Select-Object -Unique

    # Also expand the value name
    $valueNameTokens = @()
    if ($gpoValueName) {
        $valueNameTokens = $gpoValueName -creplace '([a-z])([A-Z])', '$1 $2' -split '\s+' | ForEach-Object { $_.ToLower() } | Where-Object { $_ -notin $ignoreComponents }
    }

    # Combine all meaningful tokens
    $allGpoTokens = @($expandedComponents + $valueNameTokens) | Select-Object -Unique | Where-Object { $_.Length -ge 3 }

    foreach ($setting in $CatalogSettings) {
        $score = 0
        $reasons = @()

        # Strategy 1: ADMX ID matching (most reliable for ADMX-backed settings)
        if ($setting.IsAdmxBacked -and $setting.Id) {
            $admxIdLower = $setting.Id.ToLower()

            # Check if GPO tokens appear in the ADMX ID
            foreach ($token in $allGpoTokens) {
                if ($admxIdLower -match [regex]::Escape($token)) {
                    $score += 15
                    $reasons += "ADMX ID contains: $token"
                }
            }

            # Check value name specifically in ADMX ID (strong signal)
            if ($gpoValueName) {
                $valueNameLower = $gpoValueName.ToLower()
                if ($admxIdLower -match [regex]::Escape($valueNameLower)) {
                    $score += 25
                    $reasons += "ADMX ID contains value name: $gpoValueName"
                }
            }
        }

        # Strategy 2: Keywords matching
        if ($setting.Keywords -and $setting.Keywords.Count -gt 0) {
            $keywordsLower = $setting.Keywords | ForEach-Object { $_.ToLower() }
            foreach ($token in $allGpoTokens) {
                foreach ($keyword in $keywordsLower) {
                    if ($keyword -match [regex]::Escape($token) -or $token -match [regex]::Escape($keyword)) {
                        $score += 10
                        $reasons += "Keyword match: $token ~ $keyword"
                        break
                    }
                }
            }
        }

        # Strategy 3: Display name matching
        if ($setting.DisplayName) {
            $displayTokens = $setting.DisplayName -creplace '([a-z])([A-Z])', '$1 $2' -split '[\s\-_]+' | ForEach-Object { $_.ToLower() } | Where-Object { $_.Length -ge 3 -and $_ -notin $ignoreComponents }

            foreach ($gpoToken in $allGpoTokens) {
                foreach ($displayToken in $displayTokens) {
                    # Exact match
                    if ($gpoToken -eq $displayToken) {
                        $score += 12
                        $reasons += "Display name token match: $gpoToken"
                        break
                    }
                    # Partial match (one contains the other)
                    elseif ($gpoToken.Length -ge 4 -and $displayToken.Length -ge 4) {
                        if ($gpoToken -match [regex]::Escape($displayToken) -or $displayToken -match [regex]::Escape($gpoToken)) {
                            $score += 8
                            $reasons += "Display name partial match: $gpoToken ~ $displayToken"
                            break
                        }
                    }
                }
            }
        }

        # Strategy 4: CSP URI matching (less reliable but still useful)
        if ($setting.FullCspUri) {
            $cspLower = $setting.FullCspUri.ToLower()
            foreach ($token in $allGpoTokens) {
                if ($token.Length -ge 4 -and $cspLower -match [regex]::Escape($token)) {
                    $score += 8
                    $reasons += "CSP URI contains: $token"
                }
            }
        }

        # Strategy 5: Description matching (weak but can help)
        if ($setting.Description -and $setting.Description.Length -gt 0) {
            $descLower = $setting.Description.ToLower()
            foreach ($token in $allGpoTokens) {
                if ($token.Length -ge 5 -and $descLower -match "\b$([regex]::Escape($token))\b") {
                    $score += 5
                    $reasons += "Description contains: $token"
                }
            }
        }

        # Strategy 6: Inverse polarity detection (Disable/No vs Allow/Enable)
        if ($gpoValueName) {
            $gpoHasNegative = $gpoValueName -match '(Disable|Deny|Prevent|Block|No[A-Z])'
            $settingHasPositive = $setting.DisplayName -match '(Allow|Enable|Turn\s*on|Permit)'
            $gpoHasPositive = $gpoValueName -match '(Enable|Allow|Turn)'
            $settingHasNegative = $setting.DisplayName -match '(Disable|Block|Prevent|Deny)'

            if (($gpoHasNegative -and $settingHasPositive) -or ($gpoHasPositive -and $settingHasNegative)) {
                $score += 10
                $reasons += "Inverse polarity detected"
            }
        }

        # Add candidate if score meets threshold (lowered from 30 to 20)
        if ($score -ge 20) {
            $candidates += [PSCustomObject]@{
                Setting = $setting
                Score = [Math]::Min($score, 100)
                Strategies = @($reasons | ForEach-Object { ($_ -split ':')[0] } | Select-Object -Unique)
                Reasons = $reasons | Select-Object -Unique
            }
        }
    }

    # Phase 3: Deduplicate by setting ID and rank
    $grouped = @{}
    foreach ($candidate in $candidates) {
        $settingId = $candidate.Setting.Id
        if (-not $settingId) { continue }

        if (-not $grouped.ContainsKey($settingId)) {
            $grouped[$settingId] = $candidate
        }
        elseif ($candidate.Score -gt $grouped[$settingId].Score) {
            # Keep higher score
            $grouped[$settingId] = $candidate
        }
    }

    # Convert to array and assign confidence
    $rankedMatches = $grouped.Values | ForEach-Object {
        $confidence = if ($_.Score -ge 70) { 'High' }
                     elseif ($_.Score -ge 40) { 'Medium' }
                     elseif ($_.Score -ge 20) { 'Low' }
                     else { 'Insufficient' }

        [PSCustomObject]@{
            Setting = $_.Setting
            Confidence = $confidence
            Score = $_.Score
            Strategies = $_.Strategies
            Reasons = $_.Reasons
        }
    } | Sort-Object Score -Descending | Select-Object -First 5

    return $rankedMatches
}
