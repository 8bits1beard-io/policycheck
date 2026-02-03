<#
.SYNOPSIS
    Test script to explore Settings Catalog mapping via Graph API.
.DESCRIPTION
    Connects to Microsoft Graph and queries the Settings Catalog to find
    potential mappings for GPO registry settings. This is a proof-of-concept
    to validate the approach before integrating into PolicyLens.
.PARAMETER TenantId
    Azure AD tenant ID for Graph authentication.
.PARAMETER GPOExportPath
    Path to a PolicyLens JSON export file to use for matching. If not provided,
    will just explore the Settings Catalog structure.
.PARAMETER SearchTerm
    Optional search term to filter Settings Catalog results.
.EXAMPLE
    .\Test-SettingsCatalogMapping.ps1
    Connects to Graph and explores Settings Catalog structure.
.EXAMPLE
    .\Test-SettingsCatalogMapping.ps1 -GPOExportPath .\PolicyLens_SERVER1.json
    Attempts to find Settings Catalog matches for GPO settings in the export.
.EXAMPLE
    .\Test-SettingsCatalogMapping.ps1 -SearchTerm "BitLocker"
    Searches Settings Catalog for BitLocker-related settings.
#>
[CmdletBinding()]
param(
    [string]$TenantId,
    [string]$GPOExportPath,
    [string]$SearchTerm
)

# Requires Microsoft.Graph module
$graphModule = Get-Module -ListAvailable Microsoft.Graph.DeviceManagement -ErrorAction SilentlyContinue
if (-not $graphModule) {
    Write-Error "Microsoft.Graph module not installed. Run: Install-Module Microsoft.Graph -Scope CurrentUser"
    exit 1
}

Write-Host "`n=== Settings Catalog Mapping Test ===" -ForegroundColor Cyan
Write-Host ""

# Connect to Graph
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
$connectParams = @{
    Scopes = @(
        'DeviceManagementConfiguration.Read.All'
    )
}
if ($TenantId) { $connectParams['TenantId'] = $TenantId }

try {
    Connect-MgGraph @connectParams -ErrorAction Stop | Out-Null
    Write-Host "Connected to Graph API" -ForegroundColor Green
}
catch {
    Write-Error "Failed to connect to Graph: $_"
    exit 1
}

try {
    # --- 1. Explore Settings Catalog Categories ---
    Write-Host "`n--- Settings Catalog Categories ---" -ForegroundColor Cyan

    $categoriesUri = "https://graph.microsoft.com/beta/deviceManagement/configurationCategories?`$top=100"
    $categoriesResponse = Invoke-MgGraphRequest -Uri $categoriesUri -Method GET -ErrorAction Stop

    $allCategories = @($categoriesResponse.value)
    while ($categoriesResponse.'@odata.nextLink') {
        $categoriesResponse = Invoke-MgGraphRequest -Uri $categoriesResponse.'@odata.nextLink' -Method GET
        $allCategories += $categoriesResponse.value
    }

    Write-Host "Found $($allCategories.Count) categories" -ForegroundColor Green

    # Show top-level categories
    $topCategories = $allCategories | Where-Object { -not $_.parentCategoryId } | Select-Object -First 20
    Write-Host "`nTop-level categories (first 20):"
    foreach ($cat in $topCategories) {
        Write-Host "  - $($cat.displayName) [$($cat.id)]" -ForegroundColor Gray
    }

    # --- 2. Explore Settings Catalog Settings ---
    Write-Host "`n--- Settings Catalog Settings ---" -ForegroundColor Cyan

    $settingsUri = "https://graph.microsoft.com/beta/deviceManagement/configurationSettings?`$top=100"
    if ($SearchTerm) {
        $settingsUri = "https://graph.microsoft.com/beta/deviceManagement/configurationSettings?`$filter=contains(displayName,'$SearchTerm') or contains(description,'$SearchTerm')&`$top=100"
    }

    $settingsResponse = Invoke-MgGraphRequest -Uri $settingsUri -Method GET -ErrorAction Stop

    $allSettings = @($settingsResponse.value)
    $pageCount = 1
    $maxPages = 10  # Limit pages for testing

    while ($settingsResponse.'@odata.nextLink' -and $pageCount -lt $maxPages) {
        $settingsResponse = Invoke-MgGraphRequest -Uri $settingsResponse.'@odata.nextLink' -Method GET
        $allSettings += $settingsResponse.value
        $pageCount++
    }

    Write-Host "Retrieved $($allSettings.Count) settings (limited to $maxPages pages for testing)" -ForegroundColor Green

    # Analyze settings structure
    Write-Host "`nSample settings structure:"
    $sampleSettings = $allSettings | Select-Object -First 5
    foreach ($setting in $sampleSettings) {
        Write-Host "`n  Setting: $($setting.displayName)" -ForegroundColor White
        Write-Host "    ID: $($setting.id)" -ForegroundColor Gray
        Write-Host "    Type: $($setting.'@odata.type')" -ForegroundColor Gray
        if ($setting.description) {
            $desc = if ($setting.description.Length -gt 100) { $setting.description.Substring(0,100) + "..." } else { $setting.description }
            Write-Host "    Description: $desc" -ForegroundColor Gray
        }
        # Look for CSP/OMA-URI info in the setting
        if ($setting.offsetUri) {
            Write-Host "    OffsetUri: $($setting.offsetUri)" -ForegroundColor Yellow
        }
        if ($setting.baseUri) {
            Write-Host "    BaseUri: $($setting.baseUri)" -ForegroundColor Yellow
        }
    }

    # --- 3. Look for settings with CSP/OMA-URI patterns ---
    Write-Host "`n--- Settings with OMA-URI/CSP Patterns ---" -ForegroundColor Cyan

    $settingsWithUri = $allSettings | Where-Object { $_.offsetUri -or $_.baseUri }
    Write-Host "Settings with URI info: $($settingsWithUri.Count)" -ForegroundColor Green

    # Group by base URI patterns
    $uriPatterns = @{}
    foreach ($setting in $settingsWithUri) {
        $uri = if ($setting.baseUri) { $setting.baseUri } else { $setting.offsetUri }
        $pattern = ($uri -split '/')[0..4] -join '/'
        if (-not $uriPatterns[$pattern]) {
            $uriPatterns[$pattern] = @()
        }
        $uriPatterns[$pattern] += $setting
    }

    Write-Host "`nURI patterns found:"
    foreach ($pattern in ($uriPatterns.Keys | Sort-Object | Select-Object -First 15)) {
        Write-Host "  $pattern ($($uriPatterns[$pattern].Count) settings)" -ForegroundColor Gray
    }

    # --- 4. If GPO export provided, attempt matching ---
    if ($GPOExportPath -and (Test-Path $GPOExportPath)) {
        Write-Host "`n--- Attempting GPO Matching ---" -ForegroundColor Cyan

        $export = Get-Content $GPOExportPath -Raw | ConvertFrom-Json
        $gpoSettings = $export.gpoData.RegistryPolicies

        Write-Host "GPO settings in export: $($gpoSettings.Count)" -ForegroundColor Green

        # Try to match GPO paths to Settings Catalog
        $matches = @()
        $noMatch = @()

        # Build searchable index of Settings Catalog
        $settingsIndex = @{}
        foreach ($setting in $allSettings) {
            # Index by keywords from display name
            $words = $setting.displayName -split '\s+' | Where-Object { $_.Length -gt 3 }
            foreach ($word in $words) {
                $key = $word.ToLower()
                if (-not $settingsIndex[$key]) {
                    $settingsIndex[$key] = @()
                }
                $settingsIndex[$key] += $setting
            }
        }

        # Sample matching attempt
        $sampleGPO = $gpoSettings | Select-Object -First 20

        foreach ($gpo in $sampleGPO) {
            # Extract keywords from GPO path
            $pathParts = $gpo.Path -split '\\' | Where-Object { $_ -and $_.Length -gt 3 }
            $valueName = $gpo.ValueName

            $potentialMatches = @()

            # Search by path parts
            foreach ($part in $pathParts) {
                $key = $part.ToLower()
                if ($settingsIndex[$key]) {
                    $potentialMatches += $settingsIndex[$key]
                }
            }

            # Search by value name
            $valueKey = $valueName.ToLower()
            if ($settingsIndex[$valueKey]) {
                $potentialMatches += $settingsIndex[$valueKey]
            }

            $potentialMatches = $potentialMatches | Select-Object -Unique

            if ($potentialMatches.Count -gt 0) {
                $matches += [PSCustomObject]@{
                    GPOPath = $gpo.Path
                    GPOValueName = $valueName
                    GPOValue = $gpo.Data
                    PotentialMatches = $potentialMatches.Count
                    TopMatch = $potentialMatches[0].displayName
                }
            }
            else {
                $noMatch += $gpo
            }
        }

        Write-Host "`nMatching results (sample of 20 GPO settings):"
        Write-Host "  Potential matches found: $($matches.Count)" -ForegroundColor Green
        Write-Host "  No matches: $($noMatch.Count)" -ForegroundColor Yellow

        if ($matches.Count -gt 0) {
            Write-Host "`nSample matches:"
            foreach ($m in ($matches | Select-Object -First 5)) {
                Write-Host "  GPO: $($m.GPOPath)\$($m.GPOValueName)" -ForegroundColor White
                Write-Host "    -> Potential: $($m.TopMatch) (+$($m.PotentialMatches - 1) more)" -ForegroundColor Green
            }
        }
    }

    # --- 5. Export findings for analysis ---
    $outputPath = Join-Path $PSScriptRoot "SettingsCatalog_Export_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"

    $exportData = @{
        ExportedAt = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        CategoriesCount = $allCategories.Count
        SettingsCount = $allSettings.Count
        Categories = $allCategories | Select-Object id, displayName, parentCategoryId, description
        SampleSettings = $allSettings | Select-Object -First 100 | ForEach-Object {
            @{
                id = $_.id
                displayName = $_.displayName
                description = $_.description
                offsetUri = $_.offsetUri
                baseUri = $_.baseUri
                odataType = $_.'@odata.type'
            }
        }
        UriPatterns = $uriPatterns.Keys | ForEach-Object {
            @{
                Pattern = $_
                Count = $uriPatterns[$_].Count
            }
        }
    }

    $exportData | ConvertTo-Json -Depth 10 | Out-File $outputPath -Encoding UTF8
    Write-Host "`nExported findings to: $outputPath" -ForegroundColor Cyan

}
finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    Write-Host "`nDisconnected from Graph" -ForegroundColor Gray
}

Write-Host "`n=== Test Complete ===" -ForegroundColor Cyan
Write-Host ""
