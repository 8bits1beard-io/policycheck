function Get-SettingsCatalogMappings {
    <#
    .SYNOPSIS
        Retrieves Intune Settings Catalog definitions via Microsoft Graph API.
    .DESCRIPTION
        Queries the Microsoft Graph API to retrieve all Settings Catalog setting definitions.
        Results are cached for the session to improve performance. Returns structured data
        that can be used to match GPO registry settings to their Intune equivalents.
    .PARAMETER GraphConnected
        Switch indicating that Connect-MgGraph has already been called.
        If not specified, the function will attempt to connect.
    .PARAMETER ForceRefresh
        Forces a fresh query even if cached data exists.
    .OUTPUTS
        Array of PSCustomObjects with Settings Catalog definitions including:
        - Id, DisplayName, Description
        - BaseUri, OffsetUri (CSP paths)
        - CategoryId, Keywords
        - AdmxId (if ADMX-backed)
    .EXAMPLE
        $catalog = Get-SettingsCatalogMappings -GraphConnected
        Returns all Settings Catalog definitions.
    #>
    [CmdletBinding()]
    param(
        [switch]$GraphConnected,
        [switch]$ForceRefresh
    )

    # Check for cached data
    if (-not $ForceRefresh -and $Script:SettingsCatalogCache) {
        $cacheAge = (Get-Date) - $Script:SettingsCatalogCacheTime
        if ($cacheAge.TotalMinutes -lt 15) {
            Write-Verbose "Using cached Settings Catalog data (age: $([math]::Round($cacheAge.TotalMinutes, 1)) minutes)"
            return $Script:SettingsCatalogCache
        }
    }

    # Ensure Graph connection
    if (-not $GraphConnected) {
        try {
            Write-Verbose "Connecting to Microsoft Graph..."
            Connect-MgGraph -Scopes 'DeviceManagementConfiguration.Read.All' -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Error "Failed to connect to Microsoft Graph: $_"
            return $null
        }
    }

    Write-Verbose "Querying Settings Catalog definitions from Graph API..."

    $allSettings = @()
    $uri = "https://graph.microsoft.com/beta/deviceManagement/configurationSettings"

    try {
        do {
            Write-Verbose "Fetching page: $uri"
            $response = Invoke-MgGraphRequest -Uri $uri -Method GET

            if ($response.value) {
                $allSettings += $response.value
                Write-Verbose "Retrieved $($response.value.Count) settings (total: $($allSettings.Count))"
            }

            # Get next page
            $uri = $response.'@odata.nextLink'

        } while ($uri)

        Write-Verbose "Total Settings Catalog definitions retrieved: $($allSettings.Count)"

        # Process and structure the data
        $processedSettings = $allSettings | ForEach-Object {
            $setting = $_

            # Detect if ADMX-backed
            $isAdmxBacked = $setting.id -match 'admx_' -or
                           ($setting.baseUri -and $setting.offsetUri -match 'ADMX_')

            # Extract ADMX ID if present
            $admxId = $null
            if ($isAdmxBacked) {
                if ($setting.id -match 'admx_(.+)') {
                    $admxId = $matches[1]
                }
            }

            # Build full CSP URI
            $fullCspUri = if ($setting.baseUri -and $setting.offsetUri) {
                "$($setting.baseUri)$($setting.offsetUri)"
            } elseif ($setting.offsetUri) {
                $setting.offsetUri
            } else {
                $null
            }

            [PSCustomObject]@{
                Id              = $setting.id
                DisplayName     = $setting.displayName
                Description     = $setting.description
                BaseUri         = $setting.baseUri
                OffsetUri       = $setting.offsetUri
                FullCspUri      = $fullCspUri
                CategoryId      = $setting.categoryId
                Keywords        = $setting.keywords
                IsAdmxBacked    = $isAdmxBacked
                AdmxId          = $admxId
                InfoUrls        = $setting.infoUrls
                Applicability   = $setting.applicability
            }
        }

        # Cache the results
        $Script:SettingsCatalogCache = $processedSettings
        $Script:SettingsCatalogCacheTime = Get-Date

        Write-Verbose "Settings Catalog data cached successfully"

        return $processedSettings
    }
    catch {
        Write-Error "Failed to query Settings Catalog: $_"
        return $null
    }
}
