function Get-AssignmentFilterDefinitions {
    <#
    .SYNOPSIS
        Queries Microsoft Graph API for Intune assignment filter definitions.
    .DESCRIPTION
        Retrieves all assignment filters configured in Intune. These filters can be
        applied to policy and app assignments to include or exclude devices based
        on device properties like OS version, manufacturer, or device name.
    .PARAMETER GraphConnected
        Indicates Graph is already connected (called from Invoke-PolicyLens).
    .OUTPUTS
        PSCustomObject with filter definitions keyed by filter ID for quick lookup.
    .EXAMPLE
        $filters = Get-AssignmentFilterDefinitions -GraphConnected
        $filters.Filters['filter-guid'].DisplayName  # Returns filter name
    .AUTHOR
        Joshua Walderbach
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [switch]$GraphConnected
    )

    Write-Verbose "Querying Microsoft Graph for assignment filter definitions..."

    if (-not $GraphConnected) {
        $context = Get-MgContext -ErrorAction SilentlyContinue
        if (-not $context) {
            Write-Warning "Not connected to Microsoft Graph. Call Connect-MgGraph first."
            return [PSCustomObject]@{
                Available   = $false
                Filters     = @{}
                CollectedAt = Get-Date
            }
        }
    }

    $filters = @{}

    try {
        $uri = 'https://graph.microsoft.com/beta/deviceManagement/assignmentFilters?$top=999'
        $response = Invoke-MgGraphRequest -Uri $uri -Method GET -ErrorAction Stop

        $allFilters = @($response.value)

        # Handle pagination
        while ($response.'@odata.nextLink') {
            $response = Invoke-MgGraphRequest -Uri $response.'@odata.nextLink' -Method GET -ErrorAction Stop
            $allFilters += $response.value
        }

        Write-Verbose "Retrieved $($allFilters.Count) assignment filters."

        foreach ($filter in $allFilters) {
            $filters[$filter.id] = [PSCustomObject]@{
                Id          = $filter.id
                DisplayName = $filter.displayName
                Description = $filter.description
                Platform    = $filter.platform
                Rule        = $filter.rule
                CreatedDateTime  = $filter.createdDateTime
                LastModified     = $filter.lastModifiedDateTime
            }
        }
    }
    catch {
        Write-Warning "Failed to retrieve assignment filters from Graph: $_"
    }

    [PSCustomObject]@{
        Available   = $true
        Filters     = $filters
        FilterCount = $filters.Count
        CollectedAt = Get-Date
    }
}
