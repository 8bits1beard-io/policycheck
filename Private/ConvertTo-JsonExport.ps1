function ConvertTo-JsonExport {
    <#
    .SYNOPSIS
        Converts PolicyLens results to a structured JSON export file.

    .DESCRIPTION
        This function takes the output from Invoke-PolicyLens and exports it to a JSON file
        with a standardized schema. The export includes device metadata, all policy data sections,
        and analysis results. Device information is collected automatically including computer name,
        OS version, and domain/Azure AD join status, unless pre-collected metadata is provided
        (for remote scan scenarios).

    .PARAMETER Result
        The PSCustomObject returned from Invoke-PolicyLens containing policy scan results.
        This object should contain gpoData, mdmData, graphData, appData, groupData, and analysis properties.

    .PARAMETER OutputPath
        The file path where the JSON export will be written. The path can be relative or absolute.
        Parent directories must exist.

    .PARAMETER DeviceMetadata
        Optional hashtable containing pre-collected device metadata from a remote scan.
        When provided, this metadata is used instead of collecting from the local machine.
        Expected keys: ComputerName, OSVersion, OSBuild, DomainJoined, AzureADJoined, HybridJoined

    .OUTPUTS
        System.String
        Returns the resolved absolute path to the created JSON file.

    .EXAMPLE
        $result = Invoke-PolicyLens -IncludeGPO -IncludeMDM
        $exportPath = ConvertTo-JsonExport -Result $result -OutputPath "C:\Reports\policy-export.json"

        Exports the policy check results to a JSON file and returns the full path.

    .EXAMPLE
        Invoke-PolicyLens -All | ConvertTo-JsonExport -OutputPath ".\export.json"

        Pipes policy check results directly to the export function.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSCustomObject]$Result,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath,

        [hashtable]$DeviceMetadata
    )

    process {
        Write-Verbose "Collecting device metadata..."

        # Use provided metadata (remote scan) or collect locally
        if ($DeviceMetadata) {
            Write-Verbose "Using pre-collected device metadata from remote scan"
            $deviceInfo = [ordered]@{
                computerName   = $DeviceMetadata.ComputerName
                osVersion      = $DeviceMetadata.OSVersion
                osBuild        = $DeviceMetadata.OSBuild
                domainJoined   = $DeviceMetadata.DomainJoined
                azureADJoined  = $DeviceMetadata.AzureADJoined
                hybridJoined   = $DeviceMetadata.HybridJoined
            }
        }
        else {
            # Local collection
            # Get computer name
            $computerName = $env:COMPUTERNAME

            # Get OS information
            $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
            $osVersion = if ($osInfo) { "$($osInfo.Caption) $($osInfo.Version)" } else { "Unknown" }
            $osBuild = if ($osInfo) { $osInfo.BuildNumber } else { "Unknown" }

            # Get domain join status
            $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
            $domainJoined = if ($computerSystem) { $computerSystem.PartOfDomain } else { $false }

            # Get Azure AD join status from registry
            $azureADJoined = $false
            $hybridJoined = $false

            $joinInfoPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
            if (Test-Path -Path $joinInfoPath) {
                $joinInfoKeys = Get-ChildItem -Path $joinInfoPath -ErrorAction SilentlyContinue
                if ($joinInfoKeys) {
                    $azureADJoined = $true
                    # If both domain joined and Azure AD joined, it's hybrid
                    $hybridJoined = $domainJoined -and $azureADJoined
                }
            }

            # Build the device metadata object
            $deviceInfo = [ordered]@{
                computerName   = $computerName
                osVersion      = $osVersion
                osBuild        = $osBuild
                domainJoined   = $domainJoined
                azureADJoined  = $azureADJoined
                hybridJoined   = $hybridJoined
            }
        }

        Write-Verbose "Building export structure..."

        # Build the complete export object
        $exportObject = [ordered]@{
            schemaVersion = "1.0"
            exportedAt    = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            exportedBy    = "PolicyLens v1.0.0"
            device        = $deviceInfo
            gpoData       = if ($Result.PSObject.Properties['GPOData']) { $Result.GPOData } else { $null }
            mdmData       = if ($Result.PSObject.Properties['MDMData']) { $Result.MDMData } else { $null }
            sccmData      = if ($Result.PSObject.Properties['SCCMData']) { $Result.SCCMData } else { $null }
            graphData     = if ($Result.PSObject.Properties['GraphData']) { $Result.GraphData } else { $null }
            appData       = if ($Result.PSObject.Properties['AppData']) { $Result.AppData } else { $null }
            groupData     = if ($Result.PSObject.Properties['GroupData']) { $Result.GroupData } else { $null }
            analysis      = if ($Result.PSObject.Properties['Analysis']) { $Result.Analysis } else { $null }
            mappingSuggestions = if ($Result.PSObject.Properties['MappingSuggestions']) { $Result.MappingSuggestions } else { $null }
        }

        Write-Verbose "Converting to JSON with depth 15..."

        # Convert to JSON with sufficient depth for nested objects
        $jsonContent = $exportObject | ConvertTo-Json -Depth 15

        Write-Verbose "Writing JSON to: $OutputPath"

        # Write the JSON content to the output file
        $jsonContent | Out-File -FilePath $OutputPath -Encoding UTF8 -Force

        # Resolve and return the full path
        $resolvedPath = Resolve-Path -Path $OutputPath | Select-Object -ExpandProperty Path

        Write-Verbose "Export completed: $resolvedPath"

        return $resolvedPath
    }
}
