function Get-GPOPolicyData {
    <#
    .SYNOPSIS
        Collects Group Policy data from the local device.
    .DESCRIPTION
        Runs gpresult to get applied GPOs and enumerates registry-based policy keys
        to build a complete picture of Group Policy settings on the device.
    .OUTPUTS
        PSCustomObject with ComputerGPOs, UserGPOs, RegistryPolicies, and metadata.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    Write-Verbose "Collecting Group Policy data..."

    # --- 1. Run gpresult /x to get RSoP XML ---
    $computerGpos = @()
    $userGpos = @()
    $gpresultXml = $null
    $tempXml = Join-Path $env:TEMP "PolicyLens_gpresult_$(Get-Random).xml"

    try {
        $proc = Start-Process -FilePath 'gpresult.exe' `
            -ArgumentList "/x `"$tempXml`" /f" `
            -NoNewWindow -Wait -PassThru -ErrorAction Stop

        if ($proc.ExitCode -eq 0 -and (Test-Path $tempXml)) {
            $gpresultXml = [xml](Get-Content $tempXml -Raw)

            # Parse computer GPOs
            $compResults = $gpresultXml.Rsop.ComputerResults
            if ($compResults) {
                $computerGpos = @($compResults.GPO | Where-Object { $_ } | ForEach-Object {
                    [PSCustomObject]@{
                        Name         = $_.Name
                        Guid         = if ($_.Path.Identifier) { $_.Path.Identifier.'#text' } else { '' }
                        LinkLocation = if ($_.Link.SOMPath) { $_.Link.SOMPath } else { '' }
                        LinkOrder    = if ($_.Link.SOMOrder) { [int]$_.Link.SOMOrder } else { 0 }
                        Scope        = 'Computer'
                        Enabled      = if ($_.Enabled -ne $null) { [bool]$_.Enabled } else { $true }
                        AccessDenied = if ($_.AccessDenied -ne $null) { [bool]$_.AccessDenied } else { $false }
                        SecurityFilter = if ($_.SecurityFilter) { $_.SecurityFilter } else { '' }
                    }
                })
            }

            # Parse user GPOs
            $userResults = $gpresultXml.Rsop.UserResults
            if ($userResults) {
                $userGpos = @($userResults.GPO | Where-Object { $_ } | ForEach-Object {
                    [PSCustomObject]@{
                        Name         = $_.Name
                        Guid         = if ($_.Path.Identifier) { $_.Path.Identifier.'#text' } else { '' }
                        LinkLocation = if ($_.Link.SOMPath) { $_.Link.SOMPath } else { '' }
                        LinkOrder    = if ($_.Link.SOMOrder) { [int]$_.Link.SOMOrder } else { 0 }
                        Scope        = 'User'
                        Enabled      = if ($_.Enabled -ne $null) { [bool]$_.Enabled } else { $true }
                        AccessDenied = if ($_.AccessDenied -ne $null) { [bool]$_.AccessDenied } else { $false }
                        SecurityFilter = if ($_.SecurityFilter) { $_.SecurityFilter } else { '' }
                    }
                })
            }
        }
        else {
            Write-Warning "gpresult exited with code $($proc.ExitCode). GPO XML data may be incomplete."
        }
    }
    catch {
        Write-Warning "Failed to run gpresult: $_"
        Write-Warning "This may occur on non-domain-joined devices. Registry policy scan will continue."
    }
    finally {
        if (Test-Path $tempXml -ErrorAction SilentlyContinue) {
            Remove-Item $tempXml -Force -ErrorAction SilentlyContinue
        }
    }

    # --- 2. Enumerate registry-based policies ---
    $categoryMap = @{
        'FVE'                                             = 'BitLocker'
        'WindowsUpdate'                                   = 'Windows Update'
        'Windows Defender'                                = 'Windows Defender'
        'Edge'                                            = 'Microsoft Edge'
        'MicrosoftEdge'                                   = 'Microsoft Edge'
        'Internet Settings'                               = 'Internet Explorer'
        'SystemCertificates'                              = 'Certificates'
        'Terminal Services'                               = 'Remote Desktop'
        'Safer'                                           = 'Software Restriction'
        'CodeIdentifiers'                                 = 'Software Restriction'
        'Netlogon'                                        = 'Network Authentication'
        'Windows Firewall'                                = 'Firewall'
        'Lanman'                                          = 'File Sharing'
        'PassportForWork'                                 = 'Windows Hello'
        'DataCollection'                                  = 'Privacy'
        'DeliveryOptimization'                            = 'Delivery Optimization'
        'Power'                                           = 'Power'
        'AppLocker'                                       = 'AppLocker'
        'Biometrics'                                      = 'Biometrics'
        'CloudContent'                                    = 'Cloud Content'
        'CredentialProviders'                             = 'Credential Providers'
        'DeviceGuard'                                     = 'Device Guard'
        'Lsa'                                             = 'Security'
        'EventLog'                                        = 'Event Log'
        'WindowsInkWorkspace'                             = 'Windows Ink'
        'DeviceInstall'                                   = 'Device Installation'
        'NetworkProvider'                                 = 'Network'
        'Sense'                                           = 'Defender ATP'
    }

    $registryPolicies = @()
    $registryPaths = @(
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft'; Scope = 'Computer' }
        @{ Path = 'HKCU:\SOFTWARE\Policies\Microsoft'; Scope = 'User' }
        @{ Path = 'HKLM:\SOFTWARE\Policies\Google'; Scope = 'Computer' }
        @{ Path = 'HKCU:\SOFTWARE\Policies\Google'; Scope = 'User' }
    )

    foreach ($regEntry in $registryPaths) {
        if (-not (Test-Path $regEntry.Path -ErrorAction SilentlyContinue)) {
            continue
        }

        try {
            $keys = Get-ChildItem $regEntry.Path -Recurse -ErrorAction SilentlyContinue

            foreach ($key in $keys) {
                $props = Get-ItemProperty $key.PSPath -ErrorAction SilentlyContinue
                if (-not $props) { continue }

                $props.PSObject.Properties | Where-Object {
                    $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Provider|Drive)$'
                } | ForEach-Object {
                    $relativePath = $key.Name -replace '^HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\', '' `
                                              -replace '^HKEY_CURRENT_USER\\SOFTWARE\\Policies\\', ''

                    # Determine category from path
                    $category = 'Other'
                    foreach ($pattern in $categoryMap.Keys) {
                        if ($relativePath -match [regex]::Escape($pattern)) {
                            $category = $categoryMap[$pattern]
                            break
                        }
                    }

                    $registryPolicies += [PSCustomObject]@{
                        Path      = $relativePath
                        ValueName = $_.Name
                        Data      = $_.Value
                        DataType  = $_.TypeNameOfValue -replace 'System\.', ''
                        Scope     = $regEntry.Scope
                        Category  = $category
                        FullPath  = $key.Name
                    }
                }
            }
        }
        catch {
            Write-Warning "Error reading registry at $($regEntry.Path): $_"
        }
    }

    [PSCustomObject]@{
        ComputerGPOs     = $computerGpos
        UserGPOs         = $userGpos
        RegistryPolicies = $registryPolicies
        TotalGPOCount    = $computerGpos.Count + $userGpos.Count
        CollectedAt      = Get-Date
        ComputerName     = $env:COMPUTERNAME
    }
}
