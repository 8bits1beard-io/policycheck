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

    # Check if RSOP logging is disabled and temporarily enable if needed
    $rsopPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
    $rsopWasDisabled = $false
    $rsopValueName = 'RSoPLogging'

    try {
        $rsopValue = Get-ItemProperty -Path $rsopPath -Name $rsopValueName -ErrorAction SilentlyContinue
        if ($null -ne $rsopValue -and $rsopValue.$rsopValueName -eq 0) {
            $rsopWasDisabled = $true
            Write-Warning "RSOP logging is disabled by Group Policy. Temporarily enabling to collect GPO data..."
            Set-ItemProperty -Path $rsopPath -Name $rsopValueName -Value 1 -ErrorAction Stop
            Write-Verbose "RSOP logging temporarily enabled"

            # Run gpupdate to populate RSOP cache
            Write-Warning "Running gpupdate /force to populate RSOP cache..."
            $gpupdateProc = Start-Process -FilePath 'gpupdate.exe' -ArgumentList '/force' `
                -NoNewWindow -Wait -PassThru -ErrorAction SilentlyContinue
            if ($gpupdateProc.ExitCode -ne 0) {
                Write-Warning "gpupdate exited with code $($gpupdateProc.ExitCode)"
            }
        }
    }
    catch {
        Write-Warning "Could not enable RSOP logging: $_. GPO enumeration may be incomplete."
    }

    try {
        $proc = Start-Process -FilePath 'gpresult.exe' `
            -ArgumentList "/x `"$tempXml`" /f /scope:computer" `
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
        # Restore RSOP logging to disabled if we enabled it
        if ($rsopWasDisabled) {
            try {
                Set-ItemProperty -Path $rsopPath -Name $rsopValueName -Value 0 -ErrorAction Stop
                Write-Verbose "RSOP logging restored to disabled state"
            }
            catch {
                Write-Warning "Could not restore RSOP logging setting: $_"
            }
        }

        if (Test-Path $tempXml -ErrorAction SilentlyContinue) {
            Remove-Item $tempXml -Force -ErrorAction SilentlyContinue
        }
    }

    # --- 2. Get RSoP source attribution ---
    $rsopLookup = @{}
    try {
        $rsopLookup = Get-RSoPPolicySource
        Write-Verbose "Got RSoP source data for $($rsopLookup.Count) settings"
    }
    catch {
        Write-Verbose "Could not get RSoP source data: $_. Source GPO will be unknown for registry policies."
    }

    # --- 3. Enumerate registry-based policies ---
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

                    # Look up source GPO from RSoP data
                    # RSoP uses "Machine"/"User" scope and full registry path
                    $rsopScope = if ($regEntry.Scope -eq 'Computer') { 'Machine' } else { 'User' }
                    # RSoP registry key is like "SOFTWARE\Policies\Microsoft\..." (without HKEY_ prefix)
                    $rsopRegKey = $key.Name -replace '^HKEY_LOCAL_MACHINE\\', '' -replace '^HKEY_CURRENT_USER\\', ''
                    $rsopLookupKey = "$rsopScope|$rsopRegKey|$($_.Name)"
                    $sourceInfo = $rsopLookup[$rsopLookupKey]

                    $registryPolicies += [PSCustomObject]@{
                        Path      = $relativePath
                        ValueName = $_.Name
                        Data      = $_.Value
                        DataType  = $_.TypeNameOfValue -replace 'System\.', ''
                        Scope     = $regEntry.Scope
                        Category  = $category
                        FullPath  = $key.Name
                        SourceGPO = if ($sourceInfo) { $sourceInfo.SourceGPO } else { $null }
                        SourceOU  = if ($sourceInfo) { $sourceInfo.SOMID } else { $null }
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
