function Get-MDMPolicyData {
    <#
    .SYNOPSIS
        Collects MDM/Intune policy data from the local device.
    .DESCRIPTION
        Checks MDM enrollment status, reads applied MDM policies from PolicyManager
        registry keys, and optionally runs mdmdiagnosticstool for detailed diagnostics.
    .PARAMETER SkipMDMDiag
        Skip running mdmdiagnosticstool (can be slow on some devices).
    .OUTPUTS
        PSCustomObject with enrollment info, device/user policies, and diagnostics path.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [switch]$SkipMDMDiag
    )

    Write-Verbose "Collecting MDM/Intune policy data..."

    # --- 1. Check MDM enrollment status ---
    $enrollments = @()
    $enrollmentPath = 'HKLM:\SOFTWARE\Microsoft\Enrollments'

    if (Test-Path $enrollmentPath) {
        $enrollments = @(Get-ChildItem $enrollmentPath -ErrorAction SilentlyContinue |
            Where-Object {
                $provider = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).ProviderID
                $provider -and $provider -ne ''
            } |
            ForEach-Object {
                $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                [PSCustomObject]@{
                    EnrollmentId   = $_.PSChildName
                    ProviderId     = $props.ProviderID
                    UPN            = $props.UPN
                    AADTenantId    = $props.AADTenantID
                    EnrollmentType = $props.EnrollmentType
                    DeviceId       = $props.SID
                }
            })
    }

    $isEnrolled = $enrollments.Count -gt 0

    # --- 2. Read applied MDM policies from PolicyManager ---
    $devicePolicies = @()
    $deviceBasePath = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device'

    if (Test-Path $deviceBasePath) {
        $areas = Get-ChildItem $deviceBasePath -ErrorAction SilentlyContinue
        foreach ($area in $areas) {
            try {
                $props = Get-ItemProperty $area.PSPath -ErrorAction SilentlyContinue
                if (-not $props) { continue }

                $props.PSObject.Properties |
                    Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Provider|Drive)$' } |
                    ForEach-Object {
                        $devicePolicies += [PSCustomObject]@{
                            Area    = $area.PSChildName
                            Setting = $_.Name
                            Value   = $_.Value
                            Scope   = 'Device'
                            Source  = 'PolicyManager'
                        }
                    }
            }
            catch {
                Write-Verbose "Error reading MDM area $($area.PSChildName): $_"
            }
        }
    }

    $userPolicies = @()
    $userBasePath = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\user'

    if (Test-Path $userBasePath) {
        # User policies may have a SID-based subfolder
        $userSubPaths = Get-ChildItem $userBasePath -ErrorAction SilentlyContinue
        foreach ($userSub in $userSubPaths) {
            $userAreas = Get-ChildItem $userSub.PSPath -ErrorAction SilentlyContinue
            foreach ($area in $userAreas) {
                try {
                    $props = Get-ItemProperty $area.PSPath -ErrorAction SilentlyContinue
                    if (-not $props) { continue }

                    $props.PSObject.Properties |
                        Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Provider|Drive)$' } |
                        ForEach-Object {
                            $userPolicies += [PSCustomObject]@{
                                Area    = $area.PSChildName
                                Setting = $_.Name
                                Value   = $_.Value
                                Scope   = 'User'
                                Source  = 'PolicyManager'
                            }
                        }
                }
                catch {
                    Write-Verbose "Error reading MDM user area: $_"
                }
            }
        }
    }

    # --- 3. Also check PolicyManager providers for source info ---
    $policyProviders = @()
    $providerPath = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\providers'

    if (Test-Path $providerPath) {
        $providers = Get-ChildItem $providerPath -ErrorAction SilentlyContinue
        foreach ($provider in $providers) {
            $providerName = $provider.PSChildName
            $defaultPath = Join-Path $provider.PSPath 'default'
            if (Test-Path $defaultPath) {
                $providerAreas = Get-ChildItem $defaultPath -ErrorAction SilentlyContinue
                foreach ($pa in $providerAreas) {
                    try {
                        $props = Get-ItemProperty $pa.PSPath -ErrorAction SilentlyContinue
                        if (-not $props) { continue }

                        $props.PSObject.Properties |
                            Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Provider|Drive)$' } |
                            ForEach-Object {
                                $policyProviders += [PSCustomObject]@{
                                    ProviderId = $providerName
                                    Area       = $pa.PSChildName
                                    Setting    = $_.Name
                                    Value      = $_.Value
                                }
                            }
                    }
                    catch {
                        Write-Verbose "Error reading provider area: $_"
                    }
                }
            }
        }
    }

    # --- 4. Run mdmdiagnosticstool (optional) ---
    $diagPath = $null

    if (-not $SkipMDMDiag -and $isEnrolled) {
        $diagFolder = Join-Path $env:TEMP "PolicyLens_MDMDiag_$(Get-Random)"
        try {
            New-Item -Path $diagFolder -ItemType Directory -Force | Out-Null
            $diagCab = Join-Path $diagFolder 'mdmdiag.cab'

            Write-Verbose "Running mdmdiagnosticstool..."
            $proc = Start-Process -FilePath 'mdmdiagnosticstool.exe' `
                -ArgumentList "-area DeviceEnrollment;DeviceProvisioning;Autopilot -cab `"$diagCab`"" `
                -NoNewWindow -Wait -PassThru -ErrorAction SilentlyContinue

            if ($proc.ExitCode -eq 0 -and (Test-Path $diagCab)) {
                # Extract the cab to read the XML files
                $extractPath = Join-Path $diagFolder 'extracted'
                New-Item -Path $extractPath -ItemType Directory -Force | Out-Null
                & expand.exe $diagCab -F:* $extractPath | Out-Null
                $diagPath = $extractPath
                Write-Verbose "MDM diagnostics extracted to: $extractPath"
            }
            else {
                Write-Verbose "mdmdiagnosticstool exited with code: $($proc.ExitCode)"
            }
        }
        catch {
            Write-Warning "Failed to run mdmdiagnosticstool: $_"
        }
    }
    elseif (-not $isEnrolled) {
        Write-Verbose "Device not MDM enrolled, skipping mdmdiagnosticstool."
    }

    [PSCustomObject]@{
        IsEnrolled      = $isEnrolled
        Enrollments     = $enrollments
        DevicePolicies  = $devicePolicies
        UserPolicies    = $userPolicies
        PolicyProviders = $policyProviders
        DiagnosticsPath = $diagPath
        CollectedAt     = Get-Date
    }
}
