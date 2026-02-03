function Get-MDMPolicyData {
    <#
    .SYNOPSIS
        Collects MDM/Intune policy data from the local device.
    .DESCRIPTION
        Checks MDM enrollment status, reads applied MDM policies from PolicyManager
        registry keys, and optionally runs mdmdiagnosticstool for detailed diagnostics.

        Returns two sets of policies:
        - IntunePolicies: Only settings explicitly configured by Intune (from Providers path)
        - AllCSPValues: All current CSP values including defaults (for debugging)
    .PARAMETER SkipMDMDiag
        Skip running mdmdiagnosticstool (can be slow on some devices).
    .OUTPUTS
        PSCustomObject with enrollment info, Intune policies, and diagnostics path.
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
    $intuneEnrollmentGuid = $null

    if (Test-Path $enrollmentPath) {
        $enrollments = @(Get-ChildItem $enrollmentPath -ErrorAction SilentlyContinue |
            Where-Object {
                $provider = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).ProviderID
                $provider -and $provider -ne ''
            } |
            ForEach-Object {
                $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue

                # Identify Intune enrollment (ProviderID = "MS DM Server")
                if ($props.ProviderID -eq 'MS DM Server') {
                    $intuneEnrollmentGuid = $_.PSChildName
                }

                [PSCustomObject]@{
                    EnrollmentId   = $_.PSChildName
                    ProviderId     = $props.ProviderID
                    UPN            = $props.UPN
                    AADTenantId    = $props.AADTenantID
                    EnrollmentType = $props.EnrollmentType
                    DeviceId       = $props.SID
                    IsIntune       = ($props.ProviderID -eq 'MS DM Server')
                }
            })
    }

    $isEnrolled = $enrollments.Count -gt 0

    # --- 2. Read Intune-configured policies from Providers path ---
    # This contains ONLY settings explicitly pushed by Intune, not defaults
    $intunePolicies = @()

    if ($intuneEnrollmentGuid) {
        Write-Verbose "Found Intune enrollment GUID: $intuneEnrollmentGuid"

        # Device policies from Intune provider
        $intuneDevicePath = "HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers\$intuneEnrollmentGuid\default\Device"
        if (Test-Path $intuneDevicePath) {
            $areas = Get-ChildItem $intuneDevicePath -ErrorAction SilentlyContinue
            foreach ($area in $areas) {
                try {
                    $props = Get-ItemProperty $area.PSPath -ErrorAction SilentlyContinue
                    if (-not $props) { continue }

                    $props.PSObject.Properties |
                        Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Provider|Drive)$' } |
                        ForEach-Object {
                            $intunePolicies += [PSCustomObject]@{
                                Area    = $area.PSChildName
                                Setting = $_.Name
                                Value   = $_.Value
                                Scope   = 'Device'
                                Source  = 'Intune'
                            }
                        }
                }
                catch {
                    Write-Verbose "Error reading Intune device area $($area.PSChildName): $_"
                }
            }
        }

        # User policies from Intune provider
        $intuneUserPath = "HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers\$intuneEnrollmentGuid\default\User"
        if (Test-Path $intuneUserPath) {
            $userSubPaths = Get-ChildItem $intuneUserPath -ErrorAction SilentlyContinue
            foreach ($userSub in $userSubPaths) {
                $userAreas = Get-ChildItem $userSub.PSPath -ErrorAction SilentlyContinue
                foreach ($area in $userAreas) {
                    try {
                        $props = Get-ItemProperty $area.PSPath -ErrorAction SilentlyContinue
                        if (-not $props) { continue }

                        $props.PSObject.Properties |
                            Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Provider|Drive)$' } |
                            ForEach-Object {
                                $intunePolicies += [PSCustomObject]@{
                                    Area    = $area.PSChildName
                                    Setting = $_.Name
                                    Value   = $_.Value
                                    Scope   = 'User'
                                    Source  = 'Intune'
                                }
                            }
                    }
                    catch {
                        Write-Verbose "Error reading Intune user area: $_"
                    }
                }
            }
        }

        Write-Verbose "Found $($intunePolicies.Count) Intune-configured policies"
    }
    else {
        Write-Verbose "No Intune enrollment found - cannot read Intune-specific policies"
    }

    # --- 3. Read ALL current CSP values (for comparison/debugging) ---
    # This includes defaults and values from all sources
    $devicePolicies = @()
    $deviceBasePath = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device'

    if (Test-Path $deviceBasePath) {
        $areas = Get-ChildItem $deviceBasePath -ErrorAction SilentlyContinue
        foreach ($area in $areas) {
            try {
                $props = Get-ItemProperty $area.PSPath -ErrorAction SilentlyContinue
                if (-not $props) { continue }

                $props.PSObject.Properties |
                    Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Provider|Drive)$' -and $_.Name -notmatch '_WinningProvider$' } |
                    ForEach-Object {
                        # Check for winning provider info
                        $winningProviderName = "$($_.Name)_WinningProvider"
                        $winningProvider = $props.$winningProviderName
                        $isFromIntune = ($winningProvider -eq $intuneEnrollmentGuid)

                        $devicePolicies += [PSCustomObject]@{
                            Area            = $area.PSChildName
                            Setting         = $_.Name
                            Value           = $_.Value
                            Scope           = 'Device'
                            Source          = 'PolicyManager'
                            WinningProvider = $winningProvider
                            IsFromIntune    = $isFromIntune
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
        $userSubPaths = Get-ChildItem $userBasePath -ErrorAction SilentlyContinue
        foreach ($userSub in $userSubPaths) {
            $userAreas = Get-ChildItem $userSub.PSPath -ErrorAction SilentlyContinue
            foreach ($area in $userAreas) {
                try {
                    $props = Get-ItemProperty $area.PSPath -ErrorAction SilentlyContinue
                    if (-not $props) { continue }

                    $props.PSObject.Properties |
                        Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Provider|Drive)$' -and $_.Name -notmatch '_WinningProvider$' } |
                        ForEach-Object {
                            $winningProviderName = "$($_.Name)_WinningProvider"
                            $winningProvider = $props.$winningProviderName
                            $isFromIntune = ($winningProvider -eq $intuneEnrollmentGuid)

                            $userPolicies += [PSCustomObject]@{
                                Area            = $area.PSChildName
                                Setting         = $_.Name
                                Value           = $_.Value
                                Scope           = 'User'
                                Source          = 'PolicyManager'
                                WinningProvider = $winningProvider
                                IsFromIntune    = $isFromIntune
                            }
                        }
                }
                catch {
                    Write-Verbose "Error reading MDM user area: $_"
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
        IsEnrolled           = $isEnrolled
        Enrollments          = $enrollments
        IntuneEnrollmentGuid = $intuneEnrollmentGuid
        # Primary: Only Intune-configured policies (what users care about)
        IntunePolicies       = $intunePolicies
        # Secondary: All CSP values for comparison/debugging
        DevicePolicies       = $devicePolicies
        UserPolicies         = $userPolicies
        # Summary counts
        IntunePolicyCount    = $intunePolicies.Count
        TotalCSPValueCount   = $devicePolicies.Count + $userPolicies.Count
        DiagnosticsPath      = $diagPath
        CollectedAt          = Get-Date
    }
}
