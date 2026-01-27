function Write-ConsoleSummary {
    <#
    .SYNOPSIS
        Formats and displays the PolicyCheck analysis results to the console.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Analysis,

        [Parameter(Mandatory)]
        [PSCustomObject]$GPOData,

        [Parameter(Mandatory)]
        [PSCustomObject]$MDMData,

        [PSCustomObject]$AppData,

        [PSCustomObject]$GroupData
    )

    $s = $Analysis.Summary

    Write-Host ""
    Write-Host "  ══════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  POLICY CHECK RESULTS" -ForegroundColor Cyan
    Write-Host "  ══════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""

    # --- Device Info ---
    Write-Host "  Device:   $($GPOData.ComputerName)" -ForegroundColor White
    Write-Host "  Scanned:  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray

    # Enrollment status
    if ($MDMData.IsEnrolled) {
        Write-Host "  MDM:      " -NoNewline -ForegroundColor White
        Write-Host "Enrolled" -ForegroundColor Green
        foreach ($enrollment in $MDMData.Enrollments) {
            Write-Host "            Provider: $($enrollment.ProviderId)  UPN: $($enrollment.UPN)" -ForegroundColor DarkGray
        }
    }
    else {
        Write-Host "  MDM:      " -NoNewline -ForegroundColor White
        Write-Host "Not Enrolled" -ForegroundColor Yellow
    }

    Write-Host ""

    # --- Group Policy ---
    Write-Host "  GROUP POLICY" -ForegroundColor White
    Write-Host "  ────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  Computer GPOs:       $($GPOData.ComputerGPOs.Count)" -ForegroundColor Gray
    Write-Host "  User GPOs:           $($GPOData.UserGPOs.Count)" -ForegroundColor Gray
    Write-Host "  Registry settings:   $($s.TotalGPOSettings)" -ForegroundColor Gray

    if ($GPOData.ComputerGPOs.Count -gt 0) {
        Write-Host ""
        Write-Host "  Applied Computer GPOs:" -ForegroundColor DarkGray
        foreach ($gpo in $GPOData.ComputerGPOs | Sort-Object Name) {
            Write-Host "    - $($gpo.Name)" -ForegroundColor DarkGray
        }
    }
    if ($GPOData.UserGPOs.Count -gt 0) {
        Write-Host ""
        Write-Host "  Applied User GPOs:" -ForegroundColor DarkGray
        foreach ($gpo in $GPOData.UserGPOs | Sort-Object Name) {
            Write-Host "    - $($gpo.Name)" -ForegroundColor DarkGray
        }
    }

    Write-Host ""

    # --- MDM/Intune ---
    Write-Host "  MDM / INTUNE" -ForegroundColor White
    Write-Host "  ────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  Device policies:     $($MDMData.DevicePolicies.Count)" -ForegroundColor Gray
    Write-Host "  User policies:       $($MDMData.UserPolicies.Count)" -ForegroundColor Gray

    Write-Host ""

    # --- Overlap Analysis ---
    Write-Host "  OVERLAP ANALYSIS" -ForegroundColor White
    Write-Host "  ────────────────────────────" -ForegroundColor DarkGray

    # Both configured
    Write-Host "  Both GPO & Intune:   " -NoNewline -ForegroundColor Gray
    if ($s.BothConfigured -gt 0) {
        Write-Host "$($s.BothConfigured)" -ForegroundColor Yellow -NoNewline
        Write-Host " ($($s.BothConfiguredMatch) match, " -ForegroundColor DarkGray -NoNewline
        if ($s.ValuesInConflict -gt 0) {
            Write-Host "$($s.ValuesInConflict) conflict" -ForegroundColor Red -NoNewline
        }
        else {
            Write-Host "0 conflict" -ForegroundColor Green -NoNewline
        }
        Write-Host ")" -ForegroundColor DarkGray
    }
    else {
        Write-Host "0" -ForegroundColor Green
    }

    # GPO only with mapping
    Write-Host "  GPO-only (can migrate): " -NoNewline -ForegroundColor Gray
    Write-Host "$($s.GPOOnlyWithMapping)" -ForegroundColor Cyan

    # GPO only without mapping
    Write-Host "  GPO-only (no mapping):  " -NoNewline -ForegroundColor Gray
    Write-Host "$($s.GPOOnlyNoMapping)" -ForegroundColor Magenta

    # MDM only
    Write-Host "  MDM-only settings:      $($s.MDMOnlySettings)" -ForegroundColor Gray

    # --- Conflicts detail ---
    if ($s.ValuesInConflict -gt 0) {
        Write-Host ""
        Write-Host "  VALUE CONFLICTS" -ForegroundColor Red
        Write-Host "  ────────────────────────────" -ForegroundColor DarkGray
        $conflicts = $Analysis.DetailedResults | Where-Object {
            $_.Status -eq 'BothConfigured' -and $_.ValuesMatch -eq $false
        }
        foreach ($conflict in $conflicts) {
            Write-Host "  [$($conflict.Category)] $($conflict.GPOValueName)" -ForegroundColor Yellow
            Write-Host "    GPO value:  $($conflict.GPOValue)" -ForegroundColor Gray
            Write-Host "    MDM value:  $($conflict.MDMValue)" -ForegroundColor Gray
        }
    }

    # --- App Assignments (Graph) ---
    if ($AppData -and $AppData.Available) {
        Write-Host ""
        Write-Host "  INTUNE APP ASSIGNMENTS" -ForegroundColor White
        Write-Host "  ────────────────────────────" -ForegroundColor DarkGray
        Write-Host "  Total apps:          $($AppData.Apps.Count)" -ForegroundColor Gray
        Write-Host "  Assigned apps:       $($AppData.AssignedApps.Count)" -ForegroundColor Gray

        $requiredApps = @($AppData.AssignedApps | Where-Object {
            $_.Assignments | Where-Object Intent -eq 'Required'
        })
        $availableApps = @($AppData.AssignedApps | Where-Object {
            $_.Assignments | Where-Object Intent -eq 'Available'
        })

        Write-Host "  Required:            $($requiredApps.Count)" -ForegroundColor Gray
        Write-Host "  Available:           $($availableApps.Count)" -ForegroundColor Gray

        if ($requiredApps.Count -gt 0) {
            Write-Host ""
            Write-Host "  Required Apps:" -ForegroundColor DarkGray
            foreach ($app in $requiredApps | Select-Object -First 15) {
                Write-Host "    - $($app.DisplayName) ($($app.AppType))" -ForegroundColor DarkGray
            }
            if ($requiredApps.Count -gt 15) {
                Write-Host "    ... and $($requiredApps.Count - 15) more" -ForegroundColor DarkGray
            }
        }
    }

    # --- Group Memberships (Graph) ---
    if ($GroupData -and $GroupData.Available -and $GroupData.DeviceFound) {
        Write-Host ""
        Write-Host "  AZURE AD GROUP MEMBERSHIPS" -ForegroundColor White
        Write-Host "  ────────────────────────────" -ForegroundColor DarkGray
        Write-Host "  Total groups:        $($GroupData.Groups.Count)" -ForegroundColor Gray

        $dynamicGroups = @($GroupData.Groups | Where-Object GroupType -eq 'Dynamic')
        $assignedGroups = @($GroupData.Groups | Where-Object GroupType -eq 'Assigned')
        Write-Host "  Dynamic:             $($dynamicGroups.Count)" -ForegroundColor Gray
        Write-Host "  Assigned:            $($assignedGroups.Count)" -ForegroundColor Gray

        if ($GroupData.Groups.Count -gt 0) {
            Write-Host ""
            foreach ($group in $GroupData.Groups | Sort-Object DisplayName | Select-Object -First 20) {
                $typeTag = if ($group.GroupType -eq 'Dynamic') { '[D]' } else { '[A]' }
                $color = if ($group.GroupType -eq 'Dynamic') { 'Cyan' } else { 'DarkGray' }
                Write-Host "    $typeTag $($group.DisplayName)" -ForegroundColor $color
            }
            if ($GroupData.Groups.Count -gt 20) {
                Write-Host "    ... and $($GroupData.Groups.Count - 20) more" -ForegroundColor DarkGray
            }
        }
    }

    Write-Host ""
}
