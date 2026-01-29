function Write-ConsoleSummary {
    <#
    .SYNOPSIS
        Formats and displays the PolicyLens analysis results to the console.
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
    Write-Host "  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓" -ForegroundColor Cyan
    Write-Host "  ┃  " -ForegroundColor Cyan -NoNewline
    Write-Host "📊 POLICY CHECK RESULTS" -ForegroundColor White -NoNewline
    Write-Host "                  ┃" -ForegroundColor Cyan
    Write-Host "  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛" -ForegroundColor Cyan
    Write-Host ""

    # --- Device Info ---
    Write-Host "  📍 " -ForegroundColor Cyan -NoNewline
    Write-Host "Device:  " -ForegroundColor Gray -NoNewline
    Write-Host "$($GPOData.ComputerName)" -ForegroundColor White
    Write-Host "     Scanned: " -ForegroundColor DarkGray -NoNewline
    Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray

    # Enrollment status
    if ($MDMData.IsEnrolled) {
        Write-Host "     MDM:     " -ForegroundColor DarkGray -NoNewline
        Write-Host "✓ Enrolled" -ForegroundColor Green
        foreach ($enrollment in $MDMData.Enrollments) {
            Write-Host "              Provider: " -ForegroundColor DarkGray -NoNewline
            Write-Host "$($enrollment.ProviderId)" -ForegroundColor Magenta -NoNewline
            Write-Host "  UPN: " -ForegroundColor DarkGray -NoNewline
            Write-Host "$($enrollment.UPN)" -ForegroundColor Gray
        }
    }
    else {
        Write-Host "     MDM:     " -ForegroundColor DarkGray -NoNewline
        Write-Host "○ Not Enrolled" -ForegroundColor Yellow
    }

    Write-Host ""

    # --- Group Policy ---
    Write-Host "  ┌─ " -ForegroundColor Blue -NoNewline
    Write-Host "GROUP POLICY" -ForegroundColor Blue -NoNewline
    Write-Host " ─────────────────────────────┐" -ForegroundColor Blue
    Write-Host "  │  Computer GPOs:     " -ForegroundColor DarkGray -NoNewline
    Write-Host "$($GPOData.ComputerGPOs.Count)" -ForegroundColor Blue
    Write-Host "  │  User GPOs:         " -ForegroundColor DarkGray -NoNewline
    Write-Host "$($GPOData.UserGPOs.Count)" -ForegroundColor Blue
    Write-Host "  │  Registry settings: " -ForegroundColor DarkGray -NoNewline
    Write-Host "$($s.TotalGPOSettings)" -ForegroundColor Cyan

    if ($GPOData.ComputerGPOs.Count -gt 0) {
        Write-Host "  │" -ForegroundColor Blue
        Write-Host "  │  " -ForegroundColor Blue -NoNewline
        Write-Host "Applied Computer GPOs:" -ForegroundColor Gray
        foreach ($gpo in $GPOData.ComputerGPOs | Sort-Object Name) {
            Write-Host "  │    • " -ForegroundColor Blue -NoNewline
            Write-Host "$($gpo.Name)" -ForegroundColor DarkGray
        }
    }
    if ($GPOData.UserGPOs.Count -gt 0) {
        Write-Host "  │" -ForegroundColor Blue
        Write-Host "  │  " -ForegroundColor Blue -NoNewline
        Write-Host "Applied User GPOs:" -ForegroundColor Gray
        foreach ($gpo in $GPOData.UserGPOs | Sort-Object Name) {
            Write-Host "  │    • " -ForegroundColor Blue -NoNewline
            Write-Host "$($gpo.Name)" -ForegroundColor DarkGray
        }
    }
    Write-Host "  └────────────────────────────────────────────┘" -ForegroundColor Blue
    Write-Host ""

    # --- MDM/Intune ---
    Write-Host "  ┌─ " -ForegroundColor Magenta -NoNewline
    Write-Host "MDM / INTUNE" -ForegroundColor Magenta -NoNewline
    Write-Host " ─────────────────────────────┐" -ForegroundColor Magenta
    Write-Host "  │  Device policies: " -ForegroundColor DarkGray -NoNewline
    Write-Host "$($MDMData.DevicePolicies.Count)" -ForegroundColor Magenta
    Write-Host "  │  User policies:   " -ForegroundColor DarkGray -NoNewline
    Write-Host "$($MDMData.UserPolicies.Count)" -ForegroundColor Magenta
    Write-Host "  └────────────────────────────────────────────┘" -ForegroundColor Magenta
    Write-Host ""

    # --- Overlap Analysis ---
    Write-Host "  ┌─ " -ForegroundColor White -NoNewline
    Write-Host "OVERLAP ANALYSIS" -ForegroundColor White -NoNewline
    Write-Host " ─────────────────────────┐" -ForegroundColor White

    # Both configured
    Write-Host "  │  Both GPO & Intune:     " -ForegroundColor DarkGray -NoNewline
    if ($s.BothConfigured -gt 0) {
        Write-Host "$($s.BothConfigured)" -ForegroundColor Yellow -NoNewline
        Write-Host " (" -ForegroundColor DarkGray -NoNewline
        Write-Host "$($s.BothConfiguredMatch) match" -ForegroundColor Green -NoNewline
        Write-Host ", " -ForegroundColor DarkGray -NoNewline
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
    Write-Host "  │  " -ForegroundColor White -NoNewline
    Write-Host "GPO-only (can migrate): " -ForegroundColor DarkGray -NoNewline
    Write-Host "$($s.GPOOnlyWithMapping)" -ForegroundColor Cyan

    # GPO only without mapping
    Write-Host "  │  " -ForegroundColor White -NoNewline
    Write-Host "GPO-only (no mapping):  " -ForegroundColor DarkGray -NoNewline
    Write-Host "$($s.GPOOnlyNoMapping)" -ForegroundColor DarkMagenta

    # MDM only
    Write-Host "  │  " -ForegroundColor White -NoNewline
    Write-Host "MDM-only settings:      " -ForegroundColor DarkGray -NoNewline
    Write-Host "$($s.MDMOnlySettings)" -ForegroundColor Gray
    Write-Host "  └────────────────────────────────────────────┘" -ForegroundColor White

    # --- Conflicts detail ---
    if ($s.ValuesInConflict -gt 0) {
        Write-Host ""
        Write-Host "  ┌─ " -ForegroundColor Red -NoNewline
        Write-Host "⚠ VALUE CONFLICTS" -ForegroundColor Red -NoNewline
        Write-Host " ────────────────────────┐" -ForegroundColor Red
        $conflicts = $Analysis.DetailedResults | Where-Object {
            $_.Status -eq 'BothConfigured' -and $_.ValuesMatch -eq $false
        }
        foreach ($conflict in $conflicts) {
            Write-Host "  │ " -ForegroundColor Red -NoNewline
            Write-Host "[$($conflict.Category)] " -ForegroundColor Yellow -NoNewline
            Write-Host "$($conflict.GPOValueName)" -ForegroundColor White
            Write-Host "  │   " -ForegroundColor Red -NoNewline
            Write-Host "GPO: " -ForegroundColor Blue -NoNewline
            Write-Host "$($conflict.GPOValue)" -ForegroundColor Gray
            Write-Host "  │   " -ForegroundColor Red -NoNewline
            Write-Host "MDM: " -ForegroundColor Magenta -NoNewline
            Write-Host "$($conflict.MDMValue)" -ForegroundColor Gray
        }
        Write-Host "  └────────────────────────────────────────────┘" -ForegroundColor Red
    }

    # --- App Assignments (Graph) ---
    if ($AppData -and $AppData.Available) {
        Write-Host ""
        Write-Host "  ┌─ " -ForegroundColor Cyan -NoNewline
        Write-Host "INTUNE APP ASSIGNMENTS" -ForegroundColor Cyan -NoNewline
        Write-Host " ───────────────┐" -ForegroundColor Cyan

        $requiredApps = @($AppData.AssignedApps | Where-Object {
            $_.Assignments | Where-Object Intent -eq 'Required'
        })
        $availableApps = @($AppData.AssignedApps | Where-Object {
            $_.Assignments | Where-Object Intent -eq 'Available'
        })

        Write-Host "  │  Total apps:      " -ForegroundColor DarkGray -NoNewline
        Write-Host "$($AppData.Apps.Count)" -ForegroundColor Gray
        Write-Host "  │  Assigned:        " -ForegroundColor DarkGray -NoNewline
        Write-Host "$($AppData.AssignedApps.Count)" -ForegroundColor Cyan
        Write-Host "  │  Required:        " -ForegroundColor DarkGray -NoNewline
        Write-Host "$($requiredApps.Count)" -ForegroundColor Yellow
        Write-Host "  │  Available:       " -ForegroundColor DarkGray -NoNewline
        Write-Host "$($availableApps.Count)" -ForegroundColor Green

        if ($requiredApps.Count -gt 0) {
            Write-Host "  │" -ForegroundColor Cyan
            Write-Host "  │  " -ForegroundColor Cyan -NoNewline
            Write-Host "Required Apps:" -ForegroundColor Yellow
            foreach ($app in $requiredApps | Select-Object -First 10) {
                Write-Host "  │    " -ForegroundColor Cyan -NoNewline
                Write-Host "→ " -ForegroundColor Yellow -NoNewline
                Write-Host "$($app.DisplayName)" -ForegroundColor White -NoNewline
                Write-Host " ($($app.AppType))" -ForegroundColor DarkGray
            }
            if ($requiredApps.Count -gt 10) {
                Write-Host "  │    " -ForegroundColor Cyan -NoNewline
                Write-Host "... and $($requiredApps.Count - 10) more" -ForegroundColor DarkGray
            }
        }
        Write-Host "  └────────────────────────────────────────────┘" -ForegroundColor Cyan
    }

    # --- Group Memberships (Graph) ---
    if ($GroupData -and $GroupData.Available -and $GroupData.DeviceFound) {
        Write-Host ""
        Write-Host "  ┌─ " -ForegroundColor DarkCyan -NoNewline
        Write-Host "AZURE AD GROUP MEMBERSHIPS" -ForegroundColor DarkCyan -NoNewline
        Write-Host " ───────────┐" -ForegroundColor DarkCyan

        $dynamicGroups = @($GroupData.Groups | Where-Object GroupType -eq 'Dynamic')
        $assignedGroups = @($GroupData.Groups | Where-Object GroupType -eq 'Assigned')

        Write-Host "  │  Total groups: " -ForegroundColor DarkGray -NoNewline
        Write-Host "$($GroupData.Groups.Count)" -ForegroundColor Gray
        Write-Host "  │  Dynamic:      " -ForegroundColor DarkGray -NoNewline
        Write-Host "$($dynamicGroups.Count)" -ForegroundColor Cyan
        Write-Host "  │  Assigned:     " -ForegroundColor DarkGray -NoNewline
        Write-Host "$($assignedGroups.Count)" -ForegroundColor Blue

        if ($GroupData.Groups.Count -gt 0) {
            Write-Host "  │" -ForegroundColor DarkCyan
            foreach ($group in $GroupData.Groups | Sort-Object DisplayName | Select-Object -First 15) {
                Write-Host "  │  " -ForegroundColor DarkCyan -NoNewline
                if ($group.GroupType -eq 'Dynamic') {
                    Write-Host "[D] " -ForegroundColor Cyan -NoNewline
                    Write-Host "$($group.DisplayName)" -ForegroundColor Gray
                }
                else {
                    Write-Host "[A] " -ForegroundColor Blue -NoNewline
                    Write-Host "$($group.DisplayName)" -ForegroundColor DarkGray
                }
            }
            if ($GroupData.Groups.Count -gt 15) {
                Write-Host "  │  " -ForegroundColor DarkCyan -NoNewline
                Write-Host "... and $($GroupData.Groups.Count - 15) more" -ForegroundColor DarkGray
            }
        }
        Write-Host "  └────────────────────────────────────────────┘" -ForegroundColor DarkCyan
    }

    Write-Host ""
}
