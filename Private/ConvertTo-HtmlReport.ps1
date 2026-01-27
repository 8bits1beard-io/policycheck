function ConvertTo-HtmlReport {
    <#
    .SYNOPSIS
        Generates a self-contained HTML report from PolicyCheck data.
    .DESCRIPTION
        Creates an HTML file with embedded CSS and JavaScript featuring collapsible
        sections, color-coded tables, and filter/search functionality.
    .OUTPUTS
        String path to the generated HTML report.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Analysis,

        [Parameter(Mandatory)]
        [PSCustomObject]$GPOData,

        [Parameter(Mandatory)]
        [PSCustomObject]$MDMData,

        [PSCustomObject]$GraphData,
        [PSCustomObject]$AppData,
        [PSCustomObject]$GroupData,

        [string]$OutputPath = ".\PolicyCheck_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    )

    $s = $Analysis.Summary
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $computerName = $GPOData.ComputerName

    # Load CSS
    $cssPath = Join-Path $PSScriptRoot '..\Templates\report.css'
    $css = ''
    if (Test-Path $cssPath) {
        $css = Get-Content $cssPath -Raw
    }

    # Enrollment badge
    $enrollBadge = if ($MDMData.IsEnrolled) {
        '<span class="badge badge-enrolled">MDM Enrolled</span>'
    }
    else {
        '<span class="badge badge-not-enrolled">Not Enrolled</span>'
    }

    # --- Build HTML sections ---

    # Summary cards
    $summaryCards = @"
<div class="summary-grid">
    <div class="summary-card blue">
        <span class="number">$($s.TotalGPOs)</span>
        <span class="label">Applied GPOs</span>
    </div>
    <div class="summary-card blue">
        <span class="number">$($s.TotalGPOSettings)</span>
        <span class="label">GPO Registry Settings</span>
    </div>
    <div class="summary-card blue">
        <span class="number">$($s.TotalMDMSettings)</span>
        <span class="label">MDM Settings</span>
    </div>
    <div class="summary-card green">
        <span class="number">$($s.BothConfiguredMatch)</span>
        <span class="label">Matched (GPO + MDM)</span>
    </div>
    <div class="summary-card red">
        <span class="number">$($s.ValuesInConflict)</span>
        <span class="label">Value Conflicts</span>
    </div>
    <div class="summary-card cyan">
        <span class="number">$($s.GPOOnlyWithMapping)</span>
        <span class="label">GPO-Only (Can Migrate)</span>
    </div>
    <div class="summary-card magenta">
        <span class="number">$($s.GPOOnlyNoMapping)</span>
        <span class="label">GPO-Only (No Mapping)</span>
    </div>
    <div class="summary-card blue">
        <span class="number">$($s.MDMOnlySettings)</span>
        <span class="label">MDM-Only Settings</span>
    </div>
</div>
"@

    # GPO list section
    $gpoRows = ''
    foreach ($gpo in @($GPOData.ComputerGPOs) + @($GPOData.UserGPOs) | Sort-Object Scope, Name) {
        $gpoRows += @"
        <tr>
            <td>$([System.Web.HttpUtility]::HtmlEncode($gpo.Name))</td>
            <td>$($gpo.Scope)</td>
            <td>$(if ($gpo.LinkLocation) { [System.Web.HttpUtility]::HtmlEncode($gpo.LinkLocation) } else { '-' })</td>
            <td>$($gpo.LinkOrder)</td>
            <td>$(if ($gpo.Enabled) { 'Yes' } else { 'No' })</td>
        </tr>
`n"
    }

    $gpoSection = @"
<div class="section">
    <div class="section-header" onclick="toggleSection(this)">
        <h2>Applied Group Policies ($($GPOData.TotalGPOCount))</h2>
        <span class="toggle">&#9660;</span>
    </div>
    <div class="section-body">
        <table>
            <thead>
                <tr><th>GPO Name</th><th>Scope</th><th>Link Location</th><th>Link Order</th><th>Enabled</th></tr>
            </thead>
            <tbody>
                $gpoRows
            </tbody>
        </table>
    </div>
</div>
"@

    # MDM Enrollment section
    $enrollRows = ''
    foreach ($enr in $MDMData.Enrollments) {
        $enrollRows += @"
        <div class="enrollment-grid">
            <div class="enrollment-item"><span class="key">Provider</span><span class="value">$($enr.ProviderId)</span></div>
            <div class="enrollment-item"><span class="key">UPN</span><span class="value">$($enr.UPN)</span></div>
            <div class="enrollment-item"><span class="key">Tenant ID</span><span class="value">$($enr.AADTenantId)</span></div>
            <div class="enrollment-item"><span class="key">Enrollment ID</span><span class="value">$($enr.EnrollmentId)</span></div>
        </div>
`n"
    }
    if (-not $MDMData.IsEnrolled) {
        $enrollRows = '<div class="info-box warning">This device is not enrolled in MDM/Intune.</div>'
    }

    $enrollSection = @"
<div class="section">
    <div class="section-header" onclick="toggleSection(this)">
        <h2>MDM Enrollment $enrollBadge</h2>
        <span class="toggle">&#9660;</span>
    </div>
    <div class="section-body">
        $enrollRows
    </div>
</div>
"@

    # Overlap Analysis section
    $overlapRows = ''
    $sortedResults = $Analysis.DetailedResults | Sort-Object @{Expression='Status';Descending=$false}, Category, GPOPath
    foreach ($result in $sortedResults) {
        $rowClass = switch ($result.Status) {
            'BothConfigured' {
                if ($result.ValuesMatch) { 'status-both-match' } else { 'status-both-conflict' }
            }
            'GPOOnly_MappingExists' { 'status-gpo-mapping' }
            'GPOOnly_NoMapping'     { 'status-gpo-nomapping' }
        }

        $statusTag = switch ($result.Status) {
            'BothConfigured' {
                if ($result.ValuesMatch) {
                    '<span class="status-tag both-match">Matched</span>'
                }
                else {
                    '<span class="status-tag conflict">Conflict</span>'
                }
            }
            'GPOOnly_MappingExists' { '<span class="status-tag migration-ready">Migration Ready</span>' }
            'GPOOnly_NoMapping'     { '<span class="status-tag no-mapping">No Mapping</span>' }
        }

        $gpoVal = if ($result.GPOValue -ne $null) { [System.Web.HttpUtility]::HtmlEncode("$($result.GPOValue)") } else { '-' }
        $mdmVal = if ($result.MDMValue -ne $null) { [System.Web.HttpUtility]::HtmlEncode("$($result.MDMValue)") } else { '-' }

        $overlapRows += @"
        <tr class="$rowClass" data-category="$($result.Category)" data-status="$($result.Status)">
            <td>$statusTag</td>
            <td>$(if ($result.Category) { [System.Web.HttpUtility]::HtmlEncode($result.Category) } else { '-' })</td>
            <td>$(if ($result.GPOValueName) { [System.Web.HttpUtility]::HtmlEncode($result.GPOValueName) } else { '-' })</td>
            <td style="font-size:0.8rem">$(if ($result.GPOPath) { [System.Web.HttpUtility]::HtmlEncode($result.GPOPath) } else { '-' })</td>
            <td>$gpoVal</td>
            <td>$(if ($result.MDMArea) { "$($result.MDMArea)/$($result.MDMSetting)" } else { '-' })</td>
            <td>$mdmVal</td>
        </tr>
`n"
    }

    $overlapSection = @"
<div class="section">
    <div class="section-header" onclick="toggleSection(this)">
        <h2>Overlap Analysis ($($Analysis.DetailedResults.Count) settings)</h2>
        <span class="toggle">&#9660;</span>
    </div>
    <div class="section-body">
        <div class="legend">
            <div class="legend-item"><div class="legend-dot green"></div>Both configured, values match</div>
            <div class="legend-item"><div class="legend-dot red"></div>Both configured, values conflict</div>
            <div class="legend-item"><div class="legend-dot cyan"></div>GPO-only, Intune mapping exists (migration ready)</div>
            <div class="legend-item"><div class="legend-dot magenta"></div>GPO-only, no known Intune mapping</div>
        </div>
        <div class="filter-bar">
            <input type="text" id="overlapSearch" placeholder="Search settings..." onkeyup="filterOverlapTable()">
            <select id="statusFilter" onchange="filterOverlapTable()">
                <option value="">All Statuses</option>
                <option value="BothConfigured">Both Configured</option>
                <option value="GPOOnly_MappingExists">GPO-Only (Can Migrate)</option>
                <option value="GPOOnly_NoMapping">GPO-Only (No Mapping)</option>
            </select>
        </div>
        <table id="overlapTable">
            <thead>
                <tr><th>Status</th><th>Category</th><th>Setting</th><th>GPO Path</th><th>GPO Value</th><th>MDM Setting</th><th>MDM Value</th></tr>
            </thead>
            <tbody>
                $overlapRows
            </tbody>
        </table>
    </div>
</div>
"@

    # MDM Policy Details section
    $mdmRows = ''
    $allMDM = @($MDMData.DevicePolicies) + @($MDMData.UserPolicies) | Sort-Object Area, Setting
    foreach ($pol in $allMDM) {
        $mdmRows += @"
        <tr>
            <td>$($pol.Area)</td>
            <td>$(if ($pol.Setting) { [System.Web.HttpUtility]::HtmlEncode($pol.Setting) } else { '-' })</td>
            <td>$(if ($pol.Value -ne $null) { [System.Web.HttpUtility]::HtmlEncode("$($pol.Value)") } else { '-' })</td>
            <td>$($pol.Scope)</td>
        </tr>
`n"
    }

    $mdmSection = @"
<div class="section">
    <div class="section-header collapsed" onclick="toggleSection(this)">
        <h2>MDM Policy Details ($($allMDM.Count) settings)</h2>
        <span class="toggle">&#9660;</span>
    </div>
    <div class="section-body" style="display:none">
        <table>
            <thead>
                <tr><th>CSP Area</th><th>Setting</th><th>Value</th><th>Scope</th></tr>
            </thead>
            <tbody>
                $mdmRows
            </tbody>
        </table>
    </div>
</div>
"@

    # GPO Registry Details section
    $gpoRegRows = ''
    foreach ($pol in $GPOData.RegistryPolicies | Sort-Object Category, Path) {
        $gpoRegRows += @"
        <tr>
            <td>$($pol.Category)</td>
            <td style="font-size:0.8rem">$(if ($pol.Path) { [System.Web.HttpUtility]::HtmlEncode($pol.Path) } else { '-' })</td>
            <td>$(if ($pol.ValueName) { [System.Web.HttpUtility]::HtmlEncode($pol.ValueName) } else { '-' })</td>
            <td>$(if ($pol.Data -ne $null) { [System.Web.HttpUtility]::HtmlEncode("$($pol.Data)") } else { '-' })</td>
            <td>$($pol.Scope)</td>
        </tr>
`n"
    }

    $gpoRegSection = @"
<div class="section">
    <div class="section-header collapsed" onclick="toggleSection(this)">
        <h2>GPO Registry Details ($($GPOData.RegistryPolicies.Count) entries)</h2>
        <span class="toggle">&#9660;</span>
    </div>
    <div class="section-body" style="display:none">
        <table>
            <thead>
                <tr><th>Category</th><th>Registry Path</th><th>Value Name</th><th>Data</th><th>Scope</th></tr>
            </thead>
            <tbody>
                $gpoRegRows
            </tbody>
        </table>
    </div>
</div>
"@

    # Graph Data section (if available)
    $graphSection = ''
    if ($GraphData -and $GraphData.Available) {
        $profileRows = ''
        foreach ($profile in $GraphData.Profiles | Sort-Object DisplayName) {
            $assignmentText = ($profile.Assignments | ForEach-Object {
                "$($_.TargetType -replace '#microsoft\.graph\.', '') $(if ($_.GroupId) { "($($_.GroupId))" })"
            }) -join ', '
            if (-not $assignmentText) { $assignmentText = 'None' }

            $profileRows += @"
            <tr>
                <td>$(if ($profile.DisplayName) { [System.Web.HttpUtility]::HtmlEncode($profile.DisplayName) } else { '-' })</td>
                <td style="font-size:0.8rem">$($profile.OdataType -replace '#microsoft\.graph\.', '')</td>
                <td style="font-size:0.8rem">$assignmentText</td>
            </tr>
`n"
        }

        $catalogRows = ''
        foreach ($cat in $GraphData.SettingsCatalog | Sort-Object Name) {
            $catAssign = ($cat.Assignments | ForEach-Object {
                "$($_.TargetType -replace '#microsoft\.graph\.', '') $(if ($_.GroupId) { "($($_.GroupId))" })"
            }) -join ', '
            if (-not $catAssign) { $catAssign = 'None' }

            $catalogRows += @"
            <tr>
                <td>$(if ($cat.Name) { [System.Web.HttpUtility]::HtmlEncode($cat.Name) } else { '-' })</td>
                <td>$($cat.Platforms)</td>
                <td>$($cat.Technologies)</td>
                <td style="font-size:0.8rem">$catAssign</td>
            </tr>
`n"
        }

        $graphSection = @"
<div class="section">
    <div class="section-header collapsed" onclick="toggleSection(this)">
        <h2>Intune Configuration Profiles ($($GraphData.Profiles.Count))</h2>
        <span class="toggle">&#9660;</span>
    </div>
    <div class="section-body" style="display:none">
        <table>
            <thead>
                <tr><th>Profile Name</th><th>Type</th><th>Assignments</th></tr>
            </thead>
            <tbody>
                $profileRows
            </tbody>
        </table>
    </div>
</div>
<div class="section">
    <div class="section-header collapsed" onclick="toggleSection(this)">
        <h2>Settings Catalog Policies ($($GraphData.SettingsCatalog.Count))</h2>
        <span class="toggle">&#9660;</span>
    </div>
    <div class="section-body" style="display:none">
        <table>
            <thead>
                <tr><th>Policy Name</th><th>Platform</th><th>Technologies</th><th>Assignments</th></tr>
            </thead>
            <tbody>
                $catalogRows
            </tbody>
        </table>
    </div>
</div>
"@
    }

    # App Assignments section (if available)
    $appSection = ''
    if ($AppData -and $AppData.Available) {
        $appRows = ''
        foreach ($app in $AppData.AssignedApps | Sort-Object DisplayName) {
            $intents = ($app.Assignments | ForEach-Object {
                $intentClass = switch ($_.Intent) {
                    'Required' { 'required' }
                    'Available' { 'available' }
                    default { '' }
                }
                "<span class=`"app-intent $intentClass`">$($_.Intent) - $($_.TargetType)</span>"
            }) -join '<br>'

            $appRows += @"
            <tr>
                <td><strong>$(if ($app.DisplayName) { [System.Web.HttpUtility]::HtmlEncode($app.DisplayName) } else { '-' })</strong></td>
                <td>$($app.AppType)</td>
                <td>$(if ($app.Publisher) { [System.Web.HttpUtility]::HtmlEncode($app.Publisher) } else { '-' })</td>
                <td>$intents</td>
            </tr>
`n"
        }

        $appSection = @"
<div class="section">
    <div class="section-header collapsed" onclick="toggleSection(this)">
        <h2>Intune App Assignments ($($AppData.AssignedApps.Count) assigned)</h2>
        <span class="toggle">&#9660;</span>
    </div>
    <div class="section-body" style="display:none">
        <div class="info-box info">
            Total apps in tenant: $($AppData.Apps.Count) | Assigned: $($AppData.AssignedApps.Count)
        </div>
        <table>
            <thead>
                <tr><th>App Name</th><th>Type</th><th>Publisher</th><th>Assignments</th></tr>
            </thead>
            <tbody>
                $appRows
            </tbody>
        </table>
    </div>
</div>
"@
    }

    # Group Memberships section (if available)
    $groupSection = ''
    if ($GroupData -and $GroupData.Available -and $GroupData.DeviceFound) {
        $deviceInfoHtml = @"
        <div class="enrollment-grid">
            <div class="enrollment-item"><span class="key">Display Name</span><span class="value">$($GroupData.Device.DisplayName)</span></div>
            <div class="enrollment-item"><span class="key">Device ID</span><span class="value">$($GroupData.Device.DeviceId)</span></div>
            <div class="enrollment-item"><span class="key">OS</span><span class="value">$($GroupData.Device.OperatingSystem) $($GroupData.Device.OSVersion)</span></div>
            <div class="enrollment-item"><span class="key">Trust Type</span><span class="value">$($GroupData.Device.TrustType)</span></div>
            <div class="enrollment-item"><span class="key">Managed</span><span class="value">$($GroupData.Device.IsManaged)</span></div>
            <div class="enrollment-item"><span class="key">Compliant</span><span class="value">$($GroupData.Device.IsCompliant)</span></div>
        </div>
"@

        $groupChips = ''
        foreach ($group in $GroupData.Groups | Sort-Object DisplayName) {
            $chipClass = if ($group.GroupType -eq 'Dynamic') { 'dynamic' } else { 'assigned' }
            $typeLabel = if ($group.GroupType -eq 'Dynamic') { '[D]' } else { '[A]' }
            $groupChips += "<span class=`"group-chip $chipClass`" title=`"$(if ($group.Description) { [System.Web.HttpUtility]::HtmlEncode($group.Description) } else { 'No description' })`">$typeLabel $(if ($group.DisplayName) { [System.Web.HttpUtility]::HtmlEncode($group.DisplayName) } else { '-' })</span>`n"
        }

        $groupSection = @"
<div class="section">
    <div class="section-header collapsed" onclick="toggleSection(this)">
        <h2>Azure AD Device Info &amp; Group Memberships ($($GroupData.Groups.Count) groups)</h2>
        <span class="toggle">&#9660;</span>
    </div>
    <div class="section-body" style="display:none">
        $deviceInfoHtml
        <hr style="border-color: var(--border-color); margin: 15px 0;">
        <h3 style="margin-bottom: 10px; font-size: 1rem;">Group Memberships</h3>
        <div class="info-box info">
            [D] = Dynamic membership &nbsp; | &nbsp; [A] = Assigned membership
        </div>
        <div class="group-list">
            $groupChips
        </div>
    </div>
</div>
"@
    }

    # --- Assemble full HTML ---
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PolicyCheck Report - $computerName</title>
    <style>
$css
    </style>
</head>
<body>
    <div class="report-header">
        <h1>PolicyCheck Report $enrollBadge</h1>
        <div class="subtitle">$computerName &bull; $timestamp &bull; PolicyCheck v1.0.0</div>
    </div>

    $summaryCards
    $gpoSection
    $enrollSection
    $overlapSection
    $groupSection
    $appSection
    $graphSection
    $mdmSection
    $gpoRegSection

    <div class="report-footer">
        Generated by PolicyCheck v1.0.0 on $timestamp
    </div>

    <script>
    function toggleSection(header) {
        header.classList.toggle('collapsed');
        var body = header.nextElementSibling;
        body.style.display = body.style.display === 'none' ? 'block' : 'none';
    }

    function filterOverlapTable() {
        var search = document.getElementById('overlapSearch').value.toLowerCase();
        var statusFilter = document.getElementById('statusFilter').value;
        var rows = document.querySelectorAll('#overlapTable tbody tr');

        rows.forEach(function(row) {
            var text = row.textContent.toLowerCase();
            var status = row.getAttribute('data-status');
            var matchesSearch = !search || text.indexOf(search) > -1;
            var matchesStatus = !statusFilter || status === statusFilter;
            row.style.display = (matchesSearch && matchesStatus) ? '' : 'none';
        });
    }
    </script>
</body>
</html>
"@

    # Write the report
    $resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
    $parentDir = Split-Path $resolvedPath -Parent
    if (-not (Test-Path $parentDir)) {
        New-Item -Path $parentDir -ItemType Directory -Force | Out-Null
    }

    $html | Out-File -FilePath $resolvedPath -Encoding UTF8 -Force
    return $resolvedPath
}
