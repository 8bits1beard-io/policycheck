/**
 * PolicyLens Single Device View Module
 * Renders a comprehensive single-device view with source tabs
 */

// ============================================================================
// MAIN RENDER FUNCTION
// ============================================================================

/**
 * Renders the complete single device view
 * @param {Object} deviceData - The PolicyLens JSON export for a single device
 * @returns {string} HTML string for the single device view
 */
function renderSingleView(deviceData) {
    const device = deviceData.device || {};
    const name = device.computerName || 'Unknown Device';
    const osVersion = device.osVersion || 'Unknown OS';
    const enrolled = deviceData.mdmData?.IsEnrolled || false;
    const exportDate = deviceData.exportedAt ? formatDate(deviceData.exportedAt) : 'Unknown';

    return `
        <div class="single-view-container">
            ${renderDeviceHeader(name, osVersion, enrolled, exportDate)}
            ${renderSourceTabs()}
            <div class="tab-content-container">
                ${renderGPOTab(deviceData)}
                ${renderIntuneTab(deviceData)}
                ${renderSCCMTab(deviceData)}
                ${renderAzureADTab(deviceData)}
            </div>
            ${renderMigrationAnalysis(deviceData)}
        </div>
    `;
}

// ============================================================================
// DEVICE HEADER
// ============================================================================

/**
 * Renders the device header section
 */
function renderDeviceHeader(name, osVersion, enrolled, exportDate) {
    const enrolledBadge = enrolled 
        ? '<span class="badge badge-enrolled">MDM Enrolled</span>'
        : '<span class="badge badge-not-enrolled">Not Enrolled</span>';

    return `
        <div class="device-header report-header">
            <h1>${escapeHtml(name)} ${enrolledBadge}</h1>
            <div class="subtitle">
                <span class="header-item">OS: ${escapeHtml(osVersion)}</span>
                <span class="header-separator">|</span>
                <span class="header-item">Exported: ${escapeHtml(exportDate)}</span>
            </div>
        </div>
    `;
}

// ============================================================================
// SOURCE TABS NAVIGATION
// ============================================================================

/**
 * Renders the source tabs navigation
 */
function renderSourceTabs() {
    return `
        <div class="source-tabs tabs" id="source-tabs">
            <button class="tab active" data-tab="gpo" onclick="switchSourceTab('gpo')">
                <span class="tab-icon">📋</span> GPO
            </button>
            <button class="tab" data-tab="intune" onclick="switchSourceTab('intune')">
                <span class="tab-icon">☁️</span> Intune/MDM
            </button>
            <button class="tab" data-tab="sccm" onclick="switchSourceTab('sccm')">
                <span class="tab-icon">🖥️</span> SCCM
            </button>
            <button class="tab" data-tab="azuread" onclick="switchSourceTab('azuread')">
                <span class="tab-icon">🔐</span> Azure AD
            </button>
        </div>
    `;
}

/**
 * Switches between source tabs
 */
function switchSourceTab(tabId) {
    // Update tab buttons
    document.querySelectorAll('#source-tabs .tab').forEach(tab => {
        tab.classList.toggle('active', tab.dataset.tab === tabId);
    });

    // Update tab content
    document.querySelectorAll('.source-tab-content').forEach(content => {
        content.classList.toggle('active', content.id === `tab-${tabId}`);
    });
}

// ============================================================================
// GPO TAB
// ============================================================================

/**
 * Renders the GPO tab content
 */
function renderGPOTab(deviceData) {
    const gpoData = deviceData.gpoData || {};
    const totalGPOs = gpoData.TotalGPOCount || 0;
    const registryPolicies = gpoData.RegistryPolicies || [];
    const appliedGPOs = gpoData.AppliedGPOs || [];

    return `
        <div class="source-tab-content active" id="tab-gpo">
            ${renderGPOSummaryCards(totalGPOs, registryPolicies.length)}
            ${renderAppliedGPOsList(appliedGPOs, totalGPOs)}
            ${renderGPORegistryTable(registryPolicies)}
        </div>
    `;
}

/**
 * Renders GPO summary cards
 */
function renderGPOSummaryCards(gpoCount, settingsCount) {
    return `
        <div class="summary-grid">
            <div class="summary-card blue">
                <span class="number">${gpoCount}</span>
                <span class="label">GPOs Applied</span>
                <span class="description">Group Policy Objects linked to this device</span>
            </div>
            <div class="summary-card cyan">
                <span class="number">${settingsCount}</span>
                <span class="label">Registry Settings</span>
                <span class="description">Individual policy settings from GPO</span>
            </div>
        </div>
    `;
}

/**
 * Renders the list of applied GPOs
 */
function renderAppliedGPOsList(appliedGPOs, totalCount) {
    if (!appliedGPOs || appliedGPOs.length === 0) {
        if (totalCount > 0) {
            return `
                <div class="info-box info">
                    ${totalCount} GPO(s) detected. Individual GPO names not available in export.
                </div>
            `;
        }
        return `
            <div class="info-box warning">
                No Group Policy Objects detected on this device.
            </div>
        `;
    }

    return `
        <div class="section">
            <div class="section-header">
                <h2>Applied GPOs (${appliedGPOs.length})</h2>
                <span class="toggle">▼</span>
            </div>
            <div class="section-body">
                <div class="gpo-list">
                    ${appliedGPOs.map(gpo => `
                        <div class="gpo-item">
                            <span class="gpo-name">${escapeHtml(gpo.Name || gpo.DisplayName || 'Unknown GPO')}</span>
                            ${gpo.Enabled === false ? '<span class="status-tag no-mapping">Disabled</span>' : ''}
                            ${gpo.LinkOrder ? `<span class="gpo-link-order">Link Order: ${gpo.LinkOrder}</span>` : ''}
                        </div>
                    `).join('')}
                </div>
            </div>
        </div>
    `;
}

/**
 * Renders the GPO registry settings table
 */
function renderGPORegistryTable(registryPolicies) {
    if (!registryPolicies || registryPolicies.length === 0) {
        return `
            <div class="info-box warning">
                No GPO registry policies found on this device.
            </div>
        `;
    }

    return `
        <div class="section">
            <div class="section-header">
                <h2>Registry Settings (${registryPolicies.length})</h2>
                <span class="toggle">▼</span>
            </div>
            <div class="section-body">
                <div class="filter-bar">
                    <input type="text" id="gpo-registry-search" placeholder="Search registry settings..." 
                           oninput="filterGPORegistryTable()">
                    <select id="gpo-scope-filter" onchange="filterGPORegistryTable()">
                        <option value="">All Scopes</option>
                        <option value="Machine">Machine</option>
                        <option value="User">User</option>
                    </select>
                </div>
                <div class="table-wrapper">
                    <table id="gpo-registry-table">
                        <thead>
                            <tr>
                                <th>Category</th>
                                <th>Registry Path</th>
                                <th>Value Name</th>
                                <th>Value</th>
                                <th>Scope</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${registryPolicies.map(policy => `
                                <tr data-scope="${escapeHtml(policy.Scope || '')}">
                                    <td>${escapeHtml(policy.Category || '-')}</td>
                                    <td class="path-cell">${escapeHtml(policy.Path || '-')}</td>
                                    <td>${escapeHtml(policy.ValueName || '-')}</td>
                                    <td>${escapeHtml(formatValue(policy.Data))}</td>
                                    <td><span class="scope-badge scope-${(policy.Scope || '').toLowerCase()}">${escapeHtml(policy.Scope || '-')}</span></td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    `;
}

/**
 * Filters the GPO registry table
 */
function filterGPORegistryTable() {
    const searchValue = (document.getElementById('gpo-registry-search')?.value || '').toLowerCase();
    const scopeFilter = document.getElementById('gpo-scope-filter')?.value || '';
    const table = document.getElementById('gpo-registry-table');
    if (!table) return;

    const rows = table.querySelectorAll('tbody tr');
    rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        const scope = row.dataset.scope || '';
        const matchesSearch = text.includes(searchValue);
        const matchesScope = !scopeFilter || scope === scopeFilter;
        row.style.display = (matchesSearch && matchesScope) ? '' : 'none';
    });
}

// ============================================================================
// INTUNE/MDM TAB
// ============================================================================

/**
 * Renders the Intune/MDM tab content
 */
function renderIntuneTab(deviceData) {
    const mdmData = deviceData.mdmData || {};
    const graphData = deviceData.graphData || {};
    const appData = deviceData.appData || {};
    const groupData = deviceData.groupData || {};

    const isEnrolled = mdmData.IsEnrolled || false;
    const devicePolicies = mdmData.DevicePolicies || [];
    const userPolicies = mdmData.UserPolicies || [];
    const allPolicies = [...devicePolicies, ...userPolicies];

    // Get compliance and profile data
    const profiles = graphData.Profiles || [];
    const compliancePolicies = graphData.CompliancePolicies || [];
    const settingsCatalog = graphData.SettingsCatalog || [];
    const apps = appData.AssignedApps || [];

    return `
        <div class="source-tab-content" id="tab-intune">
            ${renderIntuneSummaryCards(isEnrolled, allPolicies.length, profiles.length, compliancePolicies.length, apps.length)}
            ${renderEnrollmentStatus(mdmData)}
            ${renderIntuneProfilesSection(profiles, compliancePolicies, settingsCatalog, groupData)}
            ${renderIntuneAppsSection(appData, groupData)}
            ${renderMDMPoliciesTable(allPolicies)}
        </div>
    `;
}

/**
 * Renders Intune summary cards
 */
function renderIntuneSummaryCards(enrolled, policyCount, profileCount, complianceCount, appCount) {
    return `
        <div class="summary-grid">
            <div class="summary-card ${enrolled ? 'green' : 'yellow'}">
                <span class="number">${enrolled ? '✓' : '✗'}</span>
                <span class="label">Enrollment</span>
                <span class="description">${enrolled ? 'Device is MDM enrolled' : 'Not MDM enrolled'}</span>
            </div>
            <div class="summary-card blue">
                <span class="number">${policyCount}</span>
                <span class="label">MDM Policies</span>
                <span class="description">Active policy settings</span>
            </div>
            <div class="summary-card cyan">
                <span class="number">${profileCount}</span>
                <span class="label">Profiles</span>
                <span class="description">Configuration profiles</span>
            </div>
            <div class="summary-card magenta">
                <span class="number">${complianceCount}</span>
                <span class="label">Compliance</span>
                <span class="description">Compliance policies</span>
            </div>
            <div class="summary-card green">
                <span class="number">${appCount}</span>
                <span class="label">Apps</span>
                <span class="description">Assigned applications</span>
            </div>
        </div>
    `;
}

/**
 * Renders MDM enrollment status section
 */
function renderEnrollmentStatus(mdmData) {
    const isEnrolled = mdmData.IsEnrolled || false;
    const enrollments = mdmData.Enrollments || [];

    if (!isEnrolled) {
        return `
            <div class="callout warning">
                <span class="callout-icon">⚠️</span>
                <span class="callout-text">Device is not enrolled in MDM. Intune policies cannot be applied.</span>
            </div>
        `;
    }

    if (enrollments.length === 0) {
        return `
            <div class="info-box success">
                Device is MDM enrolled. Enrollment details not available.
            </div>
        `;
    }

    const enrollment = enrollments[0];
    return `
        <div class="section">
            <div class="section-header">
                <h2>Enrollment Details</h2>
                <span class="toggle">▼</span>
            </div>
            <div class="section-body">
                <div class="enrollment-grid">
                    ${enrollment.ProviderId ? `
                        <div class="enrollment-item">
                            <div class="key">Provider</div>
                            <div class="value">${escapeHtml(enrollment.ProviderId)}</div>
                        </div>
                    ` : ''}
                    ${enrollment.UPN ? `
                        <div class="enrollment-item">
                            <div class="key">User Principal Name</div>
                            <div class="value">${escapeHtml(enrollment.UPN)}</div>
                        </div>
                    ` : ''}
                    ${enrollment.AADTenantId ? `
                        <div class="enrollment-item">
                            <div class="key">Azure AD Tenant</div>
                            <div class="value">${escapeHtml(enrollment.AADTenantId)}</div>
                        </div>
                    ` : ''}
                    ${enrollment.EnrollmentId ? `
                        <div class="enrollment-item">
                            <div class="key">Enrollment ID</div>
                            <div class="value">${escapeHtml(enrollment.EnrollmentId)}</div>
                        </div>
                    ` : ''}
                </div>
            </div>
        </div>
    `;
}

/**
 * Renders Intune profiles and compliance section
 */
function renderIntuneProfilesSection(profiles, compliancePolicies, settingsCatalog, groupData) {
    const totalPolicies = profiles.length + compliancePolicies.length + settingsCatalog.length;
    
    if (totalPolicies === 0) {
        return '';
    }

    const deviceGroupIds = getDeviceGroupIds(groupData);
    const applicableProfiles = filterApplicablePolicies(profiles, deviceGroupIds);
    const applicableCompliance = filterApplicablePolicies(compliancePolicies, deviceGroupIds);
    const applicableCatalog = filterApplicablePolicies(settingsCatalog, deviceGroupIds);

    return `
        <div class="section">
            <div class="section-header">
                <h2>Assigned Profiles & Compliance (${applicableProfiles.length + applicableCompliance.length + applicableCatalog.length} applicable)</h2>
                <span class="toggle">▼</span>
            </div>
            <div class="section-body">
                ${applicableProfiles.length > 0 ? renderProfilesTable(applicableProfiles, 'Configuration Profiles', groupData) : ''}
                ${applicableCompliance.length > 0 ? renderComplianceTable(applicableCompliance, groupData) : ''}
                ${applicableCatalog.length > 0 ? renderSettingsCatalogTable(applicableCatalog, groupData) : ''}
                ${applicableProfiles.length + applicableCompliance.length + applicableCatalog.length === 0 ? `
                    <div class="info-box info">No Intune profiles or compliance policies are assigned to this device.</div>
                ` : ''}
            </div>
        </div>
    `;
}

/**
 * Renders configuration profiles table
 */
function renderProfilesTable(profiles, title, groupData) {
    return `
        <h3 style="margin: 15px 0 10px; color: var(--text-secondary);">${title} (${profiles.length})</h3>
        <div class="table-wrapper">
            <table>
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Type</th>
                        <th>Assigned Via</th>
                        <th>Modified</th>
                    </tr>
                </thead>
                <tbody>
                    ${profiles.map(p => {
                        const profileType = formatProfileType(p.OdataType);
                        const assignedVia = getAssignmentReason(p, getDeviceGroupIds(groupData), groupData);
                        return `
                            <tr>
                                <td><strong>${escapeHtml(p.DisplayName || p.Name || '-')}</strong></td>
                                <td>${escapeHtml(profileType)}</td>
                                <td>${assignedVia}</td>
                                <td>${p.LastModified ? formatDate(p.LastModified) : '-'}</td>
                            </tr>
                        `;
                    }).join('')}
                </tbody>
            </table>
        </div>
    `;
}

/**
 * Renders compliance policies table
 */
function renderComplianceTable(policies, groupData) {
    return `
        <h3 style="margin: 20px 0 10px; color: var(--text-secondary);">Compliance Policies (${policies.length})</h3>
        <div class="table-wrapper">
            <table>
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Type</th>
                        <th>Assigned Via</th>
                    </tr>
                </thead>
                <tbody>
                    ${policies.map(p => {
                        const policyType = formatProfileType(p.OdataType);
                        const assignedVia = getAssignmentReason(p, getDeviceGroupIds(groupData), groupData);
                        return `
                            <tr>
                                <td><strong>${escapeHtml(p.DisplayName || '-')}</strong></td>
                                <td>${escapeHtml(policyType)}</td>
                                <td>${assignedVia}</td>
                            </tr>
                        `;
                    }).join('')}
                </tbody>
            </table>
        </div>
    `;
}

/**
 * Renders Settings Catalog policies table
 */
function renderSettingsCatalogTable(policies, groupData) {
    return `
        <h3 style="margin: 20px 0 10px; color: var(--text-secondary);">Settings Catalog (${policies.length})</h3>
        <div class="table-wrapper">
            <table>
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Platform</th>
                        <th>Technologies</th>
                        <th>Assigned Via</th>
                    </tr>
                </thead>
                <tbody>
                    ${policies.map(p => {
                        const assignedVia = getAssignmentReason(p, getDeviceGroupIds(groupData), groupData);
                        return `
                            <tr>
                                <td><strong>${escapeHtml(p.Name || p.DisplayName || '-')}</strong></td>
                                <td>${escapeHtml(p.Platforms || '-')}</td>
                                <td>${escapeHtml(p.Technologies || '-')}</td>
                                <td>${assignedVia}</td>
                            </tr>
                        `;
                    }).join('')}
                </tbody>
            </table>
        </div>
    `;
}

/**
 * Renders Intune apps section
 */
function renderIntuneAppsSection(appData, groupData) {
    if (!appData?.Available) {
        return '';
    }

    const allApps = appData.AssignedApps || [];
    if (allApps.length === 0) {
        return '';
    }

    const deviceGroupIds = getDeviceGroupIds(groupData);
    const applicableApps = allApps.filter(app => appAppliesToDevice(app, deviceGroupIds));

    // Separate by intent
    const requiredApps = applicableApps.filter(app =>
        (app.Assignments || []).some(a => a.Intent === 'Required' && assignmentAppliesToDevice(a, deviceGroupIds))
    );
    const availableApps = applicableApps.filter(app =>
        (app.Assignments || []).some(a => a.Intent === 'Available' && assignmentAppliesToDevice(a, deviceGroupIds))
        && !requiredApps.includes(app)
    );

    return `
        <div class="section">
            <div class="section-header">
                <h2>App Assignments (${applicableApps.length} applicable)</h2>
                <span class="toggle">▼</span>
            </div>
            <div class="section-body">
                ${requiredApps.length > 0 ? `
                    <h3 style="margin: 10px 0; color: var(--accent-yellow);">Required Apps (${requiredApps.length})</h3>
                    <div class="app-grid">
                        ${requiredApps.map(app => renderAppCard(app, deviceGroupIds, groupData)).join('')}
                    </div>
                ` : ''}
                ${availableApps.length > 0 ? `
                    <h3 style="margin: 15px 0 10px; color: var(--accent-green);">Available Apps (${availableApps.length})</h3>
                    <div class="app-grid">
                        ${availableApps.map(app => renderAppCard(app, deviceGroupIds, groupData)).join('')}
                    </div>
                ` : ''}
                ${applicableApps.length === 0 ? `
                    <div class="info-box info">No apps are assigned to this device.</div>
                ` : ''}
            </div>
        </div>
    `;
}

/**
 * Renders a single app card
 */
function renderAppCard(app, deviceGroupIds, groupData) {
    const applicableAssignments = (app.Assignments || []).filter(a =>
        assignmentAppliesToDevice(a, deviceGroupIds)
    );

    const assignmentBadges = applicableAssignments.map(a => {
        const intentClass = (a.Intent || '').toLowerCase() === 'required' ? 'required' : 'available';
        let targetLabel = formatAssignmentTarget(a.TargetType, a.GroupId, groupData);
        return `<span class="app-intent ${intentClass}">${escapeHtml(a.Intent || '')}</span> ${targetLabel}`;
    }).join(' ');

    return `
        <div class="app-card">
            <div class="app-name">${escapeHtml(app.DisplayName || 'Unknown App')}</div>
            <div class="app-type">${escapeHtml(app.AppType || '')}${app.Publisher ? ' - ' + escapeHtml(app.Publisher) : ''}</div>
            <div class="app-assignments">${assignmentBadges}</div>
        </div>
    `;
}

/**
 * Renders MDM policies table
 */
function renderMDMPoliciesTable(policies) {
    if (policies.length === 0) {
        return '';
    }

    return `
        <div class="section">
            <div class="section-header">
                <h2>MDM Policy Settings (${policies.length})</h2>
                <span class="toggle">▼</span>
            </div>
            <div class="section-body">
                <div class="filter-bar">
                    <input type="text" id="mdm-policy-search" placeholder="Search MDM policies..."
                           oninput="filterMDMPoliciesTable()">
                    <select id="mdm-scope-filter" onchange="filterMDMPoliciesTable()">
                        <option value="">All Scopes</option>
                        <option value="Device">Device</option>
                        <option value="User">User</option>
                    </select>
                </div>
                <div class="table-wrapper">
                    <table id="mdm-policies-table">
                        <thead>
                            <tr>
                                <th>Area</th>
                                <th>Setting</th>
                                <th>Value</th>
                                <th>Scope</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${policies.map(p => `
                                <tr data-scope="${escapeHtml(p.Scope || '')}">
                                    <td>${escapeHtml(p.Area || '-')}</td>
                                    <td>${escapeHtml(p.Setting || '-')}</td>
                                    <td>${escapeHtml(formatValue(p.Value))}</td>
                                    <td><span class="scope-badge scope-${(p.Scope || '').toLowerCase()}">${escapeHtml(p.Scope || '-')}</span></td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    `;
}

/**
 * Filters MDM policies table
 */
function filterMDMPoliciesTable() {
    const searchValue = (document.getElementById('mdm-policy-search')?.value || '').toLowerCase();
    const scopeFilter = document.getElementById('mdm-scope-filter')?.value || '';
    const table = document.getElementById('mdm-policies-table');
    if (!table) return;

    const rows = table.querySelectorAll('tbody tr');
    rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        const scope = row.dataset.scope || '';
        const matchesSearch = text.includes(searchValue);
        const matchesScope = !scopeFilter || scope === scopeFilter;
        row.style.display = (matchesSearch && matchesScope) ? '' : 'none';
    });
}

// ============================================================================
// SCCM TAB
// ============================================================================

/**
 * Renders the SCCM tab content
 */
function renderSCCMTab(deviceData) {
    const sccmData = deviceData.sccmData || {};
    const isInstalled = sccmData.IsInstalled || false;

    if (!isInstalled) {
        return `
            <div class="source-tab-content" id="tab-sccm">
                <div class="summary-grid">
                    <div class="summary-card yellow">
                        <span class="number">✗</span>
                        <span class="label">SCCM Client</span>
                        <span class="description">ConfigMgr client not installed</span>
                    </div>
                </div>
                <div class="callout warning">
                    <span class="callout-icon">⚠️</span>
                    <span class="callout-text">SCCM/ConfigMgr client is not installed on this device.</span>
                </div>
            </div>
        `;
    }

    const clientInfo = sccmData.ClientInfo || {};
    const applications = sccmData.Applications || [];
    const baselines = sccmData.Baselines || [];
    const updates = sccmData.Updates || [];

    return `
        <div class="source-tab-content" id="tab-sccm">
            ${renderSCCMSummaryCards(applications.length, baselines.length, updates.length)}
            ${renderSCCMClientInfo(clientInfo)}
            ${renderSCCMApplicationsTable(applications)}
            ${renderSCCMBaselinesTable(baselines)}
            ${renderSCCMUpdatesTable(updates)}
        </div>
    `;
}

/**
 * Renders SCCM summary cards
 */
function renderSCCMSummaryCards(appCount, baselineCount, updateCount) {
    const requiredUpdates = updateCount; // This would need actual filtering in real data
    return `
        <div class="summary-grid">
            <div class="summary-card green">
                <span class="number">✓</span>
                <span class="label">SCCM Client</span>
                <span class="description">ConfigMgr client installed</span>
            </div>
            <div class="summary-card blue">
                <span class="number">${appCount}</span>
                <span class="label">Applications</span>
                <span class="description">SCCM deployed apps</span>
            </div>
            <div class="summary-card cyan">
                <span class="number">${baselineCount}</span>
                <span class="label">Baselines</span>
                <span class="description">Compliance baselines</span>
            </div>
            <div class="summary-card magenta">
                <span class="number">${updateCount}</span>
                <span class="label">Updates</span>
                <span class="description">Software updates</span>
            </div>
        </div>
    `;
}

/**
 * Renders SCCM client information
 */
function renderSCCMClientInfo(clientInfo) {
    if (!clientInfo || Object.keys(clientInfo).length === 0) {
        return '';
    }

    return `
        <div class="section">
            <div class="section-header">
                <h2>Client Information</h2>
                <span class="toggle">▼</span>
            </div>
            <div class="section-body">
                <div class="enrollment-grid">
                    ${clientInfo.ClientVersion ? `
                        <div class="enrollment-item">
                            <div class="key">Client Version</div>
                            <div class="value">${escapeHtml(clientInfo.ClientVersion)}</div>
                        </div>
                    ` : ''}
                    ${clientInfo.SiteCode ? `
                        <div class="enrollment-item">
                            <div class="key">Site Code</div>
                            <div class="value">${escapeHtml(clientInfo.SiteCode)}</div>
                        </div>
                    ` : ''}
                    ${clientInfo.ManagementPoint ? `
                        <div class="enrollment-item">
                            <div class="key">Management Point</div>
                            <div class="value">${escapeHtml(clientInfo.ManagementPoint)}</div>
                        </div>
                    ` : ''}
                    ${clientInfo.ClientId ? `
                        <div class="enrollment-item">
                            <div class="key">Client ID</div>
                            <div class="value">${escapeHtml(clientInfo.ClientId)}</div>
                        </div>
                    ` : ''}
                </div>
            </div>
        </div>
    `;
}

/**
 * Renders SCCM applications table
 */
function renderSCCMApplicationsTable(applications) {
    if (applications.length === 0) {
        return '';
    }

    return `
        <div class="section">
            <div class="section-header">
                <h2>Applications (${applications.length})</h2>
                <span class="toggle">▼</span>
            </div>
            <div class="section-body">
                <div class="filter-bar">
                    <input type="text" id="sccm-apps-search" placeholder="Search applications..."
                           oninput="filterSCCMAppsTable()">
                </div>
                <div class="table-wrapper">
                    <table id="sccm-apps-table">
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Publisher</th>
                                <th>Version</th>
                                <th>Install State</th>
                                <th>Required</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${applications.map(app => {
                                const stateClass = app.InstallState === 'Installed' ? 'both-match' : 
                                                   app.InstallState === 'Failed' ? 'conflict' : 'no-mapping';
                                return `
                                    <tr>
                                        <td><strong>${escapeHtml(app.Name || '-')}</strong></td>
                                        <td>${escapeHtml(app.Publisher || '-')}</td>
                                        <td>${escapeHtml(app.Version || '-')}</td>
                                        <td><span class="status-tag ${stateClass}">${escapeHtml(app.InstallState || '-')}</span></td>
                                        <td>${app.IsRequired ? 'Yes' : 'No'}</td>
                                    </tr>
                                `;
                            }).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    `;
}

/**
 * Filters SCCM applications table
 */
function filterSCCMAppsTable() {
    filterTableBySearch('sccm-apps-table', 'sccm-apps-search');
}

/**
 * Renders SCCM baselines table
 */
function renderSCCMBaselinesTable(baselines) {
    if (baselines.length === 0) {
        return '';
    }

    return `
        <div class="section">
            <div class="section-header">
                <h2>Compliance Baselines (${baselines.length})</h2>
                <span class="toggle">▼</span>
            </div>
            <div class="section-body">
                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Version</th>
                                <th>Compliance State</th>
                                <th>Last Evaluated</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${baselines.map(b => {
                                const stateClass = b.ComplianceState === 'Compliant' ? 'both-match' :
                                                   b.ComplianceState === 'Non-Compliant' ? 'conflict' : 'no-mapping';
                                return `
                                    <tr>
                                        <td><strong>${escapeHtml(b.Name || '-')}</strong></td>
                                        <td>${escapeHtml(b.Version || '-')}</td>
                                        <td><span class="status-tag ${stateClass}">${escapeHtml(b.ComplianceState || '-')}</span></td>
                                        <td>${b.LastEvaluated ? formatDate(b.LastEvaluated) : '-'}</td>
                                    </tr>
                                `;
                            }).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    `;
}

/**
 * Renders SCCM updates table
 */
function renderSCCMUpdatesTable(updates) {
    if (updates.length === 0) {
        return '';
    }

    const requiredUpdates = updates.filter(u => u.IsRequired);
    const displayLimit = 50;

    return `
        <div class="section">
            <div class="section-header collapsed">
                <h2>Software Updates (${updates.length} total, ${requiredUpdates.length} required)</h2>
                <span class="toggle">▼</span>
            </div>
            <div class="section-body hidden">
                <div class="filter-bar">
                    <input type="text" id="sccm-updates-search" placeholder="Search updates..."
                           oninput="filterSCCMUpdatesTable()">
                </div>
                <div class="table-wrapper" style="max-height: 400px;">
                    <table id="sccm-updates-table">
                        <thead>
                            <tr>
                                <th>Article ID</th>
                                <th>Name</th>
                                <th>State</th>
                                <th>Required</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${updates.slice(0, displayLimit).map(u => `
                                <tr>
                                    <td>${escapeHtml(u.ArticleID || '-')}</td>
                                    <td>${escapeHtml(u.Name || '-')}</td>
                                    <td>${escapeHtml(u.EvaluationState || '-')}</td>
                                    <td>${u.IsRequired ? 'Yes' : 'No'}</td>
                                </tr>
                            `).join('')}
                            ${updates.length > displayLimit ? `
                                <tr>
                                    <td colspan="4" style="text-align: center; color: var(--text-secondary);">
                                        ... and ${updates.length - displayLimit} more updates
                                    </td>
                                </tr>
                            ` : ''}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    `;
}

/**
 * Filters SCCM updates table
 */
function filterSCCMUpdatesTable() {
    filterTableBySearch('sccm-updates-table', 'sccm-updates-search');
}

// ============================================================================
// AZURE AD TAB
// ============================================================================

/**
 * Renders the Azure AD tab content
 */
function renderAzureADTab(deviceData) {
    const groupData = deviceData.groupData || {};

    if (!groupData.Available || !groupData.DeviceFound) {
        return `
            <div class="source-tab-content" id="tab-azuread">
                <div class="summary-grid">
                    <div class="summary-card yellow">
                        <span class="number">?</span>
                        <span class="label">Azure AD</span>
                        <span class="description">Group data not available</span>
                    </div>
                </div>
                <div class="callout warning">
                    <span class="callout-icon">⚠️</span>
                    <span class="callout-text">Azure AD group membership data not available. Run export with <code>-IncludeGraph</code> to include this data.</span>
                </div>
            </div>
        `;
    }

    const groups = groupData.Groups || [];
    const deviceInfo = groupData.Device || {};

    // Separate groups by type
    const dynamicGroups = groups.filter(g => g.GroupType === 'Dynamic');
    const assignedGroups = groups.filter(g => g.GroupType !== 'Dynamic');

    return `
        <div class="source-tab-content" id="tab-azuread">
            ${renderAzureADSummaryCards(groups.length, dynamicGroups.length, assignedGroups.length, deviceInfo)}
            ${renderAzureADDeviceInfo(deviceInfo)}
            ${renderAzureADGroupMemberships(groups, dynamicGroups, assignedGroups)}
        </div>
    `;
}

/**
 * Renders Azure AD summary cards
 */
function renderAzureADSummaryCards(totalGroups, dynamicCount, assignedCount, deviceInfo) {
    const isManaged = deviceInfo.IsManaged === true || deviceInfo.IsManaged === 'True';
    const isCompliant = deviceInfo.IsCompliant === true || deviceInfo.IsCompliant === 'True';

    return `
        <div class="summary-grid">
            <div class="summary-card blue">
                <span class="number">${totalGroups}</span>
                <span class="label">Total Groups</span>
                <span class="description">Azure AD group memberships</span>
            </div>
            <div class="summary-card cyan">
                <span class="number">${dynamicCount}</span>
                <span class="label">Dynamic Groups</span>
                <span class="description">Auto-assigned memberships</span>
            </div>
            <div class="summary-card magenta">
                <span class="number">${assignedCount}</span>
                <span class="label">Assigned Groups</span>
                <span class="description">Manually assigned memberships</span>
            </div>
            <div class="summary-card ${isManaged ? 'green' : 'yellow'}">
                <span class="number">${isManaged ? '✓' : '✗'}</span>
                <span class="label">Managed</span>
                <span class="description">${isManaged ? 'Device is managed' : 'Not managed'}</span>
            </div>
            <div class="summary-card ${isCompliant ? 'green' : 'red'}">
                <span class="number">${isCompliant ? '✓' : '✗'}</span>
                <span class="label">Compliant</span>
                <span class="description">${isCompliant ? 'Device is compliant' : 'Non-compliant'}</span>
            </div>
        </div>
    `;
}

/**
 * Renders Azure AD device information
 */
function renderAzureADDeviceInfo(deviceInfo) {
    if (!deviceInfo || Object.keys(deviceInfo).length === 0) {
        return '';
    }

    return `
        <div class="section">
            <div class="section-header">
                <h2>Azure AD Device Details</h2>
                <span class="toggle">▼</span>
            </div>
            <div class="section-body">
                <div class="enrollment-grid">
                    ${deviceInfo.DisplayName ? `
                        <div class="enrollment-item">
                            <div class="key">Display Name</div>
                            <div class="value">${escapeHtml(deviceInfo.DisplayName)}</div>
                        </div>
                    ` : ''}
                    ${deviceInfo.DeviceId ? `
                        <div class="enrollment-item">
                            <div class="key">Device ID</div>
                            <div class="value">${escapeHtml(deviceInfo.DeviceId)}</div>
                        </div>
                    ` : ''}
                    ${deviceInfo.OperatingSystem || deviceInfo.OSVersion ? `
                        <div class="enrollment-item">
                            <div class="key">Operating System</div>
                            <div class="value">${escapeHtml(deviceInfo.OperatingSystem || '')} ${escapeHtml(deviceInfo.OSVersion || '')}</div>
                        </div>
                    ` : ''}
                    ${deviceInfo.TrustType ? `
                        <div class="enrollment-item">
                            <div class="key">Trust Type</div>
                            <div class="value">${escapeHtml(deviceInfo.TrustType)}</div>
                        </div>
                    ` : ''}
                    ${deviceInfo.IsManaged !== undefined ? `
                        <div class="enrollment-item">
                            <div class="key">Managed</div>
                            <div class="value">${deviceInfo.IsManaged}</div>
                        </div>
                    ` : ''}
                    ${deviceInfo.IsCompliant !== undefined ? `
                        <div class="enrollment-item">
                            <div class="key">Compliant</div>
                            <div class="value">${deviceInfo.IsCompliant}</div>
                        </div>
                    ` : ''}
                </div>
            </div>
        </div>
    `;
}

/**
 * Renders Azure AD group memberships section
 */
function renderAzureADGroupMemberships(groups, dynamicGroups, assignedGroups) {
    if (groups.length === 0) {
        return `
            <div class="info-box info">
                This device is not a member of any Azure AD groups.
            </div>
        `;
    }

    return `
        <div class="section">
            <div class="section-header">
                <h2>Group Memberships (${groups.length})</h2>
                <span class="toggle">▼</span>
            </div>
            <div class="section-body">
                <div class="filter-bar">
                    <input type="text" id="azuread-groups-search" placeholder="Search groups..."
                           oninput="filterAzureADGroupsTable()">
                </div>
                
                ${dynamicGroups.length > 0 ? `
                    <h3 style="margin: 15px 0 10px; color: var(--accent-cyan);">Dynamic Memberships (${dynamicGroups.length})</h3>
                    <div class="group-list" id="dynamic-groups-list">
                        ${dynamicGroups.map(g => renderGroupChip(g, 'dynamic')).join('')}
                    </div>
                ` : ''}
                
                ${assignedGroups.length > 0 ? `
                    <h3 style="margin: 20px 0 10px; color: var(--accent-blue);">Assigned Memberships (${assignedGroups.length})</h3>
                    <div class="group-list" id="assigned-groups-list">
                        ${assignedGroups.map(g => renderGroupChip(g, 'assigned')).join('')}
                    </div>
                ` : ''}

                <h3 style="margin: 20px 0 10px; color: var(--text-secondary);">Full Group Details</h3>
                <div class="table-wrapper">
                    <table id="azuread-groups-table">
                        <thead>
                            <tr>
                                <th>Display Name</th>
                                <th>Type</th>
                                <th>Description</th>
                                <th>Object ID</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${groups.map(g => `
                                <tr>
                                    <td><strong>${escapeHtml(g.DisplayName || '-')}</strong></td>
                                    <td><span class="group-type-badge ${(g.GroupType || '').toLowerCase()}">${escapeHtml(g.GroupType || 'Assigned')}</span></td>
                                    <td>${escapeHtml(g.Description || '-')}</td>
                                    <td class="monospace">${escapeHtml(g.ObjectId || '-')}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    `;
}

/**
 * Renders a group chip
 */
function renderGroupChip(group, typeClass) {
    const description = group.Description || 'No description';
    return `<span class="group-chip ${typeClass}" title="${escapeHtml(description)}">${escapeHtml(group.DisplayName || 'Unknown Group')}</span>`;
}

/**
 * Filters Azure AD groups table
 */
function filterAzureADGroupsTable() {
    filterTableBySearch('azuread-groups-table', 'azuread-groups-search');
}

// ============================================================================
// MIGRATION ANALYSIS (COLLAPSIBLE)
// ============================================================================

/**
 * Renders the migration analysis section
 */
function renderMigrationAnalysis(deviceData) {
    const analysis = deviceData.analysis || {};
    const summary = analysis.Summary || {};
    const detailedResults = analysis.DetailedResults || [];

    const matches = summary.BothConfiguredMatch || 0;
    const conflicts = summary.ValuesInConflict || 0;
    const migrationReady = summary.GPOOnlyWithMapping || 0;
    const noMapping = summary.GPOOnlyNoMapping || 0;
    const total = matches + conflicts + migrationReady + noMapping;

    if (total === 0 && detailedResults.length === 0) {
        return '';
    }

    return `
        <div class="section migration-section" style="margin-top: 30px;">
            <div class="section-header collapsed">
                <h2>📊 Migration Analysis (${total} settings analyzed)</h2>
                <span class="toggle">▼</span>
            </div>
            <div class="section-body hidden">
                <div class="info-box explanation">
                    Analysis of GPO vs Intune/MDM policy overlap to help plan migration.
                </div>
                
                <div class="summary-grid">
                    <div class="summary-card green">
                        <span class="number">${matches}</span>
                        <span class="label">Matches</span>
                        <span class="description">Same setting, same value in both</span>
                    </div>
                    <div class="summary-card red">
                        <span class="number">${conflicts}</span>
                        <span class="label">Conflicts</span>
                        <span class="description">Different values - needs review</span>
                    </div>
                    <div class="summary-card cyan">
                        <span class="number">${migrationReady}</span>
                        <span class="label">Migration Ready</span>
                        <span class="description">GPO-only with Intune mapping</span>
                    </div>
                    <div class="summary-card magenta">
                        <span class="number">${noMapping}</span>
                        <span class="label">No Mapping</span>
                        <span class="description">GPO-only, no Intune equivalent</span>
                    </div>
                </div>

                ${conflicts > 0 ? `
                    <div class="callout warning">
                        <span class="callout-icon">⚠️</span>
                        <span class="callout-text"><strong>${conflicts} conflict(s) detected</strong> - These settings have different values in GPO vs Intune and need review before migration.</span>
                    </div>
                ` : ''}

                ${detailedResults.length > 0 ? renderMigrationDetailsTable(detailedResults) : ''}
            </div>
        </div>
    `;
}

/**
 * Renders the migration details table
 */
function renderMigrationDetailsTable(results) {
    return `
        <div class="legend-box" style="margin-top: 15px;">
            <div class="legend-item">
                <span class="legend-color match"></span>
                <span><span class="legend-label">Match</span> <span class="legend-desc">- Same value in both</span></span>
            </div>
            <div class="legend-item">
                <span class="legend-color conflict"></span>
                <span><span class="legend-label">Conflict</span> <span class="legend-desc">- Different values</span></span>
            </div>
            <div class="legend-item">
                <span class="legend-color migration"></span>
                <span><span class="legend-label">Migration Ready</span> <span class="legend-desc">- Can migrate to Intune</span></span>
            </div>
            <div class="legend-item">
                <span class="legend-color nomapping"></span>
                <span><span class="legend-label">No Mapping</span> <span class="legend-desc">- No Intune equivalent</span></span>
            </div>
        </div>

        <div class="filter-bar">
            <input type="text" id="migration-search" placeholder="Search migration analysis..."
                   oninput="filterMigrationTable()">
            <select id="migration-status-filter" onchange="filterMigrationTable()">
                <option value="">All Statuses</option>
                <option value="BothConfigured">Both Configured</option>
                <option value="GPOOnly_MappingExists">Migration Ready</option>
                <option value="GPOOnly_NoMapping">No MDM Mapping</option>
            </select>
        </div>

        <div class="table-wrapper">
            <table id="migration-table">
                <thead>
                    <tr>
                        <th>Status</th>
                        <th>Category</th>
                        <th>GPO Setting</th>
                        <th>GPO Value</th>
                        <th>MDM Setting</th>
                        <th>MDM Value</th>
                    </tr>
                </thead>
                <tbody>
                    ${results.map(r => {
                        const { rowClass, statusClass, statusText } = getMigrationRowStyles(r);
                        const mdmSetting = r.MDMArea && r.MDMSetting ? `${r.MDMArea}/${r.MDMSetting}` : '-';
                        
                        return `
                            <tr class="${rowClass}" data-status="${r.Status || ''}">
                                <td><span class="status-tag ${statusClass}">${statusText}</span></td>
                                <td>${escapeHtml(r.Category || '-')}</td>
                                <td>${escapeHtml(r.GPOValueName || '-')}</td>
                                <td>${escapeHtml(formatValue(r.GPOValue))}</td>
                                <td>${escapeHtml(mdmSetting)}</td>
                                <td>${escapeHtml(formatValue(r.MDMValue))}</td>
                            </tr>
                        `;
                    }).join('')}
                </tbody>
            </table>
        </div>
    `;
}

/**
 * Gets row styling for migration status
 */
function getMigrationRowStyles(result) {
    let rowClass = '';
    let statusClass = '';
    let statusText = '';

    if (result.Status === 'BothConfigured') {
        if (result.ValuesMatch) {
            rowClass = 'status-both-match';
            statusClass = 'both-match';
            statusText = 'Match';
        } else {
            rowClass = 'status-both-conflict';
            statusClass = 'conflict';
            statusText = 'Conflict';
        }
    } else if (result.Status === 'GPOOnly_MappingExists') {
        rowClass = 'status-gpo-mapping';
        statusClass = 'migration-ready';
        statusText = 'Migration Ready';
    } else if (result.Status === 'GPOOnly_NoMapping') {
        rowClass = 'status-gpo-nomapping';
        statusClass = 'no-mapping';
        statusText = 'No Mapping';
    } else {
        rowClass = '';
        statusClass = '';
        statusText = result.Status || 'Unknown';
    }

    return { rowClass, statusClass, statusText };
}

/**
 * Filters migration analysis table
 */
function filterMigrationTable() {
    const searchValue = (document.getElementById('migration-search')?.value || '').toLowerCase();
    const statusFilter = document.getElementById('migration-status-filter')?.value || '';
    const table = document.getElementById('migration-table');
    if (!table) return;

    const rows = table.querySelectorAll('tbody tr');
    rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        const status = row.dataset.status || '';
        const matchesSearch = text.includes(searchValue);
        const matchesStatus = !statusFilter || status === statusFilter;
        row.style.display = (matchesSearch && matchesStatus) ? '' : 'none';
    });
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Gets all group IDs the device is a member of
 */
function getDeviceGroupIds(groupData) {
    if (!groupData?.Available || !groupData?.DeviceFound || !groupData?.Groups) {
        return [];
    }
    return groupData.Groups.map(g => g.ObjectId).filter(id => id);
}

/**
 * Filters policies that apply to the device
 */
function filterApplicablePolicies(policies, deviceGroupIds) {
    return policies.filter(p => policyAppliesToDevice(p, deviceGroupIds));
}

/**
 * Checks if a policy applies to the device based on assignments
 */
function policyAppliesToDevice(policy, deviceGroupIds) {
    const assignments = policy.Assignments || [];
    if (assignments.length === 0) return false;

    let isIncluded = false;
    let isExcluded = false;

    for (const assignment of assignments) {
        const targetType = (assignment.TargetType || '').replace('#microsoft.graph.', '');
        const groupId = assignment.GroupId;

        if (targetType === 'allDevicesAssignmentTarget' || targetType === 'allLicensedUsersAssignmentTarget') {
            isIncluded = true;
        } else if (targetType === 'groupAssignmentTarget' && groupId && deviceGroupIds.includes(groupId)) {
            isIncluded = true;
        } else if (targetType === 'exclusionGroupAssignmentTarget' && groupId && deviceGroupIds.includes(groupId)) {
            isExcluded = true;
        }
    }

    return isIncluded && !isExcluded;
}

/**
 * Checks if an app applies to the device
 */
function appAppliesToDevice(app, deviceGroupIds) {
    const assignments = app.Assignments || [];
    return assignments.some(a => assignmentAppliesToDevice(a, deviceGroupIds));
}

/**
 * Checks if a single assignment applies to the device
 */
function assignmentAppliesToDevice(assignment, deviceGroupIds) {
    const targetType = assignment.TargetType || '';
    const groupId = assignment.GroupId;

    if (targetType === 'All Devices' || targetType === 'All Users') {
        return true;
    }

    if (targetType.startsWith('Group:') && groupId && deviceGroupIds.includes(groupId)) {
        return true;
    }

    return false;
}

/**
 * Gets human-readable assignment reason
 */
function getAssignmentReason(policy, deviceGroupIds, groupData) {
    const assignments = policy.Assignments || [];
    const reasons = [];

    for (const assignment of assignments) {
        const targetType = (assignment.TargetType || '').replace('#microsoft.graph.', '');
        const groupId = assignment.GroupId;

        if (targetType === 'allDevicesAssignmentTarget') {
            reasons.push('<span class="status-tag both-match">All Devices</span>');
        } else if (targetType === 'allLicensedUsersAssignmentTarget') {
            reasons.push('<span class="status-tag migration-ready">All Users</span>');
        } else if (targetType === 'groupAssignmentTarget' && groupId && deviceGroupIds.includes(groupId)) {
            const group = groupData?.Groups?.find(g => g.ObjectId === groupId);
            const groupName = group?.DisplayName || 'Group';
            reasons.push(`<span class="status-tag mdm-only" title="${escapeHtml(groupId)}">${escapeHtml(groupName)}</span>`);
        }
    }

    return reasons.length > 0 ? reasons.join(' ') : '-';
}

/**
 * Formats assignment target for display
 */
function formatAssignmentTarget(targetType, groupId, groupData) {
    if (targetType === 'All Devices') {
        return '<span class="status-tag both-match">All Devices</span>';
    } else if (targetType === 'All Users') {
        return '<span class="status-tag migration-ready">All Users</span>';
    } else if (groupId && groupData?.Groups) {
        const group = groupData.Groups.find(g => g.ObjectId === groupId);
        const groupName = group?.DisplayName || 'Group';
        return `<span class="status-tag mdm-only">${escapeHtml(groupName)}</span>`;
    }
    return `<span class="status-tag">${escapeHtml(targetType || '')}</span>`;
}

/**
 * Formats profile type for display
 */
function formatProfileType(odataType) {
    if (!odataType) return '-';
    return odataType
        .replace('#microsoft.graph.', '')
        .replace(/([A-Z])/g, ' $1')
        .trim();
}

/**
 * Generic table filter by search input
 */
function filterTableBySearch(tableId, searchInputId) {
    const searchValue = (document.getElementById(searchInputId)?.value || '').toLowerCase();
    const table = document.getElementById(tableId);
    if (!table) return;

    const rows = table.querySelectorAll('tbody tr');
    rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(searchValue) ? '' : 'none';
    });
}

/**
 * Formats a value for display
 */
function formatValue(val) {
    if (val === null || val === undefined) return '-';
    if (typeof val === 'object') return JSON.stringify(val);
    return String(val);
}

/**
 * Escapes HTML special characters
 */
function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
}

/**
 * Formats ISO date string for display
 */
function formatDate(isoString) {
    if (!isoString) return '';
    try {
        const date = new Date(isoString);
        return date.toLocaleString();
    } catch {
        return isoString;
    }
}

// ============================================================================
// INITIALIZATION
// ============================================================================

/**
 * Initializes collapsible sections after rendering
 */
function initSingleViewCollapsibles() {
    document.querySelectorAll('.single-view-container .section-header').forEach(header => {
        header.addEventListener('click', function() {
            this.classList.toggle('collapsed');
            const body = this.nextElementSibling;
            if (body) {
                body.classList.toggle('hidden');
            }
        });
    });
}

/**
 * Initialize the single view after rendering
 * Call this after inserting renderSingleView output into the DOM
 */
function initSingleView() {
    initSingleViewCollapsibles();
    // Default to GPO tab
    switchSourceTab('gpo');
}

// Export functions for use in main viewer
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        renderSingleView,
        initSingleView,
        switchSourceTab,
        filterGPORegistryTable,
        filterMDMPoliciesTable,
        filterMigrationTable,
        filterSCCMAppsTable,
        filterSCCMUpdatesTable,
        filterAzureADGroupsTable
    };
}
