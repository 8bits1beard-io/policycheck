/**
 * PolicyLens Comparison View - Multi-Device Comparison Functions
 * Supports comparing 2-3 devices across GPO, Intune, SCCM, and Azure AD sources
 */

// ============================================================================
// MAIN RENDERER
// ============================================================================

/**
 * Main entry point for rendering the comparison view
 * @param {Array} devices - Array of 2-3 device objects
 * @returns {string} HTML string for the comparison view
 */
function renderComparisonView(devices) {
    if (!devices || devices.length < 2 || devices.length > 3) {
        return `<div class="info-box warning">Please select 2 or 3 devices to compare.</div>`;
    }

    const deviceNames = devices.map(d => d.device?.computerName || 'Unknown Device');
    
    // Compute all comparisons
    const gpoComparison = compareGPOSettings(devices);
    const intuneComparison = compareIntuneSettings(devices);
    const sccmComparison = compareSCCMSettings(devices);
    const azureADComparison = compareAzureADGroups(devices);
    
    // Calculate summary
    const summary = {
        gpo: gpoComparison.differences,
        intune: intuneComparison.differences,
        sccm: sccmComparison.differences,
        azureAD: azureADComparison.differences,
        total: gpoComparison.differences + intuneComparison.differences + 
               sccmComparison.differences + azureADComparison.differences
    };

    return `
        <div class="report-header">
            <h1>Device Comparison</h1>
            <div class="subtitle">${deviceNames.map(n => escapeHtml(n)).join(' vs ')}</div>
        </div>
        
        ${renderComparisonSummary(summary, deviceNames)}
        ${renderDifferenceToggle()}
        
        ${renderGPOComparisonSection(gpoComparison, deviceNames)}
        ${renderIntuneComparisonSection(intuneComparison, deviceNames)}
        ${renderSCCMComparisonSection(sccmComparison, deviceNames)}
        ${renderAzureADComparisonSection(azureADComparison, deviceNames)}
    `;
}

// ============================================================================
// SUMMARY RENDERING
// ============================================================================

/**
 * Renders the summary cards showing total differences per source
 */
function renderComparisonSummary(summary, deviceNames) {
    return `
        <div class="summary-section">
            <div class="summary-section-header">Comparison Summary - ${deviceNames.length} Devices</div>
            <div class="summary-grid">
                <div class="summary-card ${summary.total > 0 ? 'red' : 'green'}">
                    <span class="number">${summary.total}</span>
                    <span class="label">Total Differences</span>
                </div>
                <div class="summary-card ${summary.gpo > 0 ? 'yellow' : 'green'}">
                    <span class="number">${summary.gpo}</span>
                    <span class="label">GPO Differences</span>
                </div>
                <div class="summary-card ${summary.intune > 0 ? 'yellow' : 'green'}">
                    <span class="number">${summary.intune}</span>
                    <span class="label">Intune Differences</span>
                </div>
                <div class="summary-card ${summary.sccm > 0 ? 'yellow' : 'green'}">
                    <span class="number">${summary.sccm}</span>
                    <span class="label">SCCM Differences</span>
                </div>
                <div class="summary-card ${summary.azureAD > 0 ? 'yellow' : 'green'}">
                    <span class="number">${summary.azureAD}</span>
                    <span class="label">Azure AD Differences</span>
                </div>
            </div>
        </div>
    `;
}

/**
 * Renders the toggle control to show/hide identical rows
 */
function renderDifferenceToggle() {
    return `
        <div class="filter-bar" style="margin-bottom: 20px;">
            <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                <input type="checkbox" id="hide-identical-rows" onchange="toggleIdenticalRows(this.checked)">
                <span>Show differences only (hide identical rows)</span>
            </label>
        </div>
    `;
}

/**
 * Toggle function to show/hide identical rows across all comparison tables
 */
function toggleIdenticalRows(hideIdentical) {
    const rows = document.querySelectorAll('.comparison-row');
    rows.forEach(row => {
        if (row.classList.contains('row-identical')) {
            row.style.display = hideIdentical ? 'none' : '';
        }
    });
}

// ============================================================================
// GPO COMPARISON
// ============================================================================

/**
 * Compares GPO settings across devices
 */
function compareGPOSettings(devices) {
    const result = {
        gpoObjects: compareGPOObjects(devices),
        registrySettings: compareRegistrySettings(devices),
        differences: 0
    };
    
    result.differences = result.gpoObjects.filter(r => r.hasDifference).length +
                         result.registrySettings.filter(r => r.hasDifference).length;
    
    return result;
}

/**
 * Compares which GPOs are applied to which devices
 */
function compareGPOObjects(devices) {
    // Collect all unique GPO names across all devices
    const allGPOs = new Map();
    
    devices.forEach((device, idx) => {
        const gpos = device.gpoData?.AppliedGPOs || [];
        gpos.forEach(gpo => {
            const key = gpo.Name || gpo.DisplayName || 'Unknown GPO';
            if (!allGPOs.has(key)) {
                allGPOs.set(key, { 
                    name: key, 
                    devices: new Array(devices.length).fill(null)
                });
            }
            allGPOs.get(key).devices[idx] = gpo;
        });
    });
    
    // Convert to comparison rows
    return Array.from(allGPOs.values()).map(entry => {
        const appliedCount = entry.devices.filter(d => d !== null).length;
        return {
            name: entry.name,
            cells: entry.devices.map(d => d ? { applied: true, value: '✓' } : { applied: false, value: '✗' }),
            hasDifference: appliedCount > 0 && appliedCount < devices.length
        };
    }).sort((a, b) => {
        // Sort differences first
        if (a.hasDifference !== b.hasDifference) return a.hasDifference ? -1 : 1;
        return a.name.localeCompare(b.name);
    });
}

/**
 * Compares registry settings from GPO across devices
 */
function compareRegistrySettings(devices) {
    // Collect all unique registry settings
    const allSettings = new Map();
    
    devices.forEach((device, idx) => {
        const settings = device.gpoData?.RegistryPolicies || [];
        settings.forEach(setting => {
            const key = `${setting.Path || ''}|${setting.ValueName || ''}|${setting.Scope || ''}`;
            if (!allSettings.has(key)) {
                allSettings.set(key, {
                    path: setting.Path || '',
                    valueName: setting.ValueName || '',
                    scope: setting.Scope || '',
                    category: setting.Category || '',
                    devices: new Array(devices.length).fill(null)
                });
            }
            allSettings.get(key).devices[idx] = setting;
        });
    });
    
    // Convert to comparison rows
    return Array.from(allSettings.values()).map(entry => {
        const values = entry.devices.map(d => d ? formatValue(d.Data) : null);
        const nonNullValues = values.filter(v => v !== null);
        const uniqueValues = [...new Set(nonNullValues)];
        const hasDifference = nonNullValues.length !== devices.length || uniqueValues.length > 1;
        
        return {
            path: entry.path,
            valueName: entry.valueName,
            scope: entry.scope,
            category: entry.category,
            cells: entry.devices.map(d => ({
                applied: d !== null,
                value: d ? formatValue(d.Data) : '✗'
            })),
            hasDifference
        };
    }).sort((a, b) => {
        if (a.hasDifference !== b.hasDifference) return a.hasDifference ? -1 : 1;
        return `${a.path}|${a.valueName}`.localeCompare(`${b.path}|${b.valueName}`);
    });
}

/**
 * Renders the GPO comparison section
 */
function renderGPOComparisonSection(comparison, deviceNames) {
    const totalRows = comparison.gpoObjects.length + comparison.registrySettings.length;
    const diffRows = comparison.differences;
    
    return `
        <div class="section">
            <div class="section-header">
                <h2>🖥️ GPO Comparison (${diffRows} differences of ${totalRows} items)</h2>
                <span class="toggle">▼</span>
            </div>
            <div class="section-body">
                ${comparison.gpoObjects.length > 0 ? `
                    <h3 style="margin: 0 0 10px; color: var(--text-secondary);">Applied GPOs</h3>
                    ${renderComparisonTable(
                        ['GPO Name', ...deviceNames],
                        comparison.gpoObjects.map(row => ({
                            cells: [row.name, ...row.cells.map(c => c.value)],
                            hasDifference: row.hasDifference,
                            cellClasses: ['', ...row.cells.map(c => c.applied ? 'cell-applied' : 'cell-not-applied')]
                        })),
                        'gpo-objects'
                    )}
                ` : ''}
                
                <h3 style="margin: 20px 0 10px; color: var(--text-secondary);">Registry Settings</h3>
                <div class="filter-bar">
                    <input type="text" id="gpo-compare-search" placeholder="Search registry settings..." 
                           oninput="filterComparisonTable('gpo-registry-table', this.value)">
                </div>
                ${comparison.registrySettings.length > 0 ? 
                    renderComparisonTable(
                        ['Category', 'Path', 'Value Name', ...deviceNames],
                        comparison.registrySettings.map(row => ({
                            cells: [row.category, row.path, row.valueName, ...row.cells.map(c => c.value)],
                            hasDifference: row.hasDifference,
                            cellClasses: ['', '', '', ...row.cells.map(c => c.applied ? 'cell-applied' : 'cell-not-applied')]
                        })),
                        'gpo-registry'
                    ) : '<p style="color: var(--text-secondary);">No registry settings found.</p>'
                }
            </div>
        </div>
    `;
}

// ============================================================================
// INTUNE COMPARISON
// ============================================================================

/**
 * Compares Intune settings across devices
 */
function compareIntuneSettings(devices) {
    const result = {
        profiles: compareIntuneProfiles(devices),
        apps: compareIntuneApps(devices),
        mdmPolicies: compareMDMPolicies(devices),
        differences: 0
    };
    
    result.differences = result.profiles.filter(r => r.hasDifference).length +
                         result.apps.filter(r => r.hasDifference).length +
                         result.mdmPolicies.filter(r => r.hasDifference).length;
    
    return result;
}

/**
 * Compares Intune configuration profiles across devices
 */
function compareIntuneProfiles(devices) {
    const allProfiles = new Map();
    
    devices.forEach((device, idx) => {
        const deviceGroupIds = getDeviceGroupIds(device.groupData);
        const profiles = device.graphData?.Profiles || [];
        const settingsCatalog = device.graphData?.SettingsCatalog || [];
        const compliance = device.graphData?.CompliancePolicies || [];
        
        // Filter to applicable profiles
        const applicableProfiles = profiles.filter(p => policyAppliesToDevice(p, deviceGroupIds));
        const applicableCatalog = settingsCatalog.filter(p => policyAppliesToDevice(p, deviceGroupIds));
        const applicableCompliance = compliance.filter(p => policyAppliesToDevice(p, deviceGroupIds));
        
        [...applicableProfiles, ...applicableCatalog, ...applicableCompliance].forEach(profile => {
            const key = profile.Id || profile.DisplayName || profile.Name;
            const name = profile.DisplayName || profile.Name || 'Unknown Profile';
            if (!allProfiles.has(key)) {
                allProfiles.set(key, {
                    name: name,
                    type: getProfileType(profile),
                    devices: new Array(devices.length).fill(null)
                });
            }
            allProfiles.get(key).devices[idx] = profile;
        });
    });
    
    return Array.from(allProfiles.values()).map(entry => {
        const appliedCount = entry.devices.filter(d => d !== null).length;
        return {
            name: entry.name,
            type: entry.type,
            cells: entry.devices.map(d => d ? { applied: true, value: '✓' } : { applied: false, value: '✗' }),
            hasDifference: appliedCount > 0 && appliedCount < devices.length
        };
    }).sort((a, b) => {
        if (a.hasDifference !== b.hasDifference) return a.hasDifference ? -1 : 1;
        return a.name.localeCompare(b.name);
    });
}

/**
 * Helper to get profile type label
 */
function getProfileType(profile) {
    if (profile.OdataType) {
        return profile.OdataType.replace('#microsoft.graph.', '')
            .replace(/([A-Z])/g, ' $1').trim();
    }
    if (profile.Technologies) return 'Settings Catalog';
    return 'Unknown';
}

/**
 * Compares Intune app assignments across devices
 */
function compareIntuneApps(devices) {
    const allApps = new Map();
    
    devices.forEach((device, idx) => {
        const deviceGroupIds = getDeviceGroupIds(device.groupData);
        const apps = device.appData?.AssignedApps || [];
        
        const applicableApps = apps.filter(app => appAppliesToDevice(app, deviceGroupIds));
        
        applicableApps.forEach(app => {
            const key = app.Id || app.DisplayName;
            if (!allApps.has(key)) {
                allApps.set(key, {
                    name: app.DisplayName || 'Unknown App',
                    type: app.AppType || 'Unknown',
                    devices: new Array(devices.length).fill(null)
                });
            }
            allApps.get(key).devices[idx] = app;
        });
    });
    
    return Array.from(allApps.values()).map(entry => {
        const appliedCount = entry.devices.filter(d => d !== null).length;
        const intents = entry.devices.map(d => {
            if (!d) return '✗';
            const assignments = d.Assignments || [];
            const required = assignments.some(a => a.Intent === 'Required');
            const available = assignments.some(a => a.Intent === 'Available');
            if (required) return 'Required';
            if (available) return 'Available';
            return '✓';
        });
        
        return {
            name: entry.name,
            type: entry.type,
            cells: entry.devices.map((d, i) => ({
                applied: d !== null,
                value: intents[i]
            })),
            hasDifference: appliedCount > 0 && appliedCount < devices.length
        };
    }).sort((a, b) => {
        if (a.hasDifference !== b.hasDifference) return a.hasDifference ? -1 : 1;
        return a.name.localeCompare(b.name);
    });
}

/**
 * Compares MDM policies (from local device) across devices
 */
function compareMDMPolicies(devices) {
    const allPolicies = new Map();
    
    devices.forEach((device, idx) => {
        const devicePolicies = device.mdmData?.DevicePolicies || [];
        const userPolicies = device.mdmData?.UserPolicies || [];
        
        [...devicePolicies, ...userPolicies].forEach(policy => {
            const key = `${policy.Area || ''}|${policy.Setting || ''}|${policy.Scope || ''}`;
            if (!allPolicies.has(key)) {
                allPolicies.set(key, {
                    area: policy.Area || '',
                    setting: policy.Setting || '',
                    scope: policy.Scope || '',
                    devices: new Array(devices.length).fill(null)
                });
            }
            allPolicies.get(key).devices[idx] = policy;
        });
    });
    
    return Array.from(allPolicies.values()).map(entry => {
        const values = entry.devices.map(d => d ? formatValue(d.Value) : null);
        const nonNullValues = values.filter(v => v !== null);
        const uniqueValues = [...new Set(nonNullValues)];
        const hasDifference = nonNullValues.length !== devices.length || uniqueValues.length > 1;
        
        return {
            area: entry.area,
            setting: entry.setting,
            scope: entry.scope,
            cells: entry.devices.map(d => ({
                applied: d !== null,
                value: d ? formatValue(d.Value) : '✗'
            })),
            hasDifference
        };
    }).sort((a, b) => {
        if (a.hasDifference !== b.hasDifference) return a.hasDifference ? -1 : 1;
        return `${a.area}|${a.setting}`.localeCompare(`${b.area}|${b.setting}`);
    });
}

/**
 * Renders the Intune comparison section
 */
function renderIntuneComparisonSection(comparison, deviceNames) {
    const totalRows = comparison.profiles.length + comparison.apps.length + comparison.mdmPolicies.length;
    const diffRows = comparison.differences;
    
    return `
        <div class="section">
            <div class="section-header">
                <h2>☁️ Intune Comparison (${diffRows} differences of ${totalRows} items)</h2>
                <span class="toggle">▼</span>
            </div>
            <div class="section-body">
                ${comparison.profiles.length > 0 ? `
                    <h3 style="margin: 0 0 10px; color: var(--text-secondary);">Configuration Profiles</h3>
                    ${renderComparisonTable(
                        ['Profile Name', 'Type', ...deviceNames],
                        comparison.profiles.map(row => ({
                            cells: [row.name, row.type, ...row.cells.map(c => c.value)],
                            hasDifference: row.hasDifference,
                            cellClasses: ['', '', ...row.cells.map(c => c.applied ? 'cell-applied' : 'cell-not-applied')]
                        })),
                        'intune-profiles'
                    )}
                ` : '<p style="color: var(--text-secondary);">No Intune profiles found.</p>'}
                
                ${comparison.apps.length > 0 ? `
                    <h3 style="margin: 20px 0 10px; color: var(--text-secondary);">App Assignments</h3>
                    ${renderComparisonTable(
                        ['App Name', 'Type', ...deviceNames],
                        comparison.apps.map(row => ({
                            cells: [row.name, row.type, ...row.cells.map(c => c.value)],
                            hasDifference: row.hasDifference,
                            cellClasses: ['', '', ...row.cells.map(c => {
                                if (!c.applied) return 'cell-not-applied';
                                if (c.value === 'Required') return 'cell-required';
                                if (c.value === 'Available') return 'cell-available';
                                return 'cell-applied';
                            })]
                        })),
                        'intune-apps'
                    )}
                ` : ''}
                
                ${comparison.mdmPolicies.length > 0 ? `
                    <h3 style="margin: 20px 0 10px; color: var(--text-secondary);">MDM Policies (Local)</h3>
                    <div class="filter-bar">
                        <input type="text" id="mdm-compare-search" placeholder="Search MDM policies..." 
                               oninput="filterComparisonTable('intune-mdm-table', this.value)">
                    </div>
                    ${renderComparisonTable(
                        ['Area', 'Setting', ...deviceNames],
                        comparison.mdmPolicies.map(row => ({
                            cells: [row.area, row.setting, ...row.cells.map(c => c.value)],
                            hasDifference: row.hasDifference,
                            cellClasses: ['', '', ...row.cells.map(c => c.applied ? 'cell-applied' : 'cell-not-applied')]
                        })),
                        'intune-mdm'
                    )}
                ` : ''}
            </div>
        </div>
    `;
}

// ============================================================================
// SCCM COMPARISON
// ============================================================================

/**
 * Compares SCCM settings across devices
 */
function compareSCCMSettings(devices) {
    const result = {
        applications: compareSCCMApps(devices),
        baselines: compareSCCMBaselines(devices),
        differences: 0
    };
    
    result.differences = result.applications.filter(r => r.hasDifference).length +
                         result.baselines.filter(r => r.hasDifference).length;
    
    return result;
}

/**
 * Compares SCCM applications across devices
 */
function compareSCCMApps(devices) {
    const allApps = new Map();
    
    devices.forEach((device, idx) => {
        const apps = device.sccmData?.Applications || [];
        apps.forEach(app => {
            const key = app.Name || app.Id || 'Unknown App';
            if (!allApps.has(key)) {
                allApps.set(key, {
                    name: key,
                    publisher: app.Publisher || '',
                    devices: new Array(devices.length).fill(null)
                });
            }
            allApps.get(key).devices[idx] = app;
        });
    });
    
    return Array.from(allApps.values()).map(entry => {
        const states = entry.devices.map(d => {
            if (!d) return { applied: false, value: '✗', state: null };
            return {
                applied: true,
                value: d.InstallState || '✓',
                state: d.InstallState
            };
        });
        
        const appliedCount = states.filter(s => s.applied).length;
        const uniqueStates = [...new Set(states.filter(s => s.applied).map(s => s.state))];
        const hasDifference = appliedCount !== devices.length || uniqueStates.length > 1;
        
        return {
            name: entry.name,
            publisher: entry.publisher,
            cells: states.map(s => ({ applied: s.applied, value: s.value })),
            hasDifference
        };
    }).sort((a, b) => {
        if (a.hasDifference !== b.hasDifference) return a.hasDifference ? -1 : 1;
        return a.name.localeCompare(b.name);
    });
}

/**
 * Compares SCCM compliance baselines across devices
 */
function compareSCCMBaselines(devices) {
    const allBaselines = new Map();
    
    devices.forEach((device, idx) => {
        const baselines = device.sccmData?.Baselines || [];
        baselines.forEach(baseline => {
            const key = baseline.Name || baseline.Id || 'Unknown Baseline';
            if (!allBaselines.has(key)) {
                allBaselines.set(key, {
                    name: key,
                    devices: new Array(devices.length).fill(null)
                });
            }
            allBaselines.get(key).devices[idx] = baseline;
        });
    });
    
    return Array.from(allBaselines.values()).map(entry => {
        const states = entry.devices.map(d => {
            if (!d) return { applied: false, value: '✗', state: null };
            return {
                applied: true,
                value: d.ComplianceState || '✓',
                state: d.ComplianceState
            };
        });
        
        const appliedCount = states.filter(s => s.applied).length;
        const uniqueStates = [...new Set(states.filter(s => s.applied).map(s => s.state))];
        const hasDifference = appliedCount !== devices.length || uniqueStates.length > 1;
        
        return {
            name: entry.name,
            cells: states.map(s => ({ applied: s.applied, value: s.value })),
            hasDifference
        };
    }).sort((a, b) => {
        if (a.hasDifference !== b.hasDifference) return a.hasDifference ? -1 : 1;
        return a.name.localeCompare(b.name);
    });
}

/**
 * Renders the SCCM comparison section
 */
function renderSCCMComparisonSection(comparison, deviceNames) {
    const totalRows = comparison.applications.length + comparison.baselines.length;
    const diffRows = comparison.differences;
    
    // Check if any device has SCCM
    const hasAnySCCM = comparison.applications.length > 0 || comparison.baselines.length > 0;
    
    return `
        <div class="section">
            <div class="section-header ${hasAnySCCM ? '' : 'collapsed'}">
                <h2>🔧 SCCM Comparison (${diffRows} differences of ${totalRows} items)</h2>
                <span class="toggle">▼</span>
            </div>
            <div class="section-body ${hasAnySCCM ? '' : 'hidden'}">
                ${!hasAnySCCM ? `
                    <p style="color: var(--text-secondary);">No SCCM data found on any device.</p>
                ` : ''}
                
                ${comparison.applications.length > 0 ? `
                    <h3 style="margin: 0 0 10px; color: var(--text-secondary);">Applications</h3>
                    ${renderComparisonTable(
                        ['Application', 'Publisher', ...deviceNames],
                        comparison.applications.map(row => ({
                            cells: [row.name, row.publisher, ...row.cells.map(c => c.value)],
                            hasDifference: row.hasDifference,
                            cellClasses: ['', '', ...row.cells.map(c => {
                                if (!c.applied) return 'cell-not-applied';
                                if (c.value === 'Installed') return 'cell-installed';
                                if (c.value === 'Not Installed') return 'cell-not-installed';
                                return 'cell-applied';
                            })]
                        })),
                        'sccm-apps'
                    )}
                ` : ''}
                
                ${comparison.baselines.length > 0 ? `
                    <h3 style="margin: 20px 0 10px; color: var(--text-secondary);">Compliance Baselines</h3>
                    ${renderComparisonTable(
                        ['Baseline', ...deviceNames],
                        comparison.baselines.map(row => ({
                            cells: [row.name, ...row.cells.map(c => c.value)],
                            hasDifference: row.hasDifference,
                            cellClasses: ['', ...row.cells.map(c => {
                                if (!c.applied) return 'cell-not-applied';
                                if (c.value === 'Compliant') return 'cell-compliant';
                                if (c.value === 'Non-Compliant') return 'cell-noncompliant';
                                return 'cell-applied';
                            })]
                        })),
                        'sccm-baselines'
                    )}
                ` : ''}
            </div>
        </div>
    `;
}

// ============================================================================
// AZURE AD COMPARISON
// ============================================================================

/**
 * Compares Azure AD group memberships across devices
 */
function compareAzureADGroups(devices) {
    const allGroups = new Map();
    
    devices.forEach((device, idx) => {
        const groups = device.groupData?.Groups || [];
        groups.forEach(group => {
            const key = group.ObjectId || group.DisplayName;
            if (!allGroups.has(key)) {
                allGroups.set(key, {
                    name: group.DisplayName || 'Unknown Group',
                    type: group.GroupType || 'Assigned',
                    devices: new Array(devices.length).fill(false)
                });
            }
            allGroups.get(key).devices[idx] = true;
        });
    });
    
    const rows = Array.from(allGroups.values()).map(entry => {
        const memberCount = entry.devices.filter(d => d).length;
        return {
            name: entry.name,
            type: entry.type,
            cells: entry.devices.map(d => ({
                applied: d,
                value: d ? '✓' : '✗'
            })),
            hasDifference: memberCount > 0 && memberCount < devices.length
        };
    }).sort((a, b) => {
        if (a.hasDifference !== b.hasDifference) return a.hasDifference ? -1 : 1;
        return a.name.localeCompare(b.name);
    });
    
    return {
        groups: rows,
        differences: rows.filter(r => r.hasDifference).length
    };
}

/**
 * Renders the Azure AD comparison section
 */
function renderAzureADComparisonSection(comparison, deviceNames) {
    const totalRows = comparison.groups.length;
    const diffRows = comparison.differences;
    
    return `
        <div class="section">
            <div class="section-header ${totalRows > 0 ? '' : 'collapsed'}">
                <h2>🔐 Azure AD Group Memberships (${diffRows} differences of ${totalRows} groups)</h2>
                <span class="toggle">▼</span>
            </div>
            <div class="section-body ${totalRows > 0 ? '' : 'hidden'}">
                ${totalRows === 0 ? `
                    <p style="color: var(--text-secondary);">No Azure AD group data found.</p>
                ` : `
                    <div class="filter-bar">
                        <input type="text" id="azuread-compare-search" placeholder="Search groups..." 
                               oninput="filterComparisonTable('azuread-groups-table', this.value)">
                    </div>
                    ${renderComparisonTable(
                        ['Group Name', 'Type', ...deviceNames],
                        comparison.groups.map(row => ({
                            cells: [row.name, row.type, ...row.cells.map(c => c.value)],
                            hasDifference: row.hasDifference,
                            cellClasses: ['', row.type === 'Dynamic' ? 'cell-dynamic' : 'cell-assigned',
                                         ...row.cells.map(c => c.applied ? 'cell-member' : 'cell-not-member')]
                        })),
                        'azuread-groups'
                    )}
                `}
            </div>
        </div>
    `;
}

// ============================================================================
// TABLE RENDERING UTILITIES
// ============================================================================

/**
 * Renders a comparison table with device columns
 */
function renderComparisonTable(headers, rows, tableId) {
    if (rows.length === 0) {
        return '<p style="color: var(--text-secondary);">No items to compare.</p>';
    }
    
    return `
        <div class="table-wrapper">
            <table id="${tableId}-table" class="comparison-table">
                <thead>
                    <tr>
                        ${headers.map(h => `<th>${escapeHtml(h)}</th>`).join('')}
                    </tr>
                </thead>
                <tbody>
                    ${rows.map(row => `
                        <tr class="comparison-row ${row.hasDifference ? 'row-different' : 'row-identical'}">
                            ${row.cells.map((cell, idx) => `
                                <td class="${row.cellClasses?.[idx] || ''}">${escapeHtml(cell)}</td>
                            `).join('')}
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
}

/**
 * Filters a comparison table by search text
 */
function filterComparisonTable(tableId, searchText) {
    const table = document.getElementById(tableId);
    if (!table) return;
    
    const search = searchText.toLowerCase();
    const rows = table.querySelectorAll('tbody tr');
    
    rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        const matchesSearch = text.includes(search);
        const isIdentical = row.classList.contains('row-identical');
        const hideIdentical = document.getElementById('hide-identical-rows')?.checked;
        
        row.style.display = matchesSearch && !(isIdentical && hideIdentical) ? '' : 'none';
    });
}

// ============================================================================
// HELPER FUNCTIONS (from PolicyLensViewer.html)
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

// ============================================================================
// CSS STYLES FOR COMPARISON VIEW
// ============================================================================

/**
 * Injects comparison-specific styles into the document
 * Call this when the comparison view is loaded
 */
function injectComparisonStyles() {
    if (document.getElementById('comparison-view-styles')) return;
    
    const style = document.createElement('style');
    style.id = 'comparison-view-styles';
    style.textContent = `
        /* Comparison table row highlighting */
        .comparison-row.row-different {
            background: rgba(229, 192, 123, 0.1);
        }
        .comparison-row.row-different td:first-child {
            border-left: 3px solid var(--accent-yellow);
        }
        .comparison-row.row-identical {
            opacity: 0.8;
        }
        
        /* Cell status colors */
        .cell-applied { color: var(--accent-green); }
        .cell-not-applied { color: var(--accent-red); opacity: 0.6; }
        .cell-required { color: var(--accent-yellow); font-weight: 600; }
        .cell-available { color: var(--accent-green); }
        .cell-installed { color: var(--accent-green); }
        .cell-not-installed { color: var(--accent-red); }
        .cell-compliant { color: var(--accent-green); }
        .cell-noncompliant { color: var(--accent-red); }
        .cell-member { color: var(--accent-green); }
        .cell-not-member { color: var(--accent-red); opacity: 0.6; }
        .cell-dynamic { color: var(--accent-cyan); font-style: italic; }
        .cell-assigned { color: var(--accent-blue); }
        
        /* Comparison table styling */
        .comparison-table th {
            position: sticky;
            top: 0;
            z-index: 1;
        }
        .comparison-table td {
            max-width: 250px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .comparison-table td:hover {
            white-space: normal;
            word-break: break-word;
        }
    `;
    document.head.appendChild(style);
}

// Auto-inject styles when script loads
if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', injectComparisonStyles);
    } else {
        injectComparisonStyles();
    }
}
