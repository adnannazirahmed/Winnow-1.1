const API_BASE = '/api';

let currentData = null;
let currentVulnerability = null;
let charts = {};

const SAMPLE_PRESETS = {
    'admin-privexec': {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowPolicyManagement",
                "Effect": "Allow",
                "Action": [
                    "iam:CreatePolicyVersion",
                    "iam:SetDefaultPolicyVersion",
                    "iam:AttachUserPolicy",
                    "iam:PutUserPolicy",
                    "iam:CreateAccessKey"
                ],
                "Resource": "*"
            }
        ]
    },
    'passrole-ec2': {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowInstancePassRole",
                "Effect": "Allow",
                "Action": [
                    "iam:PassRole",
                    "ec2:RunInstances",
                    "ec2:CreateInstanceProfile",
                    "ec2:AddRoleToInstanceProfile"
                ],
                "Resource": "*"
            }
        ]
    },
    's3-wildcard': {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "OverprivilegedS3Access",
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": [
                    "arn:aws:s3:::prod-customer-data",
                    "arn:aws:s3:::prod-customer-data/*"
                ]
            }
        ]
    }
};

// localStorage throws in private mode and on opaque origins; never let a
// preference read break rendering.
const safeStorage = {
    get(key, fallback = null) {
        try { return localStorage.getItem(key) ?? fallback; } catch { return fallback; }
    },
    set(key, value) {
        try { localStorage.setItem(key, value); } catch { /* preferences are best-effort */ }
    }
};

document.addEventListener('DOMContentLoaded', () => {
    initializeTheme();
    initializeEventListeners();
    initializePresetButtons();
    updateCharCount();
    loadDummyData();
});

function initializeTheme() {
    const savedTheme = safeStorage.get('theme', 'dark') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);
    updateThemeIcon(savedTheme);
}

function updateThemeIcon(theme) {
    const icon = document.getElementById('theme-icon');
    if (!icon) return;
    if (theme === 'dark') {
        icon.innerHTML = '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>';
    } else {
        icon.innerHTML = '<circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>';
    }
}

function initializeEventListeners() {
    const themeBtn = document.getElementById('theme-toggle');
    if (themeBtn) themeBtn.addEventListener('click', toggleTheme);

    const analyzeBtn = document.getElementById('analyze-btn');
    if (analyzeBtn) analyzeBtn.addEventListener('click', analyzeConfig);

    const dummyBtn = document.getElementById('load-dummy-btn');
    if (dummyBtn) dummyBtn.addEventListener('click', loadDummyData);

    const clearBtn = document.getElementById('clear-btn');
    if (clearBtn) clearBtn.addEventListener('click', clearConfig);

    const modalClose = document.getElementById('modal-close');
    if (modalClose) modalClose.addEventListener('click', closeModal);

    const modal = document.getElementById('detail-modal');
    if (modal) {
        modal.addEventListener('click', (e) => {
            if (e.target.id === 'detail-modal') closeModal();
        });
    }

    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => switchTab(btn.dataset.tab));
    });

    const rerenderGraph = () => {
        if (currentData && currentData.visualization) renderAttackGraph(currentData.visualization.attack_graph);
    };

    const layoutSel = document.getElementById('graph-layout');
    if (layoutSel) layoutSel.addEventListener('change', rerenderGraph);

    const mitreChk = document.getElementById('show-mitre');
    if (mitreChk) mitreChk.addEventListener('change', rerenderGraph);

    const labelsChk = document.getElementById('show-attack-paths');
    if (labelsChk) labelsChk.addEventListener('change', rerenderGraph);

    const zoomIn = document.getElementById('graph-zoom-in');
    if (zoomIn) zoomIn.addEventListener('click', () => {
        if (window.__graphView) window.__graphView.svg.transition().duration(200).call(window.__graphView.zoom.scaleBy, 1.25);
    });

    const zoomOut = document.getElementById('graph-zoom-out');
    if (zoomOut) zoomOut.addEventListener('click', () => {
        if (window.__graphView) window.__graphView.svg.transition().duration(200).call(window.__graphView.zoom.scaleBy, 0.8);
    });

    const zoomReset = document.getElementById('graph-zoom-reset');
    if (zoomReset) zoomReset.addEventListener('click', () => {
        if (window.__graphView) window.__graphView.svg.transition().duration(300).call(window.__graphView.zoom.transform, d3.zoomIdentity);
    });

    const inputArea = document.getElementById('config-input');
    if (inputArea) {
        inputArea.addEventListener('input', updateCharCount);
        inputArea.addEventListener('keydown', (e) => {
            if (e.key === 'Tab') {
                e.preventDefault();
                const start = e.target.selectionStart;
                const end = e.target.selectionEnd;
                e.target.value = e.target.value.substring(0, start) + '  ' + e.target.value.substring(end);
                e.target.selectionStart = e.target.selectionEnd = start + 2;
                updateCharCount();
            }
        });
    }

    const searchInput = document.getElementById('vuln-search-input');
    if (searchInput) {
        searchInput.addEventListener('input', filterVulnerabilitiesTable);
    }
}

function initializePresetButtons() {
    document.querySelectorAll('.preset-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const key = btn.dataset.preset;
            if (SAMPLE_PRESETS[key]) {
                const inputArea = document.getElementById('config-input');
                if (inputArea) {
                    inputArea.value = JSON.stringify(SAMPLE_PRESETS[key], null, 2);
                    updateCharCount();
                    showToast(`Loaded ${btn.textContent} preset`);
                }
            }
        });
    });
}

function updateCharCount() {
    const inputArea = document.getElementById('config-input');
    const charCount = document.getElementById('char-count');
    if (inputArea && charCount) {
        const len = inputArea.value.length;
        charCount.textContent = `${len.toLocaleString()} characters`;
    }
}

function toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme');
    const newTheme = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', newTheme);
    safeStorage.set('theme', newTheme);
    updateThemeIcon(newTheme);
    destroyCharts();
    if (currentData) {
        renderCharts(currentData.visualization);
        renderAttackGraph(currentData.visualization.attack_graph);
        renderVisualizer(currentData.visualization);
    }
}

async function loadDummyData() {
    setStatus('Loading demo data...', 'loading');
    try {
        const response = await fetch(`${API_BASE}/generate-dummy`, { method: 'POST' });
        const data = await response.json();
        if (data.iam_config) {
            const inputArea = document.getElementById('config-input');
            if (inputArea) {
                inputArea.value = JSON.stringify(data.iam_config, null, 2);
                updateCharCount();
            }
            await analyzeConfig();
        }
    } catch (error) {
        console.error('Failed to load dummy data:', error);
        setStatus('Failed to load demo data', 'error');
    }
}

function clearConfig() {
    const inputArea = document.getElementById('config-input');
    if (inputArea) {
        inputArea.value = '';
        inputArea.focus();
        updateCharCount();
    }
    currentData = null;
    currentVulnerability = null;
    resetUI();
    setStatus('Ready', 'ready');
}

async function analyzeConfig() {
    const inputArea = document.getElementById('config-input');
    if (!inputArea) return;
    
    const configText = inputArea.value.trim();
    if (!configText) {
        alert('Please paste an IAM configuration first');
        return;
    }
    
    let config;
    try {
        config = JSON.parse(configText);
    } catch (e) {
        alert('Invalid JSON syntax. Please verify your policy format.');
        return;
    }
    
    setStatus('Analyzing vulnerability vectors...', 'loading');
    const analyzeBtn = document.getElementById('analyze-btn');
    if (analyzeBtn) analyzeBtn.disabled = true;
    
    try {
        const response = await fetch(`${API_BASE}/analyze`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                iam_config: config,
                config_type: detectConfigType(config)
            })
        });
        
        const data = await response.json();
        
        if (!response.ok || data.error) {
            throw new Error(data.error || `Request failed (HTTP ${response.status})`);
        }
        
        currentData = data;
        currentVulnerability = null;
        renderAll(data);
        setStatus(`Found ${data.summary.total_vulnerabilities} findings`, 'success');
    } catch (error) {
        console.error('Analysis failed:', error);
        setStatus(`Error: ${error.message}`, 'error');
        alert(`Analysis failed: ${error.message}`);
    } finally {
        if (analyzeBtn) analyzeBtn.disabled = false;
    }
}

function detectConfigType(config) {
    if (config.resources && Array.isArray(config.resources)) {
        return 'terraform';
    }
    if (config.Policy || config.policy || config.Statement || config.statement) {
        return 'json';
    }
    return 'generic';
}

function renderAll(data) {
    updateSummaryCards(data.summary);
    renderVulnerabilityTable(data.vulnerabilities);
    renderAttackGraph(data.visualization.attack_graph);
    renderVisualizer(data.visualization);
    renderCharts(data.visualization);
    switchTab(safeStorage.get('activeTab', 'attack-graph') || 'attack-graph');
}

function updateSummaryCards(summary) {
    const setVal = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.textContent = val || 0;
    };
    setVal('critical-count', summary.critical);
    setVal('high-count', summary.high);
    setVal('medium-count', summary.medium);
    setVal('low-count', summary.low);
    setVal('total-count', summary.total_vulnerabilities);
    setVal('ai-count', summary.ai_suggested);
}

function renderVulnerabilityTable(vulnerabilities) {
    const tbody = document.querySelector('#vuln-table tbody');
    if (!tbody) return;
    tbody.innerHTML = '';

    vulnerabilities.forEach((vuln, idx) => {
        const tr = document.createElement('tr');
        tr.style.cursor = 'pointer';
        tr.dataset.title = (vuln.title || '').toLowerCase();
        tr.dataset.id = (vuln.id || '').toLowerCase();
        tr.dataset.resource = (vuln.resource_name || '').toLowerCase();
        tr.dataset.mitre = (vuln.mitre_techniques || []).join(' ').toLowerCase();

        tr.addEventListener('click', () => showRemediation(vuln, idx));
        
        const attackPath = vuln.attack_path ? vuln.attack_path.slice(0, 2).join(' → ') : '-';
        const mitreTags = vuln.mitre_techniques ? vuln.mitre_techniques.map(t => 
            `<span class="mitre-tag">${escapeHtml(String(t))}</span>`).join('') : '-';
        const aiBadge = vuln.detection_source === 'ai' ? '<span class="ai-badge">AI Suggested</span>' : '';
        const sev = escapeHtml(String(vuln.severity || 'MEDIUM'));
        const sevClass = safeToken(vuln.severity, 'medium');
        
        tr.innerHTML = `
            <td><code>${escapeHtml(String(vuln.id || ''))}</code></td>
            <td><strong>${escapeHtml(vuln.title)}</strong>${aiBadge}</td>
            <td><span class="severity-badge ${sevClass}"><span class="dot"></span>${sev}</span></td>
            <td><code>${escapeHtml(vuln.resource_name)}</code> <span style="color:var(--fg-muted);font-size:0.72rem;">(${escapeHtml(String(vuln.resource_type || ''))})</span></td>
            <td>${escapeHtml(attackPath)}${vuln.attack_path && vuln.attack_path.length > 2 ? '...' : ''}</td>
            <td><div class="mitre-tags">${mitreTags}</div></td>
            <td><button class="action-btn" type="button">Remediate</button></td>
        `;
        // Bound listener instead of an inline onclick referencing a global.
        const btn = tr.querySelector('.action-btn');
        if (btn) {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                showRemediation(vuln, idx);
            });
        }
        tbody.appendChild(tr);
    });

    updateVulnTableCount();
}

function filterVulnerabilitiesTable() {
    const searchInput = document.getElementById('vuln-search-input');
    if (!searchInput) return;
    const q = searchInput.value.toLowerCase().trim();
    const rows = document.querySelectorAll('#vuln-table tbody tr');

    let visibleCount = 0;
    rows.forEach(tr => {
        const matches = !q || 
            tr.dataset.title.includes(q) || 
            tr.dataset.id.includes(q) || 
            tr.dataset.resource.includes(q) || 
            tr.dataset.mitre.includes(q);
        
        tr.style.display = matches ? '' : 'none';
        if (matches) visibleCount++;
    });

    const pill = document.getElementById('vuln-count-pill');
    if (pill) pill.textContent = `Showing ${visibleCount} of ${rows.length} findings`;
}

function updateVulnTableCount() {
    const rows = document.querySelectorAll('#vuln-table tbody tr');
    const pill = document.getElementById('vuln-count-pill');
    if (pill) pill.textContent = `Showing ${rows.length} findings`;
}

function showRemediation(vuln, idx) {
    currentVulnerability = vuln;
    const remediation = currentData?.remediations?.[idx]?.remediation;
    const container = document.getElementById('remediation-content');
    if (!container) return;

    if (!remediation) {
        container.innerHTML = '<div class="empty-state-container"><p class="empty-state">No remediation data available for this finding.</p></div>';
        return;
    }

    const actionsHtml = (remediation.actions || []).map((action, aIdx) => {
        const priority = escapeHtml(String(action.priority || 'MEDIUM'));
        const priorityClass = safeToken(action.priority, 'medium');
        return `
        <div class="action-item priority-${priorityClass}">
            <div class="action-header">
                <span class="action-name">${escapeHtml(action.action)}</span>
                <span class="action-priority ${priorityClass}">${priority}</span>
            </div>
            <div class="action-description">${escapeHtml(action.description)}</div>
            <div class="action-code">
                <button class="btn btn-ghost copy-btn" type="button" data-copy-target="code-action-${aIdx}" style="position:absolute;top:8px;right:8px;padding:4px 8px;font-size:0.7rem;">Copy</button>
                <pre id="code-action-${aIdx}">${escapeHtml(action.code_example)}</pre>
            </div>
            <div class="action-explanation">${escapeHtml(action.explanation)}</div>
        </div>
    `;
    }).join('');

    const hardenedPolicy = remediation.hardened_policy ? `
        <div class="hardened-policy">
            <h4>Hardened IAM Policy Recommendation</h4>
            <div class="action-code">
                <button class="btn btn-ghost copy-btn" type="button" data-copy-target="code-hardened" style="position:absolute;top:8px;right:8px;padding:4px 8px;font-size:0.7rem;">Copy Policy</button>
                <pre id="code-hardened">${escapeHtml(JSON.stringify(remediation.hardened_policy, null, 2))}</pre>
            </div>
        </div>
    ` : '';

    const complianceNotes = remediation.compliance_notes && remediation.compliance_notes.length > 0 ? `
        <div class="compliance-notes">
            <h4>Compliance Framework References</h4>
            <ul>
                ${remediation.compliance_notes.map(note => `<li>${escapeHtml(note)}</li>`).join('')}
            </ul>
        </div>
    ` : '';

    const aiTag = vuln.detection_source === 'ai' ? '<span class="ai-badge">AI Suggested</span>' : '';
    const vSev = escapeHtml(String(vuln.severity || 'MEDIUM'));
    const vSevClass = safeToken(vuln.severity, 'medium');
    const riskScore = Number(remediation.risk_score) || 0;

    container.innerHTML = `
        <div class="remediation-card">
            <div class="remediation-header">
                <div>
                    <div class="remediation-title">${escapeHtml(vuln.title)}${aiTag}</div>
                    <div class="remediation-meta">
                        <span><strong>ID:</strong> <code>${escapeHtml(String(vuln.id || ''))}</code></span>
                        <span><strong>Resource:</strong> <code>${escapeHtml(vuln.resource_name)}</code> (${escapeHtml(String(vuln.resource_type || ''))})</span>
                        <span><strong>Severity:</strong> <span class="severity-badge ${vSevClass}">${vSev}</span></span>
                        <span><strong>Risk Score:</strong> <span style="color:var(--accent-secondary);font-weight:700;">${riskScore}/100</span></span>
                    </div>
                </div>
            </div>
            <div class="remediation-summary">${escapeHtml(remediation.summary)}</div>
            <div class="remediation-actions">${actionsHtml}</div>
            ${hardenedPolicy}
            ${complianceNotes}
        </div>
    `;

    container.querySelectorAll('[data-copy-target]').forEach(btn => {
        btn.addEventListener('click', () => copyCodeBlock(btn.dataset.copyTarget));
    });

    switchTab('remediation');
}

function copyCodeBlock(elementId) {
    const codeEl = document.getElementById(elementId);
    if (!codeEl) return;
    const text = codeEl.textContent;
    navigator.clipboard.writeText(text).then(() => {
        showToast('Code snippet copied!');
    }).catch(() => {
        showToast('Failed to copy code');
    });
}

function showToast(msg) {
    const toast = document.getElementById('toast-notification');
    if (!toast) return;
    toast.textContent = msg;
    toast.classList.add('show');
    setTimeout(() => {
        toast.classList.remove('show');
    }, 2500);
}

const GRAPH_SEV_COLORS = { CRITICAL: '#f43f5e', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#10b981' };
const GRAPH_SEV_RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

function truncLabel(s, n) {
    s = String(s || '');
    return s.length > n ? s.slice(0, n - 1) + '…' : s;
}

function findVulnIndexById(vulnId) {
    if (!currentData || !currentData.vulnerabilities) return -1;
    return currentData.vulnerabilities.findIndex(v => v.id === vulnId);
}

function renderAttackGraph(graphData) {
    const svgEl = document.getElementById('attack-graph-svg');
    if (!svgEl) return;

    const svg = d3.select(svgEl);
    svg.selectAll('*').remove();

    const tooltip = document.getElementById('graph-tooltip');
    const legendEl = document.getElementById('graph-legend');
    const countEl = document.getElementById('graph-count');
    if (tooltip) tooltip.style.opacity = '0';

    const isLight = document.documentElement.getAttribute('data-theme') === 'light';
    const textColor = isLight ? '#0f172a' : '#f1f5f9';
    const haloColor = isLight ? 'rgba(255,255,255,0.95)' : 'rgba(6,9,19,0.9)';
    const subColor = isLight ? '#475569' : '#94a3b8';

    const showMitreEl = document.getElementById('show-mitre');
    const showLabelsEl = document.getElementById('show-attack-paths');
    const layoutEl = document.getElementById('graph-layout');

    const showMitre = showMitreEl ? showMitreEl.checked : true;
    const showLabels = showLabelsEl ? showLabelsEl.checked : true;
    const layout = layoutEl ? layoutEl.value : 'grouped';

    const identities = (graphData.nodes || []).filter(n => n.type === 'identity');
    const vulns = ((graphData.nodes || []).filter(n => n.type === 'vulnerability'))
        .sort((a, b) => (GRAPH_SEV_RANK[a.severity] ?? 2) - (GRAPH_SEV_RANK[b.severity] ?? 2));

    if (!vulns.length) {
        if (countEl) countEl.textContent = 'No findings to display';
        if (legendEl) legendEl.innerHTML = '';
        const w = svgEl.clientWidth || 1000;
        svg.attr('viewBox', `0 0 ${w} 300`);
        svg.append('text')
            .attr('x', w / 2).attr('y', 150)
            .attr('text-anchor', 'middle')
            .attr('fill', subColor)
            .attr('font-size', '14px')
            .text('No vulnerabilities found — load demo data or run an analysis.');
        window.__graphView = null;
        return;
    }

    const mitreMap = new Map();
    vulns.forEach(v => (v.mitre || []).forEach(t => {
        if (!mitreMap.has(t)) mitreMap.set(t, { id: `mitre:${t}`, label: t, type: 'mitre', vulns: [] });
        mitreMap.get(t).vulns.push(v.id);
    }));
    const mitres = showMitre ? [...mitreMap.values()].sort((a, b) => b.vulns.length - a.vulns.length).slice(0, 12) : [];

    const groups = new Map();
    identities.forEach(i => groups.set(i.id, { ident: i, vulns: [] }));
    vulns.forEach(v => {
        const key = 'identity:' + (v.resource || 'unknown');
        if (!groups.has(key)) groups.set(key, { ident: { id: key, label: v.resource || 'unknown', vulnerability_count: 0 }, vulns: [] });
        groups.get(key).vulns.push(v);
    });
    const groupList = [...groups.values()].filter(g => g.vulns.length);
    groupList.sort((a, b) => b.vulns.length - a.vulns.length);

    const width = svgEl.clientWidth || 1000;
    const rowH = 36;
    const height = Math.min(1100, Math.max(480, vulns.length * rowH + 130));
    const top = 70, bottom = height - 40;
    svg.attr('height', height).attr('viewBox', `0 0 ${width} ${height}`);
    svg.style('touch-action', 'none');

    const pos = new Map();
    const ordered = [];
    groupList.forEach(g => g.vulns.forEach(v => ordered.push(v)));
    const span = Math.max(1, ordered.length - 1);
    ordered.forEach((v, i) => {
        const y = ordered.length === 1 ? (top + bottom) / 2 : top + (bottom - top) * (i / span);
        pos.set(v.id, { x: 0, y });
    });
    const meanY = ids => {
        const ys = ids.map(id => pos.get(id)).filter(Boolean).map(p => p.y);
        return ys.length ? ys.reduce((a, b) => a + b, 0) / ys.length : (top + bottom) / 2;
    };
    const spread = (items, gap) => {
        items.sort((a, b) => a.y - b.y);
        for (let i = 1; i < items.length; i++) {
            if (items[i].y - items[i - 1].y < gap) items[i].y = items[i - 1].y + gap;
        }
        const over = items.length ? items[items.length - 1].y - bottom : 0;
        if (over > 0) items.forEach(it => { it.y -= over; });
    };

    let identPos = groupList.map(g => ({ id: g.ident.id, y: meanY(g.vulns.map(v => v.id)) }));
    spread(identPos, 64);
    identPos.forEach(p => pos.set(p.id, { x: 0, y: p.y }));

    let mitrePos = mitres.map(m => ({ id: m.id, y: meanY(m.vulns) }));
    spread(mitrePos, 44);
    mitrePos.forEach(p => pos.set(p.id, { x: 0, y: p.y }));

    const hasMitre = mitres.length > 0;
    const colX = hasMitre
        ? { ident: width * 0.16, vuln: width * 0.52, mitre: width * 0.86 }
        : { ident: width * 0.22, vuln: width * 0.68 };
    pos.forEach(p => { p.x = colX.vuln; });
    identPos.forEach(p => { pos.get(p.id).x = colX.ident; });
    mitrePos.forEach(p => { pos.get(p.id).x = colX.mitre; });

    const radial = layout === 'radial';
    if (radial) {
        const cx = width / 2, cy = height / 2;
        const r1 = Math.min(width, height) * 0.18, r2 = Math.min(width, height) * 0.38;
        groupList.forEach((g, i) => {
            const a = (i / Math.max(1, groupList.length)) * Math.PI * 2 - Math.PI / 2;
            pos.get(g.ident.id).x = cx + Math.cos(a) * r1;
            pos.get(g.ident.id).y = cy + Math.sin(a) * r1;
            g.vulns.forEach((v, j) => {
                const spreadA = 0.5;
                const va = a + (g.vulns.length === 1 ? 0 : (j / (g.vulns.length - 1) - 0.5) * spreadA);
                pos.get(v.id).x = cx + Math.cos(va) * r2;
                pos.get(v.id).y = cy + Math.sin(va) * r2;
            });
        });
        mitres.forEach((m, i) => {
            const a = (i / Math.max(1, mitres.length)) * Math.PI * 2;
            const p = pos.get(m.id);
            p.x = cx + Math.cos(a) * (r2 + 90);
            p.y = cy + Math.sin(a) * (r2 + 90);
        });
    }

    const defs = svg.append('defs');
    const arrow = defs.append('marker')
        .attr('id', 'graph-arrow')
        .attr('viewBox', '0 -5 10 10')
        .attr('refX', 9).attr('refY', 0)
        .attr('markerWidth', 7).attr('markerHeight', 7)
        .attr('orient', 'auto');
    arrow.append('path').attr('d', 'M0,-5L10,0L0,5').attr('fill', isLight ? '#94a3b8' : '#64748b');

    const g = svg.append('g');

    const edgePath = (a, b) => {
        if (radial) return `M${a.x},${a.y} L${b.x},${b.y}`;
        const mx = (a.x + b.x) / 2;
        return `M${a.x},${a.y} C${mx},${a.y} ${mx},${b.y} ${b.x},${b.y}`;
    };

    const edgeData = [];
    groupList.forEach(gr => gr.vulns.forEach(v => {
        edgeData.push({ s: pos.get(gr.ident.id), t: pos.get(v.id), sev: v.severity, kind: 'vuln' });
    }));
    mitres.forEach(m => m.vulns.forEach(vid => {
        if (pos.has(vid)) edgeData.push({ s: pos.get(vid), t: pos.get(m.id), sev: null, kind: 'mitre' });
    }));

    g.append('g').selectAll('path').data(edgeData).join('path')
        .attr('d', d => edgePath(d.s, d.t))
        .attr('fill', 'none')
        .attr('stroke', d => d.kind === 'mitre' ? (isLight ? '#cbd5e1' : '#334155') : (GRAPH_SEV_COLORS[d.sev] || '#64748b'))
        .attr('stroke-opacity', d => d.kind === 'mitre' ? 0.6 : 0.65)
        .attr('stroke-width', 1.8)
        .attr('stroke-dasharray', d => d.kind === 'mitre' ? '5,4' : 'none')
        .attr('marker-end', 'url(#graph-arrow)');

    const showTip = (html, evt) => {
        if (!tooltip) return;
        const wrap = svgEl.parentElement.getBoundingClientRect();
        tooltip.innerHTML = html;
        tooltip.style.opacity = '1';
        tooltip.style.left = Math.min(wrap.width - 270, Math.max(8, evt.clientX - wrap.left + 14)) + 'px';
        tooltip.style.top = Math.max(8, evt.clientY - wrap.top - 10) + 'px';
    };
    const hideTip = () => { if (tooltip) tooltip.style.opacity = '0'; };

    const identG = g.append('g').selectAll('g').data(groupList).join('g')
        .attr('class', 'gnode')
        .attr('transform', d => `translate(${pos.get(d.ident.id).x},${pos.get(d.ident.id).y})`)
        .style('cursor', 'default');
    identG.append('rect')
        .attr('x', -54).attr('y', -22).attr('width', 108).attr('height', 44).attr('rx', 12)
        .attr('fill', isLight ? '#eef2ff' : '#141d33')
        .attr('stroke', '#6366f1').attr('stroke-width', 1.5);
    identG.append('text')
        .attr('y', 1).attr('text-anchor', 'middle')
        .attr('font-size', '11px').attr('font-weight', '700').attr('font-family', 'Plus Jakarta Sans, sans-serif')
        .attr('fill', textColor)
        .text(d => truncLabel(d.ident.label, 15));
    identG.append('text')
        .attr('y', 14).attr('text-anchor', 'middle')
        .attr('font-size', '9px').attr('font-family', 'Inter, sans-serif')
        .attr('fill', subColor)
        .text(d => `${d.vulns.length} finding${d.vulns.length === 1 ? '' : 's'}`);
    identG.on('mousemove', (evt, d) => showTip(
        `<div class="gt-title">${escapeHtml(d.ident.label)}</div>` +
        `<div class="gt-row">${d.vulns.length} finding${d.vulns.length === 1 ? '' : 's'}</div>`, evt))
        .on('mouseleave', hideTip);

    const vulnR = sev => sev === 'CRITICAL' ? 12 : sev === 'HIGH' ? 10 : sev === 'MEDIUM' ? 9 : 8;
    const vulnG = g.append('g').selectAll('g').data(vulns).join('g')
        .attr('class', 'gnode vuln')
        .attr('transform', d => `translate(${pos.get(d.id).x},${pos.get(d.id).y})`)
        .style('cursor', 'pointer');
    vulnG.append('circle')
        .attr('r', d => vulnR(d.severity))
        .attr('fill', d => GRAPH_SEV_COLORS[d.severity] || '#64748b')
        .attr('fill-opacity', 0.95)
        .attr('stroke', isLight ? '#ffffff' : 'rgba(255,255,255,0.9)')
        .attr('stroke-width', 1.5);
    vulnG.append('circle')
        .attr('r', d => vulnR(d.severity) + 5)
        .attr('fill', 'none')
        .attr('stroke', d => d.detection_source === 'ai' ? '#a855f7' : (GRAPH_SEV_COLORS[d.severity] || '#64748b'))
        .attr('stroke-opacity', d => d.detection_source === 'ai' ? 0.85 : 0.3)
        .attr('stroke-width', d => d.detection_source === 'ai' ? 2 : 2)
        .attr('stroke-dasharray', d => d.detection_source === 'ai' ? '4,3' : 'none');
    vulnG.filter(d => d.detection_source === 'ai').append('text')
        .attr('y', d => -vulnR(d.severity) - 12)
        .attr('text-anchor', 'middle')
        .attr('font-size', '9px').attr('font-weight', '800').attr('font-family', 'Plus Jakarta Sans, sans-serif')
        .attr('letter-spacing', '1px')
        .attr('fill', '#a855f7')
        .attr('stroke', haloColor).attr('stroke-width', 3).attr('paint-order', 'stroke')
        .text('AI');
    if (showLabels) {
        vulnG.append('text')
            .attr('x', 18).attr('y', 4)
            .attr('font-size', '11px').attr('font-weight', '600').attr('font-family', 'Plus Jakarta Sans, sans-serif')
            .attr('fill', textColor)
            .attr('stroke', haloColor).attr('stroke-width', 3).attr('paint-order', 'stroke')
            .text(d => truncLabel(d.full_title || d.label, 32));
    }
    vulnG
        .on('mousemove', (evt, d) => showTip(
            `<div class="gt-title">${escapeHtml(d.full_title || d.label)}${d.detection_source === 'ai' ? ' <span class="ai-badge">AI</span>' : ''}</div>` +
            `<div class="gt-row"><span class="severity-badge ${safeToken(d.severity, 'medium')}">${escapeHtml(String(d.severity || ''))}</span>` +
            `<span class="gt-mut">${escapeHtml(d.resource || '')}</span></div>` +
            (d.details ? `<div class="gt-desc">${escapeHtml(String(d.details).slice(0, 160))}${String(d.details).length > 160 ? '…' : ''}</div>` : '') +
            `<div class="gt-hint">Click to view remediation →</div>`, evt))
        .on('mouseleave', hideTip)
        .on('click', (evt, d) => {
            evt.stopPropagation();
            const vid = String(d.id).replace(/^vuln:/, '');
            const idx = findVulnIndexById(vid);
            if (idx >= 0 && currentData.vulnerabilities[idx]) showRemediation(currentData.vulnerabilities[idx], idx);
        });

    if (hasMitre) {
        const mitreG = g.append('g').selectAll('g').data(mitres).join('g')
            .attr('class', 'gnode')
            .attr('transform', d => `translate(${pos.get(d.id).x},${pos.get(d.id).y})`)
            .style('cursor', 'default');
        mitreG.append('rect')
            .attr('x', -9).attr('y', -9).attr('width', 18).attr('height', 18).attr('rx', 4)
            .attr('transform', 'rotate(45)')
            .attr('fill', isLight ? '#e0f2fe' : '#0c2a3f')
            .attr('stroke', '#06b6d4').attr('stroke-width', 1.5);
        if (showLabels) {
            mitreG.append('text')
                .attr('x', 18).attr('y', 4)
                .attr('font-size', '10px').attr('font-family', '"JetBrains Mono", monospace')
                .attr('fill', textColor)
                .attr('stroke', haloColor).attr('stroke-width', 3).attr('paint-order', 'stroke')
                .text(d => d.label);
        }
        mitreG
            .on('mousemove', (evt, d) => showTip(
                `<div class="gt-title" style="font-family:monospace">${escapeHtml(d.label)}</div>` +
                `<div class="gt-row">${d.vulns.length} linked finding${d.vulns.length === 1 ? '' : 's'}</div>`, evt))
            .on('mouseleave', hideTip);
    }

    const headers = hasMitre
        ? [{ x: colX.ident, t: 'Identities' }, { x: colX.vuln, t: 'Findings' }, { x: colX.mitre, t: 'MITRE ATT&CK' }]
        : [{ x: colX.ident, t: 'Identities' }, { x: colX.vuln, t: 'Findings' }];
    if (!radial) {
        g.append('g').selectAll('text').data(headers).join('text')
            .attr('x', d => d.x).attr('y', 26)
            .attr('text-anchor', 'middle')
            .attr('font-size', '10px').attr('font-weight', '800').attr('font-family', 'Plus Jakarta Sans, sans-serif')
            .attr('letter-spacing', '1.5px')
            .attr('fill', subColor)
            .text(d => d.t.toUpperCase());
    }

    if (legendEl) {
        const aiCount = vulns.filter(v => v.detection_source === 'ai').length;
        legendEl.innerHTML =
            `<span class="lg-item"><span class="lg-swatch lg-ident"></span>Identity</span>` +
            Object.keys(GRAPH_SEV_COLORS).map(s =>
                `<span class="lg-item"><span class="lg-dot" style="background:${GRAPH_SEV_COLORS[s]}"></span>${s.charAt(0) + s.slice(1).toLowerCase()}</span>`
            ).join('') +
            (hasMitre ? `<span class="lg-item"><span class="lg-diamond"></span>MITRE technique</span>` : '') +
            (aiCount > 0 ? `<span class="lg-item"><span class="lg-dot lg-ai"></span>AI suggested</span>` : '') +
            `<span class="lg-hint">Scroll to zoom · drag canvas to pan · click finding for remediation</span>`;
    }
    const aiTotal = vulns.filter(v => v.detection_source === 'ai').length;
    if (countEl) countEl.textContent = `${groupList.length} identities · ${vulns.length} findings${aiTotal ? ` · ${aiTotal} AI` : ''}${hasMitre ? ` · ${mitres.length} techniques` : ''}`;

    const zoom = d3.zoom().scaleExtent([0.4, 2.5]).on('zoom', e => g.attr('transform', e.transform));
    svg.call(zoom);
    window.__graphView = { zoom, svg };
}

function renderVisualizer(vizData) {
    renderEscalationChains(vizData.privilege_escalation_chains);
    renderMitreHeatmap(vizData.mitre_heatmap);
    renderResourceRiskMap(vizData.resource_risk_map);
    renderRemediationTimeline(vizData.remediation_timeline);
}

function renderEscalationChains(chains) {
    const container = document.getElementById('escalation-chains');
    if (!container) return;

    if (!chains || chains.length === 0) {
        container.innerHTML = '<p class="empty-state">No escalation chains detected</p>';
        return;
    }
    
    container.innerHTML = chains.map(chain => `
        <div class="chain-item">
            <div class="chain-header">
                <span class="chain-identity">${escapeHtml(chain.identity)}</span>
                <span class="chain-length">${Number(chain.length) || 0} vulns</span>
            </div>
            <div class="chain-steps">
                ${chain.steps.map(step => `
                    <div class="chain-step">
                        <div class="chain-step-severity" style="background: ${getSeverityColor(step.severity)}"></div>
                        <span class="chain-step-action">${escapeHtml(step.action)}</span>
                        <span class="chain-step-mitre">${escapeHtml((step.mitre || []).join(', '))}</span>
                    </div>
                `).join('')}
            </div>
        </div>
    `).join('');
}

function renderMitreHeatmap(heatmapData) {
    const container = document.getElementById('mitre-heatmap');
    if (!container) return;

    const techniques = heatmapData?.techniques || [];
    if (techniques.length === 0) {
        container.innerHTML = '<p class="empty-state">No MITRE techniques detected</p>';
        return;
    }

    const maxCount = Math.max(...techniques.map(t => Number(t.count) || 0), 1);

    const severityClass = (sev) => {
        if (sev === 'HIGH') return 'hm-high';
        if (sev === 'MEDIUM') return 'hm-medium';
        return 'hm-low';
    };

    container.innerHTML = techniques.map(tech => {
        const pct = Math.max(0, Math.min(100, Math.round(((Number(tech.count) || 0) / maxCount) * 100)));
        return `
            <div class="hm-row">
                <div class="hm-top">
                    <span class="hm-id">${escapeHtml(tech.id)}</span>
                    <span class="hm-count">${Number(tech.count) || 0}</span>
                </div>
                <div class="hm-bar-track">
                    <div class="hm-bar ${severityClass(tech.severity)}" style="width: ${pct}%"></div>
                </div>
                <div class="hm-bottom">
                    <span class="hm-name">${escapeHtml(tech.name)}</span>
                    <span class="hm-tactic">${escapeHtml(tech.tactic)}</span>
                </div>
            </div>
        `;
    }).join('');
}

function renderResourceRiskMap(riskData) {
    const container = document.getElementById('resource-risk-map');
    if (!container) return;

    const resources = riskData?.resources || [];
    if (resources.length === 0) {
        container.innerHTML = '<p class="empty-state">No resource risk data</p>';
        return;
    }
    
    const pctWidth = (part, total) => {
        const value = (Number(part) / Number(total)) * 100;
        return Number.isFinite(value) ? Math.max(0, Math.min(100, value)) : 0;
    };

    container.innerHTML = resources.map(r => `
        <div class="risk-bar">
            <span class="risk-bar-name" title="${escapeHtml(r.name)}">${escapeHtml(r.name)}</span>
            <div class="risk-bar-track">
                <div class="risk-bar-fill critical" style="width: ${pctWidth(r.critical, r.total)}%"></div>
                <div class="risk-bar-fill high" style="width: ${pctWidth(r.high, r.total)}%"></div>
                <div class="risk-bar-fill medium" style="width: ${pctWidth(r.medium, r.total)}%"></div>
                <div class="risk-bar-fill low" style="width: ${pctWidth(r.low, r.total)}%"></div>
            </div>
            <span class="risk-bar-score">${Number(r.risk_score) || 0}/100</span>
        </div>
    `).join('');
}

function renderRemediationTimeline(timelineData) {
    const container = document.getElementById('remediation-timeline');
    if (!container) return;

    const items = timelineData?.items || [];
    if (items.length === 0) {
        container.innerHTML = '<p class="empty-state">No remediation actions</p>';
        return;
    }
    
    container.innerHTML = items.map(item => `
        <div class="timeline-item">
            <div class="timeline-priority ${safeToken(item.priority, 'medium')}"></div>
            <span class="timeline-action">${escapeHtml(item.action)}</span>
            <span class="timeline-hours">${Number(item.estimated_hours) || 0}h</span>
        </div>
    `).join('');
}

function renderCharts(vizData) {
    if (!vizData) return;
    if (vizData.severity_distribution) renderSeverityChart(vizData.severity_distribution);
    if (vizData.resource_risk_map) renderRadarChart(vizData.resource_risk_map);
    renderPriorityChart(vizData.remediation_timeline);
}

function renderSeverityChart(dist) {
    const canvas = document.getElementById('severity-chart');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    destroyChart('severity');
    
    charts.severity = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: dist.labels,
            datasets: [{
                data: dist.data,
                backgroundColor: dist.colors,
                borderWidth: 0,
                cutout: '68%'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: getComputedStyle(document.documentElement).getPropertyValue('--fg-secondary').trim(), padding: 16, font: { size: 12, family: 'Plus Jakarta Sans' } }
                }
            }
        }
    });
}

function renderRadarChart(riskData) {
    const canvas = document.getElementById('radar-chart');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    destroyChart('radar');
    
    const resources = (riskData.resources || []).slice(0, 8);
    const data = {
        labels: resources.map(r => r.name.length > 15 ? r.name.slice(0,15)+'…' : r.name),
        datasets: [{
            label: 'Risk Score',
            data: resources.map(r => r.risk_score),
            backgroundColor: 'rgba(99, 102, 241, 0.25)',
            borderColor: '#6366f1',
            pointBackgroundColor: '#06b6d4',
            borderWidth: 2
        }]
    };
    
    charts.radar = new Chart(ctx, {
        type: 'radar',
        data: data,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                r: {
                    beginAtZero: true,
                    max: 100,
                    grid: { color: 'rgba(255,255,255,0.08)' },
                    angleLines: { color: 'rgba(255,255,255,0.08)' },
                    pointLabels: { color: '#94a3b8', font: { size: 10, family: 'JetBrains Mono' } },
                    ticks: { display: false }
                }
            },
            plugins: { legend: { display: false } }
        }
    });
}

function renderPriorityChart(timelineData) {
    const canvas = document.getElementById('progress-chart');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    destroyChart('progress');

    // Real data: remediation actions grouped by priority.
    const byPriority = timelineData?.by_priority || {};
    const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    const labels = order.filter(p => byPriority[p]);
    const data = labels.map(p => byPriority[p]);
    const colorMap = { CRITICAL: '#f43f5e', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#10b981' };

    if (!labels.length) return;

    charts.progress = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels.map(p => p.charAt(0) + p.slice(1).toLowerCase()),
            datasets: [{
                data: data,
                backgroundColor: labels.map(p => colorMap[p]),
                borderWidth: 0,
                cutout: '70%'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'bottom', labels: { color: '#94a3b8', padding: 16, font: { size: 12, family: 'Plus Jakarta Sans' } } }
            }
        }
    });
}

function destroyChart(name) {
    if (charts[name]) {
        charts[name].destroy();
        charts[name] = null;
    }
}

function destroyCharts() {
    Object.keys(charts).forEach(destroyChart);
}

function switchTab(tabName) {
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === tabName);
    });
    document.querySelectorAll('.tab-panel').forEach(panel => {
        panel.classList.toggle('active', panel.id === tabName);
    });

    safeStorage.set('activeTab', tabName);

    if (tabName === 'visualizer' && currentData?.visualization) {
        requestAnimationFrame(() => {
            renderMitreHeatmap(currentData.visualization.mitre_heatmap);
        });
    }
}

function setStatus(message, type) {
    const indicator = document.getElementById('status-indicator');
    if (!indicator) return;
    const dot = indicator.querySelector('.dot');
    const text = indicator.querySelector('span:last-child');
    
    if (text) text.textContent = message;
    
    if (dot) {
        dot.className = 'dot';
        if (type === 'loading') {
            dot.style.background = '#06b6d4';
            dot.style.animation = 'pulseGlow 1s infinite';
        } else if (type === 'success') {
            dot.style.background = '#10b981';
            dot.style.animation = 'pulseGlow 2s infinite';
        } else if (type === 'error') {
            dot.style.background = '#f43f5e';
            dot.style.animation = 'none';
        } else {
            dot.style.background = '#10b981';
            dot.style.animation = 'pulseGlow 2s infinite';
        }
    }
}

function closeModal() {
    const modal = document.getElementById('detail-modal');
    if (modal) modal.classList.remove('active');
}

function resetUI() {
    updateSummaryCards({ critical: 0, high: 0, medium: 0, low: 0, total_vulnerabilities: 0, ai_suggested: 0 });
    const tbody = document.querySelector('#vuln-table tbody');
    if (tbody) tbody.innerHTML = '';
    d3.select('#attack-graph-svg').selectAll('*').remove();
    
    const setEmpty = (id, html) => {
        const el = document.getElementById(id);
        if (el) el.innerHTML = html;
    };

    setEmpty('escalation-chains', '<p class="empty-state">No data</p>');
    setEmpty('resource-risk-map', '<p class="empty-state">No data</p>');
    setEmpty('remediation-timeline', '<p class="empty-state">No data</p>');
    setEmpty('remediation-content', '<div class="empty-state-container"><p class="empty-state">Select a finding to see remediation details.</p></div>');
    
    destroyCharts();
}

// Escapes for both text and attribute contexts. The previous textContent-based
// implementation did not escape quotes, so values interpolated into attributes
// (class="...", title="...", style="...") could break out and inject handlers.
function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    return String(text)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// For values used inside class names / CSS: allow only safe characters.
function safeToken(value, fallback = '') {
    const token = String(value ?? '').toLowerCase();
    return /^[a-z0-9_-]+$/.test(token) ? token : fallback;
}

function getSeverityColor(severity) {
    const colors = {
        'CRITICAL': '#f43f5e',
        'HIGH': '#f97316',
        'MEDIUM': '#eab308',
        'LOW': '#10b981'
    };
    return colors[severity] || '#64748b';
}

window.showRemediation = showRemediation;