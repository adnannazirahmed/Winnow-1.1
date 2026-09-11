/* Winnow — front-end controller.
   Vanilla ES5-compatible, no build step. Loaded after scenes.js.

   Data flow: on load we POST the demo IAM config to the Flask API and normalise
   the response into the shape the views expect. If the API is not reachable
   (static preview) we fall back to DEMO_RESULT so the UI is never empty.

   The mapping below is written against the REAL /api/analyze contract in
   backend/app.py, verified against a live response:

     { vulnerabilities: [ { id, pattern_id, title, description, severity,
                            resource_type, resource_name, policy_document,
                            attack_path: [str], mitre_techniques: [str],
                            remediation_hint, detection_source } ],
       remediations:    [ { vulnerability, remediation: { vulnerability_id,
                            original_severity, risk_score, summary, actions:
                            [{action, description, priority, code_example,
                              explanation}], hardened_policy, compliance_notes,
                            source } } ],
       visualization:   { attack_graph, severity_distribution, resource_risk_map,
                          remediation_timeline, mitre_heatmap,
                          privilege_escalation_chains, summary_stats },
       summary:         { total_vulnerabilities, critical, high, medium, low,
                          ai_suggested } }

   Note attack_path is an ARRAY of steps, not a string, and the backend already
   computes the technique names/tactics, per-resource risk scores and the
   remediation queue — so we consume those rather than re-deriving them.
*/
(function () {
  'use strict';

  var API = '/api/analyze';

  var SEV_VAR = { CRITICAL: 'var(--n-crit)', HIGH: 'var(--n-high)', MEDIUM: 'var(--n-med)', LOW: 'var(--n-low)' };
  var SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

  /* ---------------- fallback dataset (offline preview only) ----------------
     The live demo config comes from GET-less POST /api/generate-dummy; this
     bundled result only renders when the backend is unreachable. */

  function F(id, title, severity, resource, resourceType, mitre, path, description) {
    return { id: id, title: title, severity: severity, resource: resource, resource_type: resourceType, mitre: mitre, attack_path: path, description: description, detection_source: 'rule' };
  }
  var AP = 'VulnerableAdminPolicy', CU = 'CompromisedUser', LP = 'LambdaEscalationPolicy';

  var DEMO_RESULT = {
    findings: [
      F('VULN-0001', 'User Can Attach Admin Policy', 'CRITICAL', AP, 'aws_iam_policy', ['T1098.001'], 'Identity: VulnerableAdminPolicy → Action: iam:AttachUserPolicy → Target Resources: *', 'Allows attaching any managed policy including AdministratorAccess (Action: iam:AttachUserPolicy)'),
      F('VULN-0002', 'User Can Put Inline Policy', 'CRITICAL', AP, 'aws_iam_policy', ['T1098.001'], 'Identity: VulnerableAdminPolicy → Action: iam:PutUserPolicy → Target Resources: *', 'Allows creating inline policies with arbitrary permissions (Action: iam:PutUserPolicy)'),
      F('VULN-0003', 'Create Access Keys for Other Users', 'CRITICAL', AP, 'aws_iam_policy', ['T1098.004'], 'Identity: VulnerableAdminPolicy → Action: iam:CreateAccessKey → Target Resources: *', 'Can create access keys for any user, enabling credential theft (Action: iam:CreateAccessKey)'),
      F('VULN-0004', 'Update Login Profile', 'CRITICAL', AP, 'aws_iam_policy', ['T1098.005'], 'Identity: VulnerableAdminPolicy → Action: iam:UpdateLoginProfile → Target Resources: *', 'Can change password for any user (Action: iam:UpdateLoginProfile)'),
      F('VULN-0005', 'Role Assumption', 'CRITICAL', AP, 'aws_iam_policy', ['T1550.001'], 'Identity: VulnerableAdminPolicy → Action: sts:AssumeRole → Target Resources: *', 'Can assume roles with elevated permissions (Action: sts:AssumeRole)'),
      F('VULN-0006', 'Pass Role to Services', 'CRITICAL', AP, 'aws_iam_policy', ['T1098.003'], 'Identity: VulnerableAdminPolicy → Action: iam:PassRole → Target Resources: *', 'Can pass privileged roles to EC2, Lambda, etc. (Action: iam:PassRole)'),
      F('VULN-0007', 'Create Role', 'HIGH', AP, 'aws_iam_policy', ['T1098.003'], 'Identity: VulnerableAdminPolicy → Action: iam:CreateRole → Target Resources: *', 'Can create roles with arbitrary trust policies (Action: iam:CreateRole)'),
      F('VULN-0008', 'Put Role Policy', 'CRITICAL', AP, 'aws_iam_policy', ['T1098.003'], 'Identity: VulnerableAdminPolicy → Action: iam:PutRolePolicy → Target Resources: *', 'Can attach inline policies to any role (Action: iam:PutRolePolicy)'),
      F('VULN-0009', 'Attach Role Policy', 'CRITICAL', AP, 'aws_iam_policy', ['T1098.003'], 'Identity: VulnerableAdminPolicy → Action: iam:AttachRolePolicy → Target Resources: *', 'Can attach managed policies to any role (Action: iam:AttachRolePolicy)'),
      F('VULN-0010', 'Update Assume Role Policy', 'CRITICAL', AP, 'aws_iam_policy', ['T1550.001'], 'Identity: VulnerableAdminPolicy → Action: iam:UpdateAssumeRolePolicy → Target Resources: *', 'Can modify trust policy to allow self-assumption (Action: iam:UpdateAssumeRolePolicy)'),
      F('VULN-0011', 'Run Instances with Role', 'HIGH', AP, 'aws_iam_policy', ['T1611'], 'Identity: VulnerableAdminPolicy → Action: ec2:RunInstances → Target Resources: *', 'Can launch EC2 with instance profile for privilege escalation (Action: ec2:RunInstances)'),
      F('VULN-0012', 'Create Lambda Function', 'HIGH', AP, 'aws_iam_policy', ['T1611'], 'Identity: VulnerableAdminPolicy → Action: lambda:CreateFunction → Target Resources: *', 'Can create Lambda with privileged execution role (Action: lambda:CreateFunction)'),
      F('VULN-0013', 'Update Lambda Code', 'HIGH', AP, 'aws_iam_policy', ['T1611'], 'Identity: VulnerableAdminPolicy → Action: lambda:UpdateFunctionCode → Target Resources: *', 'Can modify Lambda code to execute arbitrary commands (Action: lambda:UpdateFunctionCode)'),
      F('VULN-0014', 'Attached Managed Policy: VulnerableAdminPolicy', 'MEDIUM', 'VulnerableEC2Role', 'aws_iam_role', ['T1098.001'], 'Identity: VulnerableEC2Role → Policy: arn:aws:iam::123456789012:policy/VulnerableAdminPolicy', 'aws_iam_role VulnerableEC2Role has managed policy attached'),
      F('VULN-0015', 'Attached Managed Policy: ReadOnlyAccess', 'MEDIUM', CU, 'aws_iam_user', ['T1098.001'], 'Identity: CompromisedUser → Policy: arn:aws:iam::123456789012:policy/ReadOnlyAccess', 'aws_iam_user CompromisedUser has managed policy attached'),
      F('VULN-0016', 'User Can Attach Admin Policy', 'CRITICAL', CU, 'aws_iam_user', ['T1098.001'], 'Identity: CompromisedUser → Action: iam:AttachUserPolicy → Target Resources: *', 'Allows attaching any managed policy including AdministratorAccess (Action: iam:AttachUserPolicy)'),
      F('VULN-0017', 'Create Access Keys for Other Users', 'CRITICAL', CU, 'aws_iam_user', ['T1098.004'], 'Identity: CompromisedUser → Action: iam:CreateAccessKey → Target Resources: *', 'Can create access keys for any user, enabling credential theft (Action: iam:CreateAccessKey)'),
      F('VULN-0018', 'Create Lambda Function', 'HIGH', LP, 'aws_iam_policy', ['T1611'], 'Identity: LambdaEscalationPolicy → Action: lambda:CreateFunction → Target Resources: *', 'Can create Lambda with privileged execution role (Action: lambda:CreateFunction)'),
      F('VULN-0019', 'Update Lambda Code', 'HIGH', LP, 'aws_iam_policy', ['T1611'], 'Identity: LambdaEscalationPolicy → Action: lambda:UpdateFunctionCode → Target Resources: *', 'Can modify Lambda code to execute arbitrary commands (Action: lambda:UpdateFunctionCode)'),
      F('VULN-0020', 'Pass Role to Services', 'CRITICAL', LP, 'aws_iam_policy', ['T1098.003'], 'Identity: LambdaEscalationPolicy → Action: iam:PassRole → Target Resources: *', 'Can pass privileged roles to EC2, Lambda, etc. (Action: iam:PassRole)'),
      F('VULN-0021', 'Attached Managed Policy: PowerUserAccess', 'MEDIUM', 'DevelopersGroup', 'aws_iam_group', ['T1098.001'], 'Identity: DevelopersGroup → Policy: arn:aws:iam::aws:policy/PowerUserAccess', 'aws_iam_group DevelopersGroup has managed policy attached')
    ],
    techniques: [
      { id: 'T1098.001', name: 'Additional Cloud Credentials', tactic: 'Persistence', count: 6 },
      { id: 'T1098.003', name: 'Additional Cloud Roles', tactic: 'Persistence', count: 5 },
      { id: 'T1611', name: 'Escape to Host', tactic: 'Privilege Escalation', count: 5 },
      { id: 'T1550.001', name: 'Application Access Token', tactic: 'Lateral Movement', count: 2 },
      { id: 'T1098.004', name: 'Additional Access Keys', tactic: 'Persistence', count: 2 },
      { id: 'T1098.005', name: 'Change Login Profile', tactic: 'Persistence', count: 1 }
    ],
    risks: [
      { name: AP, critical: 9, high: 4, medium: 0, low: 0, total: 13, score: 100 },
      { name: CU, critical: 2, high: 0, medium: 1, low: 0, total: 3, score: 58 },
      { name: LP, critical: 1, high: 2, medium: 0, low: 0, total: 3, score: 55 },
      { name: 'VulnerableEC2Role', critical: 0, high: 0, medium: 1, low: 0, total: 1, score: 8 },
      { name: 'DevelopersGroup', critical: 0, high: 0, medium: 1, low: 0, total: 1, score: 8 }
    ],
    queue: [
      ['Remove iam:AttachUserPolicy/AttachRolePolicy', 'CRITICAL', 4],
      ['Remove iam:PutUserPolicy/PutRolePolicy', 'CRITICAL', 4],
      ['Restrict Role Assumption with Conditions', 'HIGH', 2],
      ['Restrict iam:PassRole to Specific Roles', 'HIGH', 2],
      ['Restrict CreateAccessKey to Self', 'HIGH', 2],
      ['Restrict UpdateLoginProfile to Self', 'HIGH', 2],
      ['Apply Permissions Boundary', 'HIGH', 2],
      ['Use Permissions Boundary for Role Creation', 'HIGH', 2],
      ['Restrict Service Role Passing', 'MEDIUM', 1],
      ['Review Attached Managed Policy', 'MEDIUM', 1]
    ],
    remediations: {},
    aiCount: 0
  };

  DEMO_RESULT.source = 'offline-demo';
  DEMO_RESULT.sourceName = 'Bundled offline sample';
  DEMO_RESULT.accountId = null;
  DEMO_RESULT.identityCount = 5;
  DEMO_RESULT.policyCount = 3;
  DEMO_RESULT.escalationPaths = 0;
  DEMO_RESULT.paths = [];
  DEMO_RESULT.permGraph = null;
  DEMO_RESULT.coverage = {
    input_format: 'offline_demo', complete: true, total_resources: 0,
    iam_resources: 0, skipped_resources: 0,
    warnings: ['Backend unavailable; showing the bundled offline sample.']
  };
  DEMO_RESULT.aiStatus = 'disabled';

  /* Offline-only remediation copy. When the API answers, the backend's own
     Remediator output is used instead of this table. */
  var STRATEGY_ACTIONS = {
    attach_policy: [
      { name: 'Remove iam:AttachUserPolicy/AttachRolePolicy', priority: 'CRITICAL',
        description: 'Remove the ability to attach arbitrary managed policies. If attachment is needed, restrict to specific policy ARNs using condition keys.',
        code: { Before: { Effect: 'Allow', Action: 'iam:AttachUserPolicy', Resource: '*' }, After: { Effect: 'Allow', Action: 'iam:AttachUserPolicy', Resource: 'arn:aws:iam::<ACCOUNT_ID>:user/<TARGET_USER_NAME>', Condition: { ArnEquals: { 'iam:PolicyARN': 'arn:aws:iam::<ACCOUNT_ID>:policy/<APPROVED_POLICY_NAME>' } } } },
        explanation: 'Wildcard attachment allows escalation to AdministratorAccess. Restrict to specific approved policies.' },
      { name: 'Apply Permissions Boundary', priority: 'HIGH',
        description: 'Set a permissions boundary on the identity to limit maximum permissions regardless of attached policies.',
        code: { PermissionsBoundary: 'arn:aws:iam::<ACCOUNT_ID>:policy/<BOUNDARY_POLICY_NAME>' },
        explanation: 'Permissions boundaries provide a guardrail that cannot be bypassed by attaching policies.' }
    ],
    pass_role: [
      { name: 'Restrict iam:PassRole to Specific Roles', priority: 'HIGH',
        description: 'Limit which roles can be passed to services like EC2 and Lambda.',
        code: { Before: { Effect: 'Allow', Action: 'iam:PassRole', Resource: '*' }, After: { Effect: 'Allow', Action: 'iam:PassRole', Resource: 'arn:aws:iam::<ACCOUNT_ID>:role/<ALLOWED_ROLE_NAME>', Condition: { StringEquals: { 'iam:PassedToService': '<APPROVED_SERVICE>' } } } },
        explanation: 'Prevents passing privileged roles (e.g. AdminRole) to compute resources.' }
    ],
    access_key: [
      { name: 'Restrict CreateAccessKey to Self', priority: 'HIGH',
        description: 'Add a condition so access keys can only be created for the calling user.',
        code: { Before: { Effect: 'Allow', Action: 'iam:CreateAccessKey', Resource: '*' }, After: { Effect: 'Allow', Action: 'iam:CreateAccessKey', Resource: 'arn:aws:iam::<ACCOUNT_ID>:user/${aws:username}' } },
        explanation: 'Prevents creating access keys for other users (credential theft).' }
    ],
    managed_policy_review: [
      { name: 'Review Attached Managed Policy', priority: 'MEDIUM',
        description: 'Audit the attached managed policy for excessive permissions and replace it with a scoped custom policy.',
        code: { Review: 'aws iam get-policy-version --policy-arn <arn> --version-id <default>' },
        explanation: 'Broad AWS-managed policies (e.g. PowerUserAccess) usually exceed what the identity needs.' }
    ]
  };

  var RISK_BY_SEV = { CRITICAL: 95, HIGH: 75, MEDIUM: 50, LOW: 25 };

  function strategyFor(f) {
    if (f.title.indexOf('Attached Managed Policy') === 0) return 'managed_policy_review';
    if (f.title.indexOf('Attach') === 0 || f.title.indexOf('User Can Attach') === 0) return 'attach_policy';
    if (f.title === 'Pass Role to Services') return 'pass_role';
    if (f.title === 'Create Access Keys for Other Users') return 'access_key';
    return 'attach_policy';
  }

  /* ---------------- state ---------------- */

  var state = {
    view: 'overview',
    theme: localStorage.getItem('winnow-theme') || 'dark',
    data: DEMO_RESULT,
    groups: [],
    selId: null,
    query: '',
    sev: 'ALL',
    gdQuery: '',
    gdSev: 'ALL',
    showIdent: true,
    showMitre: true,
    spin: true,
    paletteOpen: false,
    paletteIndex: 0,
    sourceTab: 'demo',
    analysisStatus: 'loading',
    analysisError: '',
    scanTime: null,
    selectedPath: null,
    selectedEvidence: 0,
    policyView: 'proposed',
    validationReviewed: false,
    currentPolicy: null,
    requestSerial: 0,
    uploadedFileName: ''
  };

  var hero = null, graph = null;

  var NAV = [
    ['overview', 'Overview', ['M3 12l9-9 9 9', 'M5 10v10h14V10']],
    ['graph', 'Attack graph', ['M5 8a3 3 0 1 0 0-6 3 3 0 0 0 0 6z', 'M19 8a3 3 0 1 0 0-6 3 3 0 0 0 0 6z', 'M12 22a3 3 0 1 0 0-6 3 3 0 0 0 0 6z', 'M8 6.5h8', 'M7.5 8l3 9', 'M16.5 8l-3 9']],
    ['findings', 'Findings', ['M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z', 'M14 2v6h6', 'M16 13H8', 'M16 17H8']],
    ['remediation', 'Remediation', ['M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z']],
    ['visualizer', 'Path explorer', ['M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7z', 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z']],
    ['charts', 'Charts', ['M21.21 15.89A10 10 0 1 1 8 2.83', 'M22 12A10 10 0 0 0 12 2v10z']]
  ];
  var TITLES = { overview: 'Posture overview', graph: 'Attack graph', findings: 'Findings', remediation: 'Policy workbench', visualizer: 'Path explorer', charts: 'Charts' };

  /* ---------------- helpers ---------------- */

  function $(id) { return document.getElementById(id); }
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) { return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]; }); }
  function icon(paths, size) {
    return '<svg width="' + (size || 14) + '" height="' + (size || 14) + '" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">' +
      paths.map(function (d) { return '<path d="' + d + '"/>'; }).join('') + '</svg>';
  }
  function countBy(sev) { return state.data.findings.filter(function (f) { return f.severity === sev; }).length; }
  function totalHours() { return state.data.queue.reduce(function (a, q) { return a + (Number(q[2]) || 0); }, 0); }
  function findingById(id) {
    var all = state.data.findings;
    for (var i = 0; i < all.length; i++) if (all[i].id === id) return all[i];
    return all[0];
  }

  /* Group findings by resource — the identity column of the graph. */
  function computeGroups() {
    var order = [], byName = {};
    state.data.findings.forEach(function (f) {
      if (!byName[f.resource]) { byName[f.resource] = { name: f.resource, type: f.resource_type, ids: [] }; order.push(byName[f.resource]); }
      byName[f.resource].ids.push(f.id);
    });
    order.sort(function (a, b) { return b.ids.length - a.ids.length; });
    state.groups = order;
  }

  /* Map the /api/analyze response onto the view model. Keys here match the
     verified contract; there are no speculative fallbacks left. */
  function normalise(payload) {
    if (!payload) return DEMO_RESULT;
    var raw = payload.vulnerabilities || [];

    var findings = raw.map(function (f) {
      var path = f.attack_path;
      return {
        id: f.id,
        title: f.title || 'Unnamed finding',
        severity: String(f.severity || 'MEDIUM').toUpperCase(),
        resource: f.resource_name || 'unknown',
        resource_type: f.resource_type || '',
        mitre: f.mitre_techniques || [],
        /* attack_path arrives as an array of steps. */
        attack_path: Array.isArray(path) ? path.join(' → ') : (path || ''),
        description: f.description || '',
        detection_source: f.detection_source || 'rule',
        policy_document: f.policy_document || {},
        decision: f.decision || 'allowed',
        unknowns: f.unknowns || [],
        technique: (f.policy_document && f.policy_document.technique) || ''
      };
    });

    var viz = payload.visualization || {};

    /* The backend resolves technique names and tactics from its MITRE table;
       only rebuild the histogram if that section is missing. */
    var techniques;
    var heat = viz.mitre_heatmap && viz.mitre_heatmap.techniques;
    if (heat && heat.length) {
      techniques = heat.map(function (t) {
        return { id: t.id, name: t.name || t.id, tactic: t.tactic || '', count: t.count || 0 };
      });
    } else {
      var techMap = {};
      findings.forEach(function (f) {
        f.mitre.forEach(function (t) {
          if (!techMap[t]) techMap[t] = { id: t, name: t, tactic: '', count: 0 };
          techMap[t].count++;
        });
      });
      techniques = Object.keys(techMap).map(function (k) { return techMap[k]; })
        .sort(function (a, b) { return b.count - a.count; });
    }

    /* Same for the weighted per-resource risk score. */
    var risks;
    var rr = viz.resource_risk_map && viz.resource_risk_map.resources;
    if (rr && rr.length) {
      risks = rr.map(function (r) {
        return { name: r.name, critical: r.critical || 0, high: r.high || 0, medium: r.medium || 0, low: r.low || 0, total: r.total || 0, score: r.risk_score || 0 };
      });
    } else {
      var riskMap = {};
      findings.forEach(function (f) {
        var r = riskMap[f.resource] || (riskMap[f.resource] = { name: f.resource, critical: 0, high: 0, medium: 0, low: 0, total: 0, score: 0 });
        r.total++;
        if (f.severity === 'CRITICAL') r.critical++;
        else if (f.severity === 'HIGH') r.high++;
        else if (f.severity === 'LOW') r.low++;
        else r.medium++;
      });
      risks = Object.keys(riskMap).map(function (k) { return riskMap[k]; });
      var maxW = 1;
      risks.forEach(function (r) { r._w = r.critical * 10 + r.high * 5 + r.medium * 2 + r.low; maxW = Math.max(maxW, r._w); });
      risks.forEach(function (r) { r.score = Math.round((r._w / maxW) * 100); });
      risks.sort(function (a, b) { return b.score - a.score; });
    }

    /* The remediation queue is the backend's timeline, already sorted by
       priority and carrying its own hour estimates. */
    var items = (viz.remediation_timeline && viz.remediation_timeline.items) || [];
    var queue = items.map(function (i) {
      return [i.action || '', String(i.priority || 'MEDIUM').toUpperCase(), Number(i.estimated_hours) || 0];
    });

    /* Index the real remediations by vulnerability id. */
    var remediations = {};
    (payload.remediations || []).forEach(function (entry) {
      var rem = entry && entry.remediation;
      if (!rem) return;
      var key = rem.vulnerability_id || (entry.vulnerability && entry.vulnerability.id);
      if (key) remediations[key] = rem;
    });

    var summary = payload.summary || {};
    var permGraph = (viz.permission_graph && viz.permission_graph.nodes) ? viz.permission_graph : null;
    var paths = (permGraph && permGraph.escalation_paths) || [];

    return {
      findings: findings, techniques: techniques, risks: risks, queue: queue,
      remediations: remediations,
      aiCount: summary.ai_suggested || 0,
      graphCount: summary.graph_detected || 0,
      escalationPaths: summary.escalation_paths || 0,
      permGraph: permGraph,
      paths: paths,
      source: summary.source || 'upload',
      sourceName: summary.source_name || null,
      accountId: summary.account_id || null,
      identityCount: Number(summary.identity_count) || 0,
      policyCount: Number(summary.policy_count) || 0,
      coverage: summary.coverage || { complete: true, warnings: [] },
      aiStatus: summary.ai_status || 'disabled'
    };
  }

  /* ---------------- rendering ---------------- */

  function renderNav() {
    $('nav').innerHTML = NAV.map(function (n) {
      var id = n[0];
      var count = id === 'findings' ? state.data.findings.length
        : id === 'remediation' ? state.data.queue.length
        : id === 'visualizer' ? state.data.escalationPaths
        : id === 'graph' ? '3D' : '';
      return '<button class="nav-item" data-goto="' + id + '"' + (state.view === id ? ' aria-current="page"' : '') + '>' +
        icon(n[2], 14) + '<span class="label">' + esc(n[1]) + '</span><span class="count">' + esc(count) + '</span></button>';
    }).join('');
  }

  function renderTopbar() {
    $('view-title').textContent = TITLES[state.view];
    $('stat-findings').textContent = state.data.findings.length + ' findings';
    $('stat-identities').textContent = state.data.identityCount + ' identities';
    $('stat-techniques').textContent = state.data.escalationPaths + ' paths';
    var sourceLabel = state.data.source === 'live' ? 'AWS account'
      : state.data.source === 'demo' ? 'Demo'
      : state.data.source === 'offline-demo' ? 'Offline demo' : 'Uploaded JSON';
    $('source-eyebrow').textContent = 'Analysis · ' + sourceLabel;
  }

  function renderAnalysisContext() {
    var d = state.data, coverage = d.coverage || {}, warnings = coverage.warnings || [];
    var source = d.source === 'live' ? ('AWS ' + (d.accountId || 'account'))
      : (d.sourceName || (d.source === 'demo' ? 'Bundled demo' : d.source === 'offline-demo' ? 'Bundled offline sample' : 'Uploaded JSON'));
    var status = state.analysisStatus === 'loading' ? 'Analyzing'
      : state.analysisStatus === 'error' ? 'Failed'
      : !coverage.complete ? 'Partial coverage'
      : d.findings.length ? 'Analysis complete' : 'No findings detected';
    var time = state.scanTime ? state.scanTime.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '';
    $('analysis-context').innerHTML =
      '<span class="context-source">' + esc(source) + '</span>' +
      '<span class="context-sep">·</span><span>' + esc(status) + '</span>' +
      (time ? '<span class="context-sep">·</span><span>' + esc(time) + '</span>' : '') +
      '<span class="context-sep">·</span><span>' + esc(d.identityCount) + ' identities</span>' +
      '<span class="context-sep">·</span><span>' + esc(d.policyCount) + ' policies</span>' +
      (warnings.length ? '<span class="context-warning">' + esc(warnings.length) + ' coverage note' + (warnings.length === 1 ? '' : 's') + '</span>' : '');
  }

  function renderSourcePanel() {
    Array.prototype.forEach.call(document.querySelectorAll('[data-source-tab]'), function (button) {
      var selected = button.getAttribute('data-source-tab') === state.sourceTab;
      button.setAttribute('aria-selected', selected ? 'true' : 'false');
    });
    ['demo', 'upload', 'live'].forEach(function (name) {
      $('source-' + name).hidden = name !== state.sourceTab;
    });
    var message = $('source-message');
    message.hidden = !state.analysisError;
    message.textContent = state.analysisError || '';
  }

  function renderResultState() {
    var host = $('result-state');
    var coverage = state.data.coverage || {}, warnings = coverage.warnings || [];
    if (state.analysisStatus === 'loading') {
      host.hidden = false;
      host.className = 'result-state loading';
      host.innerHTML = '<strong>Analyzing this source…</strong><span>Import, permission evaluation, paths, and remediation are running.</span>';
      return;
    }
    if (state.analysisStatus === 'error') {
      host.hidden = false;
      host.className = 'result-state error';
      host.innerHTML = '<strong>Analysis failed</strong><span>' + esc(state.analysisError) + '</span>';
      return;
    }
    if (!state.data.findings.length || !coverage.complete || warnings.length) {
      host.hidden = false;
      host.className = 'result-state ' + (!coverage.complete ? 'warning' : 'success');
      var title = !coverage.complete ? 'Analysis completed with coverage limits'
        : !state.data.findings.length ? 'No findings detected within this scan’s coverage'
        : 'Coverage notes apply to these results';
      host.innerHTML = '<strong>' + esc(title) + '</strong>' +
        '<span>' + esc(warnings.join(' · ') || 'The remediation queue is empty.') + '</span>';
      return;
    }
    host.hidden = true;
  }

  function renderOverview() {
    var crit = countBy('CRITICAL'), high = countBy('HIGH'), med = countBy('MEDIUM'), low = countBy('LOW');
    var top = state.data.risks[0];
    var words = ['Zero', 'One', 'Two', 'Three', 'Four', 'Five', 'Six', 'Seven', 'Eight', 'Nine', 'Ten', 'Eleven', 'Twelve'];
    var pathCount = state.data.escalationPaths;
    $('hero-title').innerHTML = pathCount
      ? esc(words[pathCount] || pathCount) + ' candidate<br>escalation path' + (pathCount === 1 ? '' : 's')
      : 'No candidate<br>escalation paths';
    if (top) {
      $('hero-note').textContent = top.name + ' carries ' + top.total + ' finding' + (top.total === 1 ? '' : 's') + '.';
      $('hero-risk').textContent = 'risk ' + top.score + '/100';
    } else {
      $('hero-note').textContent = state.analysisStatus === 'error' ? 'The current analysis did not complete.' : 'No risky resources were found in the supported input.';
      $('hero-risk').textContent = 'no scored resources';
    }
    $('hero-actions').textContent = state.data.queue.length + ' actions · ' + totalHours() + 'h';

    var metrics = [
      ['Critical', crit, crit ? 'highest urgency' : 'clear', 'var(--n-crit)'],
      ['High', high, 'compute escalation', 'var(--n-high)'],
      ['Medium', med, 'managed policies', 'var(--n-med)'],
      ['Low', low, low ? 'informational' : 'nothing benign', 'var(--n-low)'],
      ['Identities', state.data.identityCount, 'users · roles · groups', 'var(--n-acc)'],
      ['Techniques', state.data.techniques.length, 'MITRE ATT&CK', 'var(--n-mute)']
    ];
    $('metrics').innerHTML = metrics.map(function (m) {
      return '<div class="metric"><div class="metric-label"><i class="metric-bar" style="background:' + m[3] + '"></i>' + esc(m[0]) + '</div>' +
        '<div class="metric-value">' + esc(m[1]) + '</div><div class="metric-note">' + esc(m[2]) + '</div></div>';
    }).join('');

    $('risk-list').innerHTML = state.data.risks.map(function (r) {
      var pc = function (n) { return (n / Math.max(1, r.total) * 100) + '%'; };
      return '<div class="risk-row"><span class="risk-name" title="' + esc(r.name) + '">' + esc(r.name) + '</span>' +
        '<span class="risk-track">' +
        '<i style="width:' + pc(r.critical) + ';background:var(--n-crit)"></i>' +
        '<i style="width:' + pc(r.high) + ';background:var(--n-high)"></i>' +
        '<i style="width:' + pc(r.medium) + ';background:var(--n-med)"></i>' +
        '<i style="width:' + pc(r.low) + ';background:var(--n-low)"></i>' +
        '</span><span class="risk-score">' + esc(r.score) + '/100</span></div>';
    }).join('') || '<div class="empty-panel">No resource risk to display.</div>';

    $('top-findings').innerHTML = state.data.findings.filter(function (f) { return f.severity === 'CRITICAL'; }).slice(0, 6).map(function (f) {
      return '<button class="list-row" data-select="' + esc(f.id) + '" data-goto="remediation"><i class="dot" style="background:' + SEV_VAR[f.severity] + '"></i>' +
        '<span class="title">' + esc(f.title) + '</span><span class="meta">' + esc(f.resource) + '</span></button>';
    }).join('') || '<div class="empty-panel">No findings in this analysis.</div>';
    renderSourcePanel();
    renderResultState();
    renderAnalysisContext();
  }

  function renderInspector() {
    var f = findingById(state.selId);
    if (!f) {
      $('inspector').innerHTML = '<div class="empty-panel">No finding selected.</div>';
      return;
    }
    $('inspector').innerHTML =
      '<div class="eyebrow">Selected node</div>' +
      '<div class="head">' + esc(f.title) + '</div>' +
      '<div class="tag-row"><span class="tag" style="border-color:' + SEV_VAR[f.severity] + ';color:' + SEV_VAR[f.severity] + '">' + esc(f.severity) + '</span>' +
      '<span class="tag">' + esc(f.id) + '</span>' +
      (f.decision === 'candidate' ? '<span class="tag" style="color:var(--n-med)">conditional</span>' : '') +
      (f.detection_source === 'ai' ? '<span class="tag">AI suggested</span>' : '') + '</div>' +
      '<div class="body">' + esc(f.description) + '</div>' +
      '<dl class="facts"><dt>Resource</dt><dd class="mono">' + esc(f.resource) + (f.resource_type ? ' (' + esc(f.resource_type) + ')' : '') + '</dd>' +
      '<dt style="margin-top:6px">Attack path</dt><dd>' + esc(f.attack_path) + '</dd></dl>' +
      '<button class="btn" data-goto="remediation" style="margin-top:4px;border-color:var(--n-acc)">Open remediation</button>';
  }

  /* Text mirror of the 3D attack graph, shown below it: every identity, the
     findings on it, and the MITRE techniques each finding maps to. A selected
     node — clicked in the 3D view or in a row here — is highlighted and scrolled
     into view. The search box + severity chips filter the rows (they never
     touch the 3D scene). Only #gd-body / #gd-meta / #gd-sev-filters are
     rewritten, so the search input keeps focus while typing. */
  function gdRowMatches(f, q) {
    if (state.gdSev !== 'ALL' && f.severity !== state.gdSev) return false;
    if (!q) return true;
    return (f.id + ' ' + f.title + ' ' + f.resource + ' ' + (f.mitre || []).join(' '))
      .toLowerCase().indexOf(q) >= 0;
  }

  function renderGraphDetail(scrollToSel) {
    var host = $('graph-detail');
    var body = $('gd-body');
    if (!host || !body) return;
    var groups = state.groups || [];

    var filters = $('gd-sev-filters');
    if (filters) {
      filters.innerHTML = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(function (k) {
        var label = k === 'ALL' ? 'All' : k.charAt(0) + k.slice(1).toLowerCase();
        return '<button class="chip" data-gd-sev="' + k + '" aria-pressed="' + (state.gdSev === k) + '">' + label + '</button>';
      }).join('');
    }

    if (!groups.length) {
      body.innerHTML = '<div class="gd-empty">No findings to break down.</div>';
      if ($('gd-meta')) $('gd-meta').textContent = '';
      return;
    }

    var techById = {};
    (state.data.techniques || []).forEach(function (t) { techById[t.id] = t; });
    var q = state.gdQuery.trim().toLowerCase();
    var shown = 0;

    var html = groups.map(function (g) {
      var matched = g.ids.filter(function (id) {
        var f = findingById(id);
        return f && f.id === id && gdRowMatches(f, q);
      });
      if (!matched.length) return '';
      shown += matched.length;

      var rows = matched.map(function (id) {
        var f = findingById(id);
        var techs = (f.mitre || []).map(function (m) {
          var t = techById[m];
          return '<span class="gd-tech" title="' + esc((t && t.tactic) || '') + '">' +
            esc(m) + (t && t.name ? ' · ' + esc(t.name) : '') + '</span>';
        }).join('');
        return '<button class="gd-row' + (id === state.selId ? ' sel' : '') + '" data-select="' + esc(id) + '">' +
          '<i class="dot" style="background:' + SEV_VAR[f.severity] + '"></i>' +
          '<span class="gd-id">' + esc(f.id) + '</span>' +
          '<span class="gd-title">' + esc(f.title) + '</span>' +
          '<span class="gd-sev" style="color:' + SEV_VAR[f.severity] + '">' + esc(f.severity) + '</span>' +
          '<span class="gd-techs">' + (techs || '<span class="gd-tech gd-none">no technique</span>') + '</span>' +
        '</button>';
      }).join('');
      return '<div class="gd-group">' +
        '<div class="gd-identity">' +
          '<span class="gd-name">' + esc(g.name) + '</span>' +
          '<span class="gd-type mono">' + esc(g.type || 'identity') + '</span>' +
          '<span class="gd-count">' + matched.length +
            (matched.length === g.ids.length ? '' : ' of ' + g.ids.length) +
            (g.ids.length === 1 && matched.length === 1 ? ' finding' : ' findings') + '</span>' +
        '</div>' + rows +
      '</div>';
    }).join('');

    body.innerHTML = html || '<div class="gd-empty">No findings match that filter.</div>';

    if ($('gd-meta')) {
      var total = state.data.findings.length;
      $('gd-meta').textContent = (shown === total ? total + ' findings' : shown + ' of ' + total + ' findings') +
        ' · ' + groups.length + ' identities';
    }

    /* Only chase the selected row into view when the user just picked it (a 3D
       node or a row click). On load / filter / data refresh, leave the panel at
       the top — otherwise every reload jumps to whatever VULN-0001 maps to. */
    if (scrollToSel) {
      var sel = body.querySelector('.gd-row.sel');
      if (sel) {
        var hr = host.getBoundingClientRect(), r = sel.getBoundingClientRect();
        if (r.top < hr.top + 72 || r.bottom > hr.bottom) {
          host.scrollTop += (r.top - hr.top) - (host.clientHeight - r.height) / 2;
        }
      }
    }
  }

  function renderFindings() {
    var q = state.query.trim().toLowerCase();
    var rows = state.data.findings.filter(function (f) {
      if (state.sev !== 'ALL' && f.severity !== state.sev) return false;
      if (!q) return true;
      return (f.title + ' ' + f.id + ' ' + f.resource + ' ' + f.mitre.join(' ')).toLowerCase().indexOf(q) >= 0;
    });

    $('sev-filters').innerHTML = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(function (k) {
      var label = k === 'ALL' ? 'All' : k.charAt(0) + k.slice(1).toLowerCase();
      return '<button class="chip" data-sev="' + k + '" aria-pressed="' + (state.sev === k) + '">' + label + '</button>';
    }).join('');

    $('shown-count').textContent = rows.length + ' of ' + state.data.findings.length;

    $('findings-body').innerHTML = rows.map(function (f) {
      return '<tr data-select="' + esc(f.id) + '" data-goto="remediation">' +
        '<td class="id">' + esc(f.id) + '</td>' +
        '<td>' + esc(f.title) + (f.detection_source === 'ai' ? ' <span class="tag">AI</span>' : '') + '</td>' +
        '<td><span class="sev" style="color:' + SEV_VAR[f.severity] + '"><i class="dot" style="background:' + SEV_VAR[f.severity] + '"></i>' + esc(f.severity) + '</span></td>' +
        '<td class="mono">' + esc(f.resource) + '</td>' +
        '<td><span class="mitre-tags">' + f.mitre.map(function (m) { return '<span class="tag">' + esc(m) + '</span>'; }).join('') + '</span></td>' +
        '<td style="text-align:right"><button class="btn btn-sm">Remediate</button></td></tr>';
    }).join('') || '<tr><td colspan="6" style="color:var(--n-mute)">No findings match that filter.</td></tr>';
  }

  function renderRemediation() {
    var f = findingById(state.selId);
    if (!f) {
      $('rem-header').innerHTML = '<div class="empty-panel">No remediation is needed because this analysis has no findings.</div>';
      $('rem-actions').innerHTML = '';
      $('policy-code').textContent = '';
      $('policy-caption').textContent = 'No proposal selected';
      $('validation-checks').innerHTML = '<div class="empty-panel">No proposal to check.</div>';
      $('validation-status').textContent = 'No proposal';
      $('compliance').innerHTML = '<div>Nothing mapped for this result.</div>';
      $('queue-mini').innerHTML = '<div class="empty-panel">Queue is empty.</div>';
      return;
    }
    var real = state.data.remediations[f.id];

    /* Prefer the backend's own remediation for this finding; the local
       strategy table is only used in the offline preview. */
    var actions, hardened, original, compliance, score, summary, validation, requiredInputs;
    if (real) {
      actions = (real.actions || []).map(function (a) {
        return {
          name: a.action || '', priority: String(a.priority || 'MEDIUM').toUpperCase(),
          description: a.description || '',
          code: typeof a.code_example === 'string' ? a.code_example : JSON.stringify(a.code_example, null, 2),
          explanation: a.explanation || ''
        };
      });
      hardened = real.hardened_policy || {};
      original = real.original_policy || {};
      compliance = real.compliance_notes || [];
      score = real.risk_score;
      summary = real.summary || '';
      validation = real.validation || {};
      requiredInputs = real.required_inputs || [];
    } else {
      var strategy = strategyFor(f);
      actions = (STRATEGY_ACTIONS[strategy] || STRATEGY_ACTIONS.attach_policy).map(function (a) {
        return { name: a.name, priority: a.priority, description: a.description, code: JSON.stringify(a.code, null, 2), explanation: a.explanation };
      });
      hardened = strategy === 'managed_policy_review'
        ? { attached_policy_arn: 'scoped-replacement-required' }
        : { Version: '2012-10-17', Statement: [{
            Effect: 'Allow',
            Action: strategy === 'access_key' ? ['iam:CreateAccessKey'] : strategy === 'pass_role' ? ['iam:PassRole'] : ['iam:CreateAccessKey', 'iam:PassRole'],
            Resource: strategy === 'access_key' ? ['arn:aws:iam::<ACCOUNT_ID>:user/${aws:username}'] : ['arn:aws:iam::<ACCOUNT_ID>:role/<ALLOWED_ROLE_NAME>']
          }] };
      compliance = ['CIS AWS Foundations Benchmark', 'NIST 800-53 Access Control Family'];
      score = RISK_BY_SEV[f.severity];
      summary = 'Vulnerability in ' + f.resource + ': ' + f.title + '.';
      original = f.policy_document && f.policy_document.statement
        ? { Version: '2012-10-17', Statement: [f.policy_document.statement] } : {};
      validation = { status: 'review_required', policy_structure: 'unknown', conditions_preserved: false, change_present: false, export_ready: false, modeled_impact: 'not_run' };
      requiredInputs = ['Backend connection'];
    }

    $('rem-header').innerHTML =
      '<div class="row"><div style="flex:1;min-width:220px">' +
      '<div class="title">' + esc(f.title) + '</div>' +
      '<div class="facts"><span>' + esc(f.id) + '</span><span>' + esc(f.resource) + '</span><span style="color:' + SEV_VAR[f.severity] + '">' + esc(f.severity) + '</span>' +
      (real ? '<span>' + esc(real.source === 'ai' ? 'AI remediation' : 'rule engine') + '</span>' : '') + '</div>' +
      '</div><div style="text-align:right"><div class="score">' + esc(score) + '/100</div><div class="score-label">risk score</div></div></div>' +
      '<div class="rem-summary">' + esc(summary) + '</div>';

    $('rem-actions').innerHTML = actions.map(function (a) {
      var color = a.priority === 'CRITICAL' ? 'var(--n-crit)' : a.priority === 'HIGH' ? 'var(--n-high)' : 'var(--n-med)';
      return '<div class="panel"><div class="panel-head"><span class="panel-title" style="flex:1 1 auto">' + esc(a.name) + '</span>' +
        '<span class="tag" style="border-color:' + color + ';color:' + color + '">' + esc(a.priority) + '</span></div>' +
        '<div class="panel-body"><div style="font-size:12.5px;color:var(--n-mute);line-height:1.6">' + esc(a.description) + '</div>' +
        '<div class="code"><pre>' + esc(a.code) + '</pre></div>' +
        '<div class="explain">' + esc(a.explanation) + '</div></div></div>';
    }).join('') || '<div class="panel"><div class="panel-body" style="color:var(--n-mute)">No remediation actions returned for this finding.</div></div>';

    state.currentPolicy = { original: original, proposed: hardened, validation: validation, requiredInputs: requiredInputs };
    renderPolicyWorkbench();
    $('compliance').innerHTML = compliance.map(function (c) { return '<div><span>↳</span><span>' + esc(c) + '</span></div>'; }).join('') || '<div>No compliance mappings returned.</div>';
    $('queue-mini').innerHTML = queueHtml(5) || '<div class="empty-panel">Queue is empty.</div>';
  }

  function policyDiff(original, proposed) {
    var before = JSON.stringify(original || {}, null, 2).split('\n');
    var after = JSON.stringify(proposed || {}, null, 2).split('\n');
    var prefix = 0, suffix = 0;
    while (prefix < before.length && prefix < after.length && before[prefix] === after[prefix]) prefix++;
    while (suffix < before.length - prefix && suffix < after.length - prefix &&
      before[before.length - 1 - suffix] === after[after.length - 1 - suffix]) suffix++;
    var lines = before.slice(0, prefix).map(function (line) { return '  ' + line; });
    before.slice(prefix, before.length - suffix).forEach(function (line) { lines.push('- ' + line); });
    after.slice(prefix, after.length - suffix).forEach(function (line) { lines.push('+ ' + line); });
    before.slice(before.length - suffix).forEach(function (line) { lines.push('  ' + line); });
    return lines.join('\n');
  }

  function renderPolicyWorkbench() {
    var current = state.currentPolicy || { original: {}, proposed: {}, validation: {}, requiredInputs: [] };
    var view = state.policyView;
    Array.prototype.forEach.call(document.querySelectorAll('[data-policy-view]'), function (button) {
      button.setAttribute('aria-selected', button.getAttribute('data-policy-view') === view ? 'true' : 'false');
    });
    var text = view === 'original' ? JSON.stringify(current.original || {}, null, 2)
      : view === 'diff' ? policyDiff(current.original, current.proposed)
      : JSON.stringify(current.proposed || {}, null, 2);
    $('policy-code').textContent = text;
    $('policy-code').className = view === 'diff' ? 'diff-text' : '';
    state.currentPolicy.visibleText = text;
    var validation = current.validation || {};
    var ready = validation.export_ready;
    $('policy-caption').textContent = view === 'original' ? 'Exact source statement retained by the finding'
      : view === 'diff' ? 'Lines prefixed − are removed; lines prefixed + are proposed'
      : ready ? 'Structurally checked proposal; workflow access still needs review'
      : 'Proposal template; resolve required inputs before export';
    var checks = [
      ['Policy structure', validation.policy_structure || 'unknown', validation.policy_structure === 'passed'],
      ['Original conditions preserved', validation.conditions_preserved ? 'passed' : 'review', !!validation.conditions_preserved],
      ['Change present', validation.change_present ? 'passed' : 'review', !!validation.change_present],
      ['Modeled impact', validation.modeled_impact === 'not_run' ? 'not run' : validation.modeled_impact, false]
    ];
    $('validation-checks').innerHTML = checks.map(function (check) {
      return '<div class="validation-row"><span>' + esc(check[0]) + '</span><span class="tag ' + (check[2] ? 'check-pass' : 'check-review') + '">' + esc(check[1]) + '</span></div>';
    }).join('') + (current.requiredInputs || []).map(function (input) {
      return '<div class="validation-row"><span>Required input</span><span class="tag check-review">' + esc(input) + '</span></div>';
    }).join('') + '<div class="validation-note">' + esc(validation.note || 'No AWS change has been applied.') + '</div>';
    $('validation-status').textContent = ready ? 'Structurally checked' : current.proposed && Object.keys(current.proposed).length ? 'Review required' : 'No proposal';
    $('validation-status').className = 'tag ' + (ready ? 'check-pass' : 'check-review');
    $('validate-proposal').textContent = state.validationReviewed ? 'Checks reviewed' : 'Review checks';
  }

  function queueHtml(limit) {
    return state.data.queue.slice(0, limit || 99).map(function (q) {
      var color = q[1] === 'CRITICAL' ? 'var(--n-crit)' : q[1] === 'HIGH' ? 'var(--n-high)' : 'var(--n-med)';
      return '<div class="queue-row"><i class="dot" style="background:' + color + '"></i>' +
        '<span class="action" title="' + esc(q[0]) + '">' + esc(q[0]) + '</span><span class="hours">' + esc(q[2]) + 'h</span></div>';
    }).join('');
  }

  function renderVisualizer() {
    var paths = state.data.paths || [];
    if (!state.selectedPath || !paths.some(function (path) { return path.id === state.selectedPath; })) {
      state.selectedPath = paths.length ? paths[0].id : null;
      state.selectedEvidence = 0;
    }
    $('chain-count').textContent = paths.length + ' path' + (paths.length === 1 ? '' : 's');
    $('chains').innerHTML = paths.map(function (path) {
      var selected = path.id === state.selectedPath;
      return '<button class="path-list-row' + (selected ? ' selected' : '') + '" data-path-select="' + esc(path.id) + '">' +
        '<span class="path-list-top"><span>' + esc(path.technique) + '</span><span class="tag ' + (path.decision === 'candidate' ? 'check-review' : 'check-pass') + '">' + esc(path.decision || 'allowed') + '</span></span>' +
        '<span class="path-list-meta">' + esc(path.affected_identity) + ' · ' + esc((path.required_permissions || []).join(' + ')) + '</span></button>';
    }).join('') || '<div class="empty-panel">No candidate escalation paths in this analysis.</div>';

    var selectedPath = paths.filter(function (path) { return path.id === state.selectedPath; })[0];
    if (!selectedPath) {
      $('path-title').textContent = 'No path selected';
      $('path-subtitle').textContent = 'Run an analysis with reachable escalation techniques.';
      $('path-decision').textContent = 'No path';
      $('path-nodes').innerHTML = '<div class="empty-panel">Nothing to display.</div>';
      $('evidence-code').textContent = '';
      $('evidence-source').textContent = '';
      $('path-unknowns').innerHTML = '<div class="empty-panel">No path-specific limits.</div>';
    } else {
      var evidence = selectedPath.matched_permissions || [];
      if (state.selectedEvidence >= evidence.length) state.selectedEvidence = 0;
      var chosen = evidence[state.selectedEvidence] || {};
      $('path-title').textContent = selectedPath.description || selectedPath.technique;
      $('path-subtitle').textContent = selectedPath.affected_identity + ' · ' + (selectedPath.required_permissions || []).join(' + ');
      $('path-decision').textContent = selectedPath.decision === 'candidate' ? 'Conditional candidate' : 'Modeled allowed';
      $('path-decision').className = 'tag ' + (selectedPath.decision === 'candidate' ? 'check-review' : 'check-pass');
      var nodes = (selectedPath.path || []).map(function (node, index) {
        return '<button class="path-node" data-evidence-select="' + Math.min(index, Math.max(0, evidence.length - 1)) + '"><span>' + (index ? 'Reached identity' : 'Entry identity') + '</span><strong>' + esc(node) + '</strong></button>';
      });
      nodes.push('<button class="path-node action-node" data-evidence-select="0"><span>Required permission' + ((selectedPath.required_permissions || []).length === 1 ? '' : 's') + '</span><strong>' + esc((selectedPath.required_permissions || []).join(' + ')) + '</strong></button>');
      $('path-nodes').innerHTML = nodes.join('<span class="path-arrow">→</span>');
      var statement = chosen.source_statement || chosen.statement || chosen;
      $('evidence-code').textContent = JSON.stringify(statement && Object.keys(statement).length ? statement : { note: 'No source statement was retained for this legacy path.' }, null, 2);
      $('evidence-source').textContent = chosen.source_policy || chosen.relationship || ('Evidence ' + (state.selectedEvidence + 1));
      var unknowns = (selectedPath.unknowns || []).slice();
      if (!unknowns.length) unknowns.push('This is a modeled IAM decision; verify organization, boundary, session, and workload context before action.');
      var coverageWarnings = (state.data.coverage && state.data.coverage.warnings) || [];
      coverageWarnings.forEach(function (warning) { if (unknowns.indexOf(warning) < 0) unknowns.push(warning); });
      var finding = state.data.findings.filter(function (item) {
        return item.technique === selectedPath.technique && item.resource === selectedPath.affected_identity.split('::').slice(1).join('::');
      })[0];
      $('path-unknowns').innerHTML = unknowns.map(function (item) { return '<div class="limit-row"><span>!</span><span>' + esc(item) + '</span></div>'; }).join('') +
        (evidence.length > 1 ? '<div class="evidence-pager">' + evidence.map(function (item, index) {
          return '<button class="chip" data-evidence-select="' + index + '" aria-pressed="' + (index === state.selectedEvidence) + '">' + esc(item.evidence_type || 'evidence') + ' ' + (index + 1) + '</button>';
        }).join('') + '</div>' : '') +
        (finding ? '<button class="btn" data-path-remediate="' + esc(finding.id) + '">Review policy change</button>' : '');
    }

    $('tech-count').textContent = state.data.techniques.length + ' techniques';
    var max = Math.max.apply(null, state.data.techniques.map(function (t) { return t.count; }).concat([1]));
    $('heatmap').innerHTML = state.data.techniques.map(function (t) {
      var color = t.count >= max * 0.8 ? 'var(--n-crit)' : t.count >= max * 0.34 ? 'var(--n-high)' : 'var(--n-med)';
      return '<div class="tech"><div class="tech-row"><span class="tech-id">' + esc(t.id) + '</span>' +
        '<span class="tech-name">' + esc(t.name) + '</span><span class="tech-count">' + esc(t.count) + '</span></div>' +
        '<div class="bar"><div style="width:' + Math.round(t.count / max * 100) + '%;background:' + color + '"></div></div>' +
        '<span class="tactic">' + esc(t.tactic) + '</span></div>';
    }).join('');

    $('queue-total').textContent = totalHours() + 'h total';
    $('queue-full').innerHTML = queueHtml() || '<div class="empty-panel">Queue is empty.</div>';
  }

  function donut(items, total) {
    var R = 74, C = 2 * Math.PI * R, off = 0;
    var arcs = items.filter(function (i) { return i.value > 0; }).map(function (i) {
      var len = i.value / total * C;
      var s = '<circle cx="95" cy="95" r="' + R + '" fill="none" stroke="' + i.color + '" stroke-width="16" ' +
        'stroke-dasharray="' + (len - 2) + ' ' + (C - len + 2) + '" stroke-dashoffset="' + (-off) + '" transform="rotate(-90 95 95)"/>';
      off += len;
      return s;
    }).join('');
    return '<div style="display:flex;flex-direction:column;align-items:center;gap:14px">' +
      '<svg width="190" height="190" viewBox="0 0 190 190">' + arcs +
      '<text x="95" y="92" text-anchor="middle" font-size="26" font-family="Inter,sans-serif" font-weight="300" fill="currentColor">' + total + '</text>' +
      '<text x="95" y="110" text-anchor="middle" font-size="9" letter-spacing="2" font-family="JetBrains Mono,monospace" fill="currentColor" opacity="0.55">TOTAL</text></svg>' +
      '<div style="display:flex;gap:14px;flex-wrap:wrap;justify-content:center">' +
      items.map(function (i) {
        return '<span style="display:flex;align-items:center;gap:6px;font-size:11px;font-family:var(--mono);opacity:.75">' +
          '<i style="width:8px;height:8px;border-radius:2px;background:' + i.color + '"></i>' + esc(i.label) + ' ' + i.value + '</span>';
      }).join('') + '</div></div>';
  }

  function radar() {
    var cx = 110, cy = 105, R = 78, rs = state.data.risks.slice(0, 6);
    var pts = rs.map(function (r, i) {
      var a = i / rs.length * Math.PI * 2 - Math.PI / 2, rr = r.score / 100 * R;
      return { x: cx + Math.cos(a) * rr, y: cy + Math.sin(a) * rr, ax: cx + Math.cos(a) * R, ay: cy + Math.sin(a) * R,
        lx: cx + Math.cos(a) * (R + 20), ly: cy + Math.sin(a) * (R + 20) + 3,
        name: r.name.length > 13 ? r.name.slice(0, 12) + '…' : r.name };
    });
    return '<svg width="240" height="215" viewBox="0 0 240 215" style="color:currentColor">' +
      '<g opacity="0.25">' + [0.33, 0.66, 1].map(function (f) { return '<circle cx="' + cx + '" cy="' + cy + '" r="' + R * f + '" fill="none" stroke="currentColor"/>'; }).join('') + '</g>' +
      '<g opacity="0.2">' + pts.map(function (p) { return '<line x1="' + cx + '" y1="' + cy + '" x2="' + p.ax + '" y2="' + p.ay + '" stroke="currentColor"/>'; }).join('') + '</g>' +
      '<polygon points="' + pts.map(function (p) { return p.x + ',' + p.y; }).join(' ') + '" fill="currentColor" fill-opacity="0.14" stroke="currentColor" stroke-width="1.4"/>' +
      pts.map(function (p) { return '<circle cx="' + p.x + '" cy="' + p.y + '" r="2.6" fill="currentColor"/>'; }).join('') +
      pts.map(function (p) { return '<text x="' + p.lx + '" y="' + p.ly + '" text-anchor="middle" font-size="8.5" font-family="JetBrains Mono,monospace" fill="currentColor" opacity="0.6">' + esc(p.name) + '</text>'; }).join('') +
      '</svg>';
  }

  function renderCharts() {
    var dark = state.theme === 'dark';
    var c = dark ? { CRITICAL: '#d2686f', HIGH: '#cc8b4e', MEDIUM: '#bca85a', LOW: '#7fa189' } : { CRITICAL: '#a8434b', HIGH: '#91602c', MEDIUM: '#7d6c22', LOW: '#4a6b55' };

    $('chart-sev-meta').textContent = state.data.findings.length + ' findings';
    $('chart-severity').innerHTML = donut([
      { label: 'Critical', value: countBy('CRITICAL'), color: c.CRITICAL },
      { label: 'High', value: countBy('HIGH'), color: c.HIGH },
      { label: 'Medium', value: countBy('MEDIUM'), color: c.MEDIUM },
      { label: 'Low', value: countBy('LOW'), color: c.LOW }
    ], state.data.findings.length);

    $('chart-radar').innerHTML = radar();

    /* Count actions per priority — the card is "Actions by priority", so this
       must be a count, not a sum of hours. */
    var byPriority = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    state.data.queue.forEach(function (q) { byPriority[q[1]] = (byPriority[q[1]] || 0) + 1; });
    $('chart-pri-meta').textContent = state.data.queue.length + ' actions';
    $('chart-priority').innerHTML = donut([
      { label: 'Critical', value: byPriority.CRITICAL, color: c.CRITICAL },
      { label: 'High', value: byPriority.HIGH, color: c.HIGH },
      { label: 'Medium', value: byPriority.MEDIUM, color: c.MEDIUM },
      { label: 'Low', value: byPriority.LOW, color: c.LOW }
    ], state.data.queue.length || 1);
  }

  /* ---------------- 3D lifecycle ---------------- */

  function mountHero() {
    if (hero || state.view !== 'overview') return;
    hero = window.WinnowScenes.createHero($('hero-canvas'), { theme: state.theme });
  }
  function mountGraph() {
    if (graph || state.view !== 'graph') return;
    graph = window.WinnowScenes.createGraph($('graph-canvas'), {
      theme: state.theme,
      findings: state.data.findings,
      groups: state.groups,
      techniques: state.data.techniques,
      showIdentities: state.showIdent,
      showMitre: state.showMitre,
      autoOrbit: state.spin,
      onSelect: function (id) { state.selId = id; renderInspector(); renderGraphDetail(true); }
    });
  }
  function remountGraph() { if (graph) { graph.dispose(); graph = null; } mountGraph(); }

  /* Idempotent guard: if a visible host has lost its canvas (theme flip, view
     change, context loss) rebuild it. Cheap, and keeps the 3D from ever
     silently disappearing. */
  function ensureScenes() {
    if (!window.THREE) return;
    var heroHost = $('hero-canvas');
    if (state.view === 'overview' && heroHost && !heroHost.children.length) { hero = null; mountHero(); }
    var graphHost = $('graph-canvas');
    if (state.view === 'graph' && graphHost && !graphHost.children.length) { graph = null; mountGraph(); }
  }
  setInterval(ensureScenes, 500);
  function remountAll() {
    if (hero) { hero.dispose(); hero = null; }
    if (graph) { graph.dispose(); graph = null; }
    mountHero(); mountGraph();
  }

  /* ---------------- command palette ---------------- */

  function paletteItems() {
    var items = NAV.map(function (n) { return { kind: 'view', label: n[1], meta: '', view: n[0] }; });
    state.data.findings.forEach(function (f) { items.push({ kind: 'finding', label: f.title, meta: f.id, view: 'remediation', select: f.id }); });
    state.data.techniques.forEach(function (t) { items.push({ kind: 'technique', label: t.id + ' · ' + t.name, meta: t.count + '×', view: 'visualizer' }); });
    return items;
  }

  function renderPalette() {
    var q = $('palette-input').value.trim().toLowerCase();
    var items = paletteItems().filter(function (i) {
      return !q || (i.label + ' ' + i.meta + ' ' + i.kind).toLowerCase().indexOf(q) >= 0;
    }).slice(0, 40);
    state._paletteItems = items;
    if (state.paletteIndex >= items.length) state.paletteIndex = 0;
    $('palette-results').innerHTML = items.map(function (i, idx) {
      return '<button class="palette-item' + (idx === state.paletteIndex ? ' sel' : '') + '" data-pi="' + idx + '">' +
        '<span class="kind">' + esc(i.kind) + '</span><span class="label">' + esc(i.label) + '</span><span class="meta">' + esc(i.meta) + '</span></button>';
    }).join('') || '<div style="padding:14px;color:var(--n-mute);font-size:12px">Nothing matches.</div>';
  }

  function openPalette() {
    state.paletteOpen = true;
    state.paletteIndex = 0;
    $('palette-backdrop').hidden = false;
    $('palette-input').value = '';
    renderPalette();
    $('palette-input').focus();
  }
  function closePalette() { state.paletteOpen = false; $('palette-backdrop').hidden = true; }
  function runPalette(i) {
    var item = (state._paletteItems || [])[i];
    if (!item) return;
    if (item.select) { state.selId = item.select; renderInspector(); renderRemediation(); }
    closePalette();
    goTo(item.view);
  }

  /* ---------------- navigation ---------------- */

  function goTo(view) {
    if (state.view === 'overview' && view !== 'overview' && hero) { hero.dispose(); hero = null; }
    if (state.view === 'graph' && view !== 'graph' && graph) { graph.dispose(); graph = null; }
    state.view = view;
    Array.prototype.forEach.call(document.querySelectorAll('.view'), function (el) {
      el.classList.toggle('active', el.getAttribute('data-view') === view);
    });
    renderNav();
    renderTopbar();
    if (view === 'overview') { renderOverview(); mountHero(); }
    if (view === 'graph') { renderInspector(); renderGraphDetail(); mountGraph(); }
    if (view === 'findings') renderFindings();
    if (view === 'remediation') renderRemediation();
    if (view === 'visualizer') renderVisualizer();
    if (view === 'charts') renderCharts();
    try { history.replaceState(null, '', '#' + view); } catch (e) {}
  }

  function renderAll() {
    computeGroups();
    if (!state.selId && state.data.findings.length) state.selId = state.data.findings[0].id;
    renderNav(); renderTopbar();
    renderOverview(); renderInspector(); renderFindings();
    renderRemediation(); renderVisualizer(); renderCharts();
    renderGraphDetail();
  }

  function applyTheme() {
    document.documentElement.setAttribute('data-theme', state.theme);
    localStorage.setItem('winnow-theme', state.theme);
    var dark = state.theme === 'dark';
    $('theme-toggle').innerHTML = dark
      ? icon(['M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z'], 13)
      : '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"><circle cx="12" cy="12" r="4.5"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.5 1.5M17.5 17.5L19 19M19 5l-1.5 1.5M6.5 17.5L5 19"/></svg>';
    renderCharts();
    remountAll();
  }

  /* ---------------- analysis ---------------- */

  function beginAnalysis(label) {
    state.requestSerial += 1;
    state.analysisStatus = 'loading';
    state.analysisError = '';
    $('status-text').textContent = label || 'Analyzing…';
    renderSourcePanel();
    renderResultState();
    renderAnalysisContext();
    return state.requestSerial;
  }

  function applyResult(payload, requestId) {
    if (requestId && requestId !== state.requestSerial) return;
    state.data = normalise(payload);
    state.selId = null;
    state.selectedPath = null;
    state.selectedEvidence = 0;
    state.analysisError = '';
    state.analysisStatus = state.data.coverage && !state.data.coverage.complete ? 'partial'
      : state.data.findings.length ? 'complete' : 'empty';
    state.scanTime = new Date();
    var d = state.data;
    var engine = d.aiCount ? 'graph + rule + AI' : 'graph + rule engine';
    var prefix = d.source === 'live' && d.accountId ? ('AWS ' + d.accountId + ' · ') : (engine + ' · ');
    $('status-text').textContent = prefix + d.findings.length + ' findings · ' + d.escalationPaths + ' escalation paths';
    renderAll();
    remountGraph();
  }

  function fallbackOffline(msg) {
    state.data = normalise(null);
    state.selId = null;
    state.analysisStatus = 'partial';
    state.analysisError = '';
    state.scanTime = new Date();
    $('status-text').textContent = msg || 'Demo dataset · offline';
    renderAll();
    remountGraph();
  }

  function failAnalysis(message, source, sourceName, requestId) {
    if (requestId && requestId !== state.requestSerial) return;
    state.data = normalise({
      vulnerabilities: [], remediations: [],
      visualization: { permission_graph: { nodes: [], links: [], escalation_paths: [] } },
      summary: {
        source: source || 'upload', source_name: sourceName || null,
        identity_count: 0, policy_count: 0, escalation_paths: 0,
        coverage: { complete: false, warnings: [message] }, ai_status: 'disabled'
      }
    });
    state.selId = null;
    state.analysisStatus = 'error';
    state.analysisError = message;
    state.scanTime = new Date();
    $('status-text').textContent = 'Analysis failed · ' + message;
    renderAll();
    remountGraph();
  }

  function postJSON(path, body) {
    return fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body)
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) {
        if (!r.ok || j.error) { var e = new Error(j.error || ('http ' + r.status)); e.handled = true; throw e; }
        return j;
      });
    });
  }

  /* Load the built-in demo: ask the backend for the config, then analyze it —
     the backend is the single source of truth for the demo scenario. */
  function analyze() {
    state.sourceTab = 'demo';
    var requestId = beginAnalysis('Analyzing demo…');
    postJSON('/api/generate-dummy')
      .then(function (j) { return postJSON(API, { iam_config: j.iam_config, config_type: 'terraform', source: 'demo', source_name: 'Bundled IAM scenario' }); })
      .then(function (payload) { applyResult(payload, requestId); })
      .catch(function () { if (requestId === state.requestSerial) fallbackOffline('Demo dataset · backend offline'); });
  }

  function scanAccount() {
    state.sourceTab = 'live';
    var requestId = beginAnalysis('Scanning AWS account…');
    var btn = document.getElementById('scan-aws');
    if (btn) btn.disabled = true;
    postJSON('/api/scan-account')
      .then(function (payload) { applyResult(payload, requestId); })
      .catch(function (err) {
        failAnalysis(err && err.message ? err.message : 'AWS scan failed', 'live', 'AWS account', requestId);
      })
      .then(function () { if (btn) btn.disabled = false; });
  }

  function analyzeUpload() {
    var text = $('config-input').value.trim();
    if (!text) {
      state.analysisError = 'Choose a JSON file or paste a JSON document.';
      renderSourcePanel();
      return;
    }
    var parsed;
    try { parsed = JSON.parse(text); }
    catch (error) {
      state.analysisError = 'The input is not valid JSON: ' + error.message;
      renderSourcePanel();
      return;
    }
    state.sourceTab = 'upload';
    var name = state.uploadedFileName || 'Pasted JSON';
    var requestId = beginAnalysis('Analyzing ' + name + '…');
    postJSON(API, { iam_config: parsed, config_type: 'terraform', source: 'upload', source_name: name })
      .then(function (payload) { applyResult(payload, requestId); })
      .catch(function (error) { failAnalysis(error.message || 'Analysis failed', 'upload', name, requestId); });
  }

  /* ---------------- events ---------------- */

  document.addEventListener('click', function (e) {
    var sourceTab = e.target.closest('[data-source-tab]');
    if (sourceTab) { state.sourceTab = sourceTab.getAttribute('data-source-tab'); state.analysisError = ''; renderSourcePanel(); return; }

    var pathSelect = e.target.closest('[data-path-select]');
    if (pathSelect) { state.selectedPath = pathSelect.getAttribute('data-path-select'); state.selectedEvidence = 0; renderVisualizer(); return; }

    var evidenceSelect = e.target.closest('[data-evidence-select]');
    if (evidenceSelect) { state.selectedEvidence = +evidenceSelect.getAttribute('data-evidence-select'); renderVisualizer(); return; }

    var policyView = e.target.closest('[data-policy-view]');
    if (policyView) { state.policyView = policyView.getAttribute('data-policy-view'); renderPolicyWorkbench(); return; }

    var pathRemediate = e.target.closest('[data-path-remediate]');
    if (pathRemediate) { state.selId = pathRemediate.getAttribute('data-path-remediate'); state.policyView = 'diff'; renderRemediation(); goTo('remediation'); return; }

    var pi = e.target.closest('[data-pi]');
    if (pi) { runPalette(+pi.getAttribute('data-pi')); return; }

    var sevBtn = e.target.closest('[data-sev]');
    if (sevBtn) { state.sev = sevBtn.getAttribute('data-sev'); renderFindings(); return; }

    var gdSevBtn = e.target.closest('[data-gd-sev]');
    if (gdSevBtn) { state.gdSev = gdSevBtn.getAttribute('data-gd-sev'); renderGraphDetail(); return; }

    var selEl = e.target.closest('[data-select]');
    if (selEl) {
      state.selId = selEl.getAttribute('data-select');
      renderInspector();
      renderRemediation();
      renderGraphDetail();
    }

    var nav = e.target.closest('[data-goto]');
    if (nav) { goTo(nav.getAttribute('data-goto')); return; }

    if (e.target.closest('#palette-open')) { openPalette(); return; }
    if (e.target.id === 'palette-backdrop') { closePalette(); return; }
    if (e.target.closest('#theme-toggle')) { state.theme = state.theme === 'dark' ? 'light' : 'dark'; applyTheme(); return; }
    if (e.target.closest('#reanalyze') || e.target.closest('[data-load-demo]')) { analyze(); return; }
    if (e.target.closest('#scan-aws') || e.target.closest('[data-scan-aws]')) { scanAccount(); return; }
    if (e.target.closest('#analyze-upload')) { analyzeUpload(); return; }
    if (e.target.closest('#reset-cam')) { if (graph) graph.resetCamera(); return; }
    if (e.target.closest('#copy-policy')) {
      var copyButton = e.target.closest('#copy-policy');
      var copyText = state.currentPolicy && state.currentPolicy.visibleText || '';
      if (!copyText) return;
      navigator.clipboard.writeText(copyText).then(function () {
        copyButton.textContent = 'Copied';
        setTimeout(function () { copyButton.textContent = 'Copy visible policy'; }, 1400);
      }).catch(function () { copyButton.textContent = 'Copy failed'; });
      return;
    }
    if (e.target.closest('#validate-proposal')) {
      state.validationReviewed = true;
      renderPolicyWorkbench();
      return;
    }
    if (e.target.closest('#t-ident')) { state.showIdent = !state.showIdent; $('t-ident').setAttribute('aria-pressed', state.showIdent); $('t-ident').textContent = state.showIdent ? 'Identities on' : 'Identities off'; remountGraph(); return; }
    if (e.target.closest('#t-mitre')) { state.showMitre = !state.showMitre; $('t-mitre').setAttribute('aria-pressed', state.showMitre); $('t-mitre').textContent = state.showMitre ? 'MITRE on' : 'MITRE off'; remountGraph(); return; }
    if (e.target.closest('#t-spin')) { state.spin = !state.spin; $('t-spin').setAttribute('aria-pressed', state.spin); $('t-spin').textContent = state.spin ? 'Auto-orbit' : 'Static'; if (graph) graph.setAutoOrbit(state.spin); return; }
  });

  $('finding-search').addEventListener('input', function (e) { state.query = e.target.value; renderFindings(); });
  $('gd-search').addEventListener('input', function (e) { state.gdQuery = e.target.value; renderGraphDetail(); });
  $('palette-input').addEventListener('input', function () { state.paletteIndex = 0; renderPalette(); });
  $('config-file').addEventListener('change', function (event) {
    var file = event.target.files && event.target.files[0];
    if (!file) return;
    state.uploadedFileName = file.name;
    $('upload-detail').textContent = file.name + ' · ' + Math.max(1, Math.round(file.size / 1024)) + ' KB';
    var reader = new FileReader();
    reader.onload = function () { $('config-input').value = String(reader.result || ''); state.analysisError = ''; renderSourcePanel(); };
    reader.onerror = function () { state.analysisError = 'The selected file could not be read.'; renderSourcePanel(); };
    reader.readAsText(file);
  });

  window.addEventListener('keydown', function (e) {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); openPalette(); return; }
    if (!state.paletteOpen) return;
    if (e.key === 'Escape') { closePalette(); return; }
    if (e.key === 'ArrowDown') { e.preventDefault(); state.paletteIndex = Math.min(state.paletteIndex + 1, (state._paletteItems || []).length - 1); renderPalette(); }
    if (e.key === 'ArrowUp') { e.preventDefault(); state.paletteIndex = Math.max(0, state.paletteIndex - 1); renderPalette(); }
    if (e.key === 'Enter') { e.preventDefault(); runPalette(state.paletteIndex); }
  });

  /* ---------------- boot ---------------- */

  /* Reload lands at the top of the view, not wherever the page was scrolled.
     The app drives navigation with replaceState (no real back/forward stack),
     so nothing needs the browser's saved scroll position. */
  try { history.scrollRestoration = 'manual'; } catch (e) {}

  applyTheme();
  renderAll();
  /* Default the hash BEFORE using it: on a plain visit location.hash is '',
     and the old one-liner tested the defaulted value but passed the raw one,
     so goTo('') matched no section and the whole app booted blank. */
  var initialView = (location.hash || '').slice(1);
  goTo(initialView in TITLES ? initialView : 'overview');
  window.scrollTo(0, 0);
  analyze();
})();
