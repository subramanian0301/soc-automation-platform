const fs = require('fs');
const path = require('path');
const jwt = require('../backend/node_modules/jsonwebtoken');

const API_BASE = 'http://localhost:4000/api/v1';

async function logStep(title) {
  console.log(`\n======================================================`);
  console.log(`▶ ${title}`);
  console.log(`======================================================`);
}

async function request(url, options = {}) {
  const res = await fetch(url, options);
  let data = null;
  const contentType = res.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    data = await res.json().catch(() => null);
  } else if (contentType.includes('application/pdf')) {
    const arrayBuffer = await res.arrayBuffer();
    data = Buffer.from(arrayBuffer);
  } else {
    data = await res.text();
  }
  return { status: res.status, headers: res.headers, data };
}

async function uploadFile(token, filename, content, mimeType = 'application/json') {
  const formData = new FormData();
  const blob = new Blob([content], { type: mimeType });
  formData.append('file', blob, filename);

  const res = await fetch(`${API_BASE}/analyses/upload`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
    body: formData,
  });
  const data = await res.json().catch(() => ({}));
  return { status: res.status, data };
}

async function main() {
  console.log('STARTING FINAL END-TO-END MULTI-USER SECURITY & SYSTEM VERIFICATION');
  console.log(`Target Backend: ${API_BASE}`);
  console.log(`Timestamp: ${new Date().toISOString()}`);

  const testResults = [];
  function record(name, passed, details) {
    testResults.push({ name, passed, details });
    console.log(`[${passed ? 'PASS' : 'FAIL'}] ${name}: ${details}`);
    if (!passed) throw new Error(`Assertion failed: ${name} - ${details}`);
  }

  // --------------------------------------------------------------------------
  // STEP 1: Log in as Analyst Alpha & Upload Analysis
  // --------------------------------------------------------------------------
  await logStep('STEP 1: Log in as Analyst Alpha and upload a valid security-analysis file');
  const alphaLogin = await request(`${API_BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'analyst_alpha' }),
  });
  record('Alpha Login', alphaLogin.status === 201, `Status: ${alphaLogin.status}, User: ${alphaLogin.data.user.username}`);
  const tokenAlpha = alphaLogin.data.access_token;

  const alphaPayload = JSON.stringify({
    system_host: 'ALPHA-CORP-WORKSTATION-01',
    logged_user: 'jsmith_finance',
    os_name: 'Windows 11 Enterprise 23H2',
    risk_score: 82,
    severity_level: 'HIGH',
    suggested_action: 'Isolate Host and Reset Credentials',
    yara_matches: [
      { rule_name: 'Alpha_Trojan_Emotet_Variant', description: 'Matched Emotet payload pattern in memory dump' }
    ],
    iocs: [
      { type: 'IP', value: '185.220.101.5', category: 'C2 Infrastructure', confidence: 95 },
      { type: 'DOMAIN', value: 'cdn-updates-crypto.top', category: 'Malicious Domain', confidence: 90 }
    ],
    mitre_techniques: [
      { technique_id: 'T1059.001', technique_name: 'PowerShell', tactic: 'Execution' },
      { technique_id: 'T1071.001', technique_name: 'Web Protocols', tactic: 'Command and Control' }
    ],
    file_metadata: {
      file_name: 'invoice_october.pdf.exe',
      file_size_bytes: 492048,
      file_type: 'PE32 Executable'
    }
  });

  const alphaUpload = await uploadFile(tokenAlpha, 'alpha_telemetry.json', alphaPayload);
  record('Alpha Upload', alphaUpload.status === 201, `Analysis ID: ${alphaUpload.data.analysisId}, Host: ${alphaUpload.data.hostname}`);
  const alphaId = alphaUpload.data.analysisId;

  // --------------------------------------------------------------------------
  // STEP 2: Confirm Analysis Saved & Visible to Alpha
  // --------------------------------------------------------------------------
  await logStep('STEP 2: Confirm analysis is saved and visible to Analyst Alpha');
  const alphaGet = await request(`${API_BASE}/analyses/${alphaId}`, {
    headers: { Authorization: `Bearer ${tokenAlpha}` },
  });
  record('Alpha Read Own Analysis', alphaGet.status === 200, `Hostname: ${alphaGet.data.hostname}, Risk: ${alphaGet.data.riskScore}`);

  const alphaList = await request(`${API_BASE}/analyses`, {
    headers: { Authorization: `Bearer ${tokenAlpha}` },
  });
  const alphaHasId = alphaList.data.some(a => a.analysisId === alphaId);
  record('Alpha List View Contains Analysis', alphaHasId, `Total visible analyses for Alpha: ${alphaList.data.length}`);

  // --------------------------------------------------------------------------
  // STEP 3: Log in as Analyst Beta & Verify IDOR Protection on Alpha's Analysis
  // --------------------------------------------------------------------------
  await logStep('STEP 3: Log in as Analyst Beta and verify Beta cannot view, modify, export, or trigger SOAR on Alpha');
  const betaLogin = await request(`${API_BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'analyst_beta' }),
  });
  record('Beta Login', betaLogin.status === 201, `Status: ${betaLogin.status}, User: ${betaLogin.data.user.username}`);
  const tokenBeta = betaLogin.data.access_token;

  // 3a. Beta cannot view Alpha in analysis list
  const betaList = await request(`${API_BASE}/analyses`, {
    headers: { Authorization: `Bearer ${tokenBeta}` },
  });
  const betaSeesAlpha = betaList.data.some(a => a.analysisId === alphaId);
  record('Beta List Isolation', !betaSeesAlpha, `Beta cannot see Alpha's analysis in GET /analyses`);

  // 3b. Beta cannot view Alpha's analysis details (IDOR read)
  const betaRead = await request(`${API_BASE}/analyses/${alphaId}`, {
    headers: { Authorization: `Bearer ${tokenBeta}` },
  });
  record('Beta IDOR Read Blocked', betaRead.status === 403, `Status: ${betaRead.status} (Expected: 403 Forbidden)`);

  // 3c. Beta cannot query any sub-resource of Alpha
  const subResources = [
    'siem', 'iocs', 'threat-intel', 'mitre', 'behavior', 'sandbox',
    'incidents', 'cases', 'assets', 'endpoints', 'vulnerabilities', 'soar'
  ];
  for (const sub of subResources) {
    const subRes = await request(`${API_BASE}/analyses/${alphaId}/${sub}`, {
      headers: { Authorization: `Bearer ${tokenBeta}` },
    });
    record(`Beta IDOR Sub-resource /${sub} Blocked`, subRes.status === 403, `Status: ${subRes.status}`);
  }

  // 3d. Beta cannot mutate Alpha's analysis
  const betaIncident = await request(`${API_BASE}/analyses/${alphaId}/incidents`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${tokenBeta}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ title: 'Unauthorized Incident Injection', reason: 'Testing IDOR' }),
  });
  record('Beta IDOR Create Incident Blocked', betaIncident.status === 403, `Status: ${betaIncident.status}`);

  const betaCase = await request(`${API_BASE}/analyses/${alphaId}/cases`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${tokenBeta}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ title: 'Unauthorized Case Injection' }),
  });
  record('Beta IDOR Create Case Blocked', betaCase.status === 403, `Status: ${betaCase.status}`);

  const betaAsset = await request(`${API_BASE}/analyses/${alphaId}/assets`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${tokenBeta}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ assetName: 'Unauthorized Asset Injection' }),
  });
  record('Beta IDOR Create Asset Blocked', betaAsset.status === 403, `Status: ${betaAsset.status}`);

  const betaEndpoint = await request(`${API_BASE}/analyses/${alphaId}/endpoints`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${tokenBeta}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ hostname: 'UNAUTHORIZED-ENDPOINT' }),
  });
  record('Beta IDOR Create Endpoint Blocked', betaEndpoint.status === 403, `Status: ${betaEndpoint.status}`);

  const betaVuln = await request(`${API_BASE}/analyses/${alphaId}/vulnerabilities`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${tokenBeta}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ title: 'Fabricated Vulnerability', cveId: 'CVE-2026-0000' }),
  });
  record('Beta IDOR Create Vulnerability Blocked', betaVuln.status === 403, `Status: ${betaVuln.status}`);

  // 3e. Beta cannot export reports for Alpha
  const betaPdfExport = await request(`${API_BASE}/analyses/${alphaId}/reports/analysis-summary/export?format=pdf`, {
    headers: { Authorization: `Bearer ${tokenBeta}` },
  });
  record('Beta IDOR PDF Export Blocked', betaPdfExport.status === 403, `Status: ${betaPdfExport.status}`);

  const betaCsvExport = await request(`${API_BASE}/analyses/${alphaId}/reports/vulnerabilities/export?format=csv`, {
    headers: { Authorization: `Bearer ${tokenBeta}` },
  });
  record('Beta IDOR CSV Export Blocked', betaCsvExport.status === 403, `Status: ${betaCsvExport.status}`);

  // 3f. Beta cannot trigger SOAR actions on Alpha
  const betaSoar = await request(`${API_BASE}/analyses/${alphaId}/soar`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${tokenBeta}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ actionName: 'Isolate Host', target: 'ALPHA-CORP-WORKSTATION-01' }),
  });
  record('Beta IDOR SOAR Trigger Blocked', betaSoar.status === 403, `Status: ${betaSoar.status}`);

  // --------------------------------------------------------------------------
  // STEP 4: Administrator Permitted Access Verification
  // --------------------------------------------------------------------------
  await logStep('STEP 4: Verify Administrator permitted access override');
  const adminLogin = await request(`${API_BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'soc_admin' }),
  });
  record('Admin Login', adminLogin.status === 201, `Status: ${adminLogin.status}, Role: ${adminLogin.data.user.role}`);
  const tokenAdmin = adminLogin.data.access_token;

  // Upload an analysis as Beta to test multi-owner visibility
  const betaPayload = JSON.stringify({
    system_host: 'BETA-SERVER-CLUSTER-09',
    logged_user: 'admin_backup',
    risk_score: 30,
    severity_level: 'LOW',
  });
  const betaUpload = await uploadFile(tokenBeta, 'beta_telemetry.json', betaPayload);
  const betaId = betaUpload.data.analysisId;
  record('Beta Upload Own Analysis', betaUpload.status === 201, `Beta Analysis ID: ${betaId}`);

  // Admin reads Alpha analysis
  const adminReadAlpha = await request(`${API_BASE}/analyses/${alphaId}`, {
    headers: { Authorization: `Bearer ${tokenAdmin}` },
  });
  record('Admin Read Alpha Analysis Override', adminReadAlpha.status === 200, `Status: ${adminReadAlpha.status}, Host: ${adminReadAlpha.data.hostname}`);

  // Admin reads Beta analysis
  const adminReadBeta = await request(`${API_BASE}/analyses/${betaId}`, {
    headers: { Authorization: `Bearer ${tokenAdmin}` },
  });
  record('Admin Read Beta Analysis Override', adminReadBeta.status === 200, `Status: ${adminReadBeta.status}, Host: ${adminReadBeta.data.hostname}`);

  // Admin exports Alpha report
  const adminPdfAlpha = await request(`${API_BASE}/analyses/${alphaId}/reports/analysis-summary/export?format=pdf`, {
    headers: { Authorization: `Bearer ${tokenAdmin}` },
  });
  record('Admin Export Alpha Report Override', adminPdfAlpha.status === 200, `Status: ${adminPdfAlpha.status}, Size: ${adminPdfAlpha.data.length} bytes`);

  // Admin list view contains both Alpha and Beta
  const adminList = await request(`${API_BASE}/analyses`, {
    headers: { Authorization: `Bearer ${tokenAdmin}` },
  });
  const adminHasAlpha = adminList.data.some(a => a.analysisId === alphaId);
  const adminHasBeta = adminList.data.some(a => a.analysisId === betaId);
  record('Admin Global List View', adminHasAlpha && adminHasBeta, `Contains Alpha: ${adminHasAlpha}, Contains Beta: ${adminHasBeta}, Total: ${adminList.data.length}`);

  // --------------------------------------------------------------------------
  // STEP 5: Test All Modules for Owner (Alpha)
  // --------------------------------------------------------------------------
  await logStep('STEP 5: Test Dashboard, SIEM, IOCs, Threat Intel, MITRE, Behavior, Sandbox, Incidents, Cases, Assets, Endpoints, Vulnerabilities, Reports, and Analytics');

  // Dashboard
  const dashRes = await request(`${API_BASE}/analyses/${alphaId}`, {
    headers: { Authorization: `Bearer ${tokenAlpha}` },
  });
  record('Dashboard Overview', dashRes.status === 200 && dashRes.data.riskScore === 82, `Risk: ${dashRes.data.riskScore}, Threat: ${dashRes.data.threatLevel}`);

  // SIEM
  const siemRes = await request(`${API_BASE}/analyses/${alphaId}/siem`, {
    headers: { Authorization: `Bearer ${tokenAlpha}` },
  });
  record('SIEM Endpoint', siemRes.status === 200, `Total SIEM Events: ${siemRes.data.totalCount}`);

  // IOCs
  const iocsRes = await request(`${API_BASE}/analyses/${alphaId}/iocs`, {
    headers: { Authorization: `Bearer ${tokenAlpha}` },
  });
  record('IOC Search Endpoint', iocsRes.status === 200 && iocsRes.data.totalCount >= 2, `Total IOCs: ${iocsRes.data.totalCount}`);

  // Threat Intel
  const threatRes = await request(`${API_BASE}/analyses/${alphaId}/threat-intel`, {
    headers: { Authorization: `Bearer ${tokenAlpha}` },
  });
  record('Threat Intel Endpoint', threatRes.status === 200 && threatRes.data.yaraResults.length >= 1, `YARA rules: ${threatRes.data.yaraResults.map(y => y.ruleName).join(', ')}`);

  // MITRE ATT&CK
  const mitreRes = await request(`${API_BASE}/analyses/${alphaId}/mitre`, {
    headers: { Authorization: `Bearer ${tokenAlpha}` },
  });
  record('MITRE ATT&CK Endpoint', mitreRes.status === 200 && mitreRes.data.totalCount >= 2, `Techniques: ${mitreRes.data.techniques.map(t => t.techniqueId).join(', ')}`);

  // Behavior
  const behavRes = await request(`${API_BASE}/analyses/${alphaId}/behavior`, {
    headers: { Authorization: `Bearer ${tokenAlpha}` },
  });
  record('Behavior Endpoint', behavRes.status === 200, `Total Behaviors: ${behavRes.data.totalCount}`);

  // Sandbox
  const sandRes = await request(`${API_BASE}/analyses/${alphaId}/sandbox`, {
    headers: { Authorization: `Bearer ${tokenAlpha}` },
  });
  record('Sandbox Endpoint', sandRes.status === 200, `Total Sandbox Executions: ${sandRes.data.totalCount}`);

  // Incidents: Create & Query
  const createInc = await request(`${API_BASE}/analyses/${alphaId}/incidents`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${tokenAlpha}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ title: 'Critical C2 Beaconing Detected', reason: 'Emotet IOC matched', severity: 'HIGH' }),
  });
  record('Incident Creation (Alpha)', createInc.status === 201, `Incident ID: ${createInc.data.id}`);

  const incRes = await request(`${API_BASE}/analyses/${alphaId}/incidents`, {
    headers: { Authorization: `Bearer ${tokenAlpha}` },
  });
  record('Incidents Query (Alpha)', incRes.status === 200 && incRes.data.totalCount >= 1, `Count: ${incRes.data.totalCount}`);

  // Cases: Create & Query
  const createCase = await request(`${API_BASE}/analyses/${alphaId}/cases`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${tokenAlpha}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ title: 'Investigate Finance Workstation Emotet Infection', priority: 'HIGH' }),
  });
  record('Case Creation (Alpha)', createCase.status === 201, `Case Number: ${createCase.data.caseNumber}`);

  const casesRes = await request(`${API_BASE}/analyses/${alphaId}/cases`, {
    headers: { Authorization: `Bearer ${tokenAlpha}` },
  });
  record('Cases Query (Alpha)', casesRes.status === 200 && casesRes.data.totalCount >= 1, `Count: ${casesRes.data.totalCount}`);

  // Assets: Create & Query
  const createAsset = await request(`${API_BASE}/analyses/${alphaId}/assets`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${tokenAlpha}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ assetName: 'ALPHA-CORP-WORKSTATION-01', assetType: 'WORKSTATION', criticality: 'HIGH' }),
  });
  record('Asset Creation (Alpha)', createAsset.status === 201, `Asset: ${createAsset.data.assetName}`);

  const assetRes = await request(`${API_BASE}/analyses/${alphaId}/assets`, {
    headers: { Authorization: `Bearer ${tokenAlpha}` },
  });
  record('Assets Query (Alpha)', assetRes.status === 200 && assetRes.data.totalCount >= 1, `Count: ${assetRes.data.totalCount}`);

  // Endpoints: Create & Query
  const createEp = await request(`${API_BASE}/analyses/${alphaId}/endpoints`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${tokenAlpha}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ hostname: 'ALPHA-CORP-WORKSTATION-01', ipAddress: '10.20.1.45', osType: 'Windows 11' }),
  });
  record('Endpoint Creation (Alpha)', createEp.status === 201, `Endpoint Host: ${createEp.data.hostname}`);

  const epRes = await request(`${API_BASE}/analyses/${alphaId}/endpoints`, {
    headers: { Authorization: `Bearer ${tokenAlpha}` },
  });
  record('Endpoints Query (Alpha)', epRes.status === 200 && epRes.data.totalCount >= 1, `Count: ${epRes.data.totalCount}`);

  // Vulnerabilities: Create & Query
  const createVuln = await request(`${API_BASE}/analyses/${alphaId}/vulnerabilities`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${tokenAlpha}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ cveId: 'CVE-2024-38021', title: 'Windows MSHTML Platform RCE', severity: 'CRITICAL', cvssScore: 8.8 }),
  });
  record('Vulnerability Creation (Alpha)', createVuln.status === 201, `CVE: ${createVuln.data.cveId}`);

  const vulnRes = await request(`${API_BASE}/analyses/${alphaId}/vulnerabilities`, {
    headers: { Authorization: `Bearer ${tokenAlpha}` },
  });
  record('Vulnerabilities Query (Alpha)', vulnRes.status === 200 && vulnRes.data.totalCount >= 1, `Count: ${vulnRes.data.totalCount}`);

  // Reports (Structured JSON)
  const reportTypes = ['analysis-summary', 'security-findings', 'incidents-cases', 'assets-endpoints', 'vulnerabilities', 'soar-activity'];
  for (const rt of reportTypes) {
    const repRes = await request(`${API_BASE}/analyses/${alphaId}/reports/${rt}`, {
      headers: { Authorization: `Bearer ${tokenAlpha}` },
    });
    record(`Report JSON /${rt}`, repRes.status === 200, `Type: "${repRes.data.reportType}", Analysis: ${repRes.data.analysisId}`);
  }

  // Enterprise Analytics
  const alphaAnalytics = await request(`${API_BASE}/analytics/enterprise`, {
    headers: { Authorization: `Bearer ${tokenAlpha}` },
  });
  record('Enterprise Analytics (Alpha)', alphaAnalytics.status === 200 && !alphaAnalytics.data.isGlobalAdmin, `Scope: ${alphaAnalytics.data.scope}, User Analyses: ${alphaAnalytics.data.totalAnalyses}`);

  const adminAnalytics = await request(`${API_BASE}/analytics/enterprise`, {
    headers: { Authorization: `Bearer ${tokenAdmin}` },
  });
  record('Enterprise Analytics (Admin)', adminAnalytics.status === 200 && adminAnalytics.data.isGlobalAdmin, `Scope: ${adminAnalytics.data.scope}, Global Analyses: ${adminAnalytics.data.totalAnalyses}`);

  // --------------------------------------------------------------------------
  // STEP 6: PDF & CSV Downloads with Authorization Bearer Header
  // --------------------------------------------------------------------------
  await logStep('STEP 6: Test PDF and CSV downloads using the Authorization Bearer header');

  const pdfDownload = await request(`${API_BASE}/analyses/${alphaId}/reports/analysis-summary/export?format=pdf`, {
    headers: { Authorization: `Bearer ${tokenAlpha}` },
  });
  const isPdfBuffer = Buffer.isBuffer(pdfDownload.data);
  const pdfMagic = isPdfBuffer ? pdfDownload.data.subarray(0, 5).toString('utf-8') : '';
  record('PDF Export Header Magic & Buffer', pdfDownload.status === 200 && pdfMagic.startsWith('%PDF-'), `Magic: "${pdfMagic}", Size: ${pdfDownload.data.length} bytes, Type: ${pdfDownload.headers.get('content-type')}`);

  const csvDownload = await request(`${API_BASE}/analyses/${alphaId}/reports/vulnerabilities/export?format=csv`, {
    headers: { Authorization: `Bearer ${tokenAlpha}` },
  });
  const csvText = typeof csvDownload.data === 'string' ? csvDownload.data : csvDownload.data.toString('utf-8');
  const hasCsvHeaders = csvText.includes('CVE ID,Title,CVSS Score');
  const hasFormulaEscape = !csvText.includes(',=') && !csvText.includes(',+');
  record('CSV Export Headers & Formula Escaping', csvDownload.status === 200 && hasCsvHeaders && hasFormulaEscape, `Status: ${csvDownload.status}, Rows: ${csvText.split('\n').length}, Type: ${csvDownload.headers.get('content-type')}`);

  // --------------------------------------------------------------------------
  // STEP 7: Confirm SOAR Actions Remain in SIMULATION Mode
  // --------------------------------------------------------------------------
  await logStep('STEP 7: Confirm SOAR actions remain in SIMULATION mode and perform no real external actions');

  const soarAction = await request(`${API_BASE}/analyses/${alphaId}/soar`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${tokenAlpha}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      actionName: 'Isolate Host from Local Subnet',
      target: 'ALPHA-CORP-WORKSTATION-01',
      actionType: 'Network Containment',
      description: 'Triggered during E2E live verification',
      isSimulation: true,
      triggeredBy: 'Analyst Alpha E2E'
    }),
  });

  const isSim = soarAction.data.status === 'SIMULATION';
  const hasSimLog = soarAction.data.result?.includes('Simulation Mode') || soarAction.data.executionLog?.includes('SIMULATION');
  record('SOAR Simulation Guarantee', soarAction.status === 201 && isSim && hasSimLog, `Status: ${soarAction.data.status}, Result: "${soarAction.data.result}", Log: "${soarAction.data.executionLog}"`);

  // Verify SOAR query lists the action with status SIMULATION
  const soarQuery = await request(`${API_BASE}/analyses/${alphaId}/soar`, {
    headers: { Authorization: `Bearer ${tokenAlpha}` },
  });
  const simCount = soarQuery.data.soarExecutions.filter(s => s.status === 'SIMULATION').length;
  record('SOAR Query Simulation Count', soarQuery.status === 200 && simCount >= 1, `Total SOAR actions: ${soarQuery.data.totalCount}, Simulations: ${simCount}`);

  // --------------------------------------------------------------------------
  // STEP 8: Negative Authorization, Expired Token & Unavailable Field Handling
  // --------------------------------------------------------------------------
  await logStep('STEP 8: Verify expired tokens, unauthorized access, forbidden access, empty datasets, and unavailable fields');

  // 8a. Expired Token
  const expiredToken = jwt.sign(
    { sub: 'user-analyst-alpha', username: 'analyst_alpha', role: 'SOC_ANALYST', email: 'alpha@soc.platform.local' },
    'soc_dev_local_secret_key_8f3a9e2c1b4d5e6f708192a3b4c5d6e7',
    { algorithm: 'HS256', expiresIn: '-10s' } // Expired 10 seconds ago
  );
  const expiredRes = await request(`${API_BASE}/analyses`, {
    headers: { Authorization: `Bearer ${expiredToken}` },
  });
  record('Expired Token Rejected', expiredRes.status === 401, `Status: ${expiredRes.status} (Expected: 401 Unauthorized)`);

  // 8b. Missing Token (Unauthorized)
  const noTokenRes = await request(`${API_BASE}/analyses`);
  record('Missing Token Rejected', noTokenRes.status === 401, `Status: ${noTokenRes.status} (Expected: 401 Unauthorized)`);

  // 8c. Non-existent Analysis (404 Not Found)
  const notFoundRes = await request(`${API_BASE}/analyses/analysis_non_existent_404_test`, {
    headers: { Authorization: `Bearer ${tokenAlpha}` },
  });
  record('Non-Existent Analysis Returns 404', notFoundRes.status === 404, `Status: ${notFoundRes.status} (Expected: 404 Not Found)`);

  // 8d. Empty datasets handling on freshly uploaded minimal file
  const emptyPayload = JSON.stringify({ system_host: 'MINIMAL-HOST', risk_score: null });
  const emptyUpload = await uploadFile(tokenAlpha, 'minimal_test.json', emptyPayload);
  const emptyId = emptyUpload.data.analysisId;

  const emptySiem = await request(`${API_BASE}/analyses/${emptyId}/siem`, {
    headers: { Authorization: `Bearer ${tokenAlpha}` },
  });
  record('Empty Dataset Graceful Response', emptySiem.status === 200 && Array.isArray(emptySiem.data.events) && emptySiem.data.events.length === 0, `SIEM Events Array: length ${emptySiem.data.events.length}`);

  const emptyDetails = await request(`${API_BASE}/analyses/${emptyId}`, {
    headers: { Authorization: `Bearer ${tokenAlpha}` },
  });
  record('Unavailable Fields Semantics (null not fabricated)', emptyDetails.status === 200 && emptyDetails.data.riskScore === null, `RiskScore: ${emptyDetails.data.riskScore}`);

  console.log('\n======================================================');
  console.log(`✅ ALL ${testResults.length} E2E VERIFICATION CHECKS PASSED SUCCESSFULLY!`);
  console.log('======================================================\n');
}

main().catch(err => {
  console.error('\n❌ E2E VERIFICATION ERROR:', err.message);
  process.exit(1);
});
