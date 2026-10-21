const API_BASE = 'http://localhost:4000/api/v1';

async function requestJson(url, options = {}) {
  const res = await fetch(url, options);
  const data = await res.json();
  return { status: res.status, data };
}

async function uploadFile(filename, content, mimeType = 'text/plain') {
  const formData = new FormData();
  const blob = new Blob([content], { type: mimeType });
  formData.append('file', blob, filename);

  const res = await fetch(`${API_BASE}/analyses/upload`, {
    method: 'POST',
    body: formData,
  });
  const data = await res.json();
  return { status: res.status, data };
}

async function runLiveVerification() {
  console.log('=== PHASE 2 LIVE E2E VERIFICATION ===\n');

  // 1. Health & Service Check
  console.log('[Step 1] Checking backend health & DB connectivity...');
  const health = await requestJson(`${API_BASE}/analyses`);
  console.log(`Backend Health Status: ${health.status} (${Array.isArray(health.data) ? health.data.length : 0} existing database records)`);
  if (health.status !== 200) {
    throw new Error('Backend health check failed');
  }

  // 2. Fixture A: Zero Risk JSON (riskScore = 0)
  console.log('\n[Step 2] Testing Fixture A (Zero Risk JSON, riskScore = 0)...');
  const fixtureA_content = JSON.stringify({
    system_host: 'ZERO-RISK-SRV',
    logged_user: 'sec_auditor',
    os_name: 'Ubuntu 22.04 LTS',
    risk_score: 0,
    severity_level: 'LOW',
    suggested_action: 'No Action Required',
    custom_unmapped_telemetry: {
      uptime_hours: 1420,
      compliance_pass: true
    }
  });

  const uploadA = await uploadFile('fixture_a_zero_risk.json', fixtureA_content, 'application/json');
  console.log(`Fixture A Upload Status: ${uploadA.status}, ID: ${uploadA.data.analysisId}`);
  if (uploadA.status !== 201) throw new Error(`Fixture A upload failed: ${JSON.stringify(uploadA.data)}`);

  const detailA = await requestJson(`${API_BASE}/analyses/${uploadA.data.analysisId}`);
  console.log(`Fixture A riskScore: ${detailA.data.riskScore} (Expected: 0)`);
  console.log(`Fixture A hostname: ${detailA.data.hostname} (Expected: ZERO-RISK-SRV)`);
  console.log(`Fixture A calculatedMd5: ${detailA.data.fileMetadata?.calculatedMd5}`);
  if (detailA.data.riskScore !== 0) throw new Error('Fixture A riskScore did NOT preserve exact 0!');
  if (!detailA.data.fileMetadata?.calculatedMd5) throw new Error('Fixture A calculatedMd5 missing!');

  // 3. Fixture B: Mid Risk CSV (riskScore = 65, missing threat level)
  console.log('\n[Step 3] Testing Fixture B (Mid Risk CSV, riskScore = 65, inferred MEDIUM threat level)...');
  const fixtureB_content = `"Node Name";"User";"Risk Value";"IP Address";"CVE ID";"CVSS Score";"Reported MD5"
"PROD-APP-02";"appadmin";"65";"10.20.4.15";"CVE-2025-5432";"6.5";"d41d8cd98f00b204e9800998ecf8427e"
`;

  const uploadB = await uploadFile('fixture_b_mid_risk.csv', fixtureB_content, 'text/csv');
  console.log(`Fixture B Upload Status: ${uploadB.status}, ID: ${uploadB.data.analysisId}`);
  if (uploadB.status !== 201) throw new Error(`Fixture B upload failed: ${JSON.stringify(uploadB.data)}`);

  const detailB = await requestJson(`${API_BASE}/analyses/${uploadB.data.analysisId}`);
  console.log(`Fixture B riskScore: ${detailB.data.riskScore} (Expected: 65)`);
  console.log(`Fixture B threatLevel: ${detailB.data.threatLevel} (Expected: MEDIUM inferred)`);
  console.log(`Fixture B calculatedMd5 vs reported hash: calculated=${detailB.data.fileMetadata?.calculatedMd5}, reported=${detailB.data.hashes?.md5}`);
  if (detailB.data.riskScore !== 65) throw new Error('Fixture B riskScore != 65!');
  if (detailB.data.threatLevel !== 'MEDIUM') throw new Error('Fixture B threatLevel was not inferred as MEDIUM!');

  // 4. Fixture C: High Risk LOG with Section Headers & Unparsed Diagnostic Line (riskScore = 100)
  console.log('\n[Step 4] Testing Fixture C (Critical Risk 100 LOG with unparsed line)...');
  const fixtureC_content = `
Host Name => CRITICAL-DC-01
Risk Value => 100
Severity Level => CRITICAL

=== YARA SIGNATURES ===
Rule_APT_Ransomware_LockBit

=== MITRE ATTACK ===
T1486 - Data Encrypted for Impact

=== SIEM LOGS ===
Event: 4625 SRC=192.168.1.50 DST=192.168.1.1 DENY

Unparsed diagnostic line without entity regex match 9999
`;

  const uploadC = await uploadFile('fixture_c_critical.log', fixtureC_content, 'text/plain');
  console.log(`Fixture C Upload Status: ${uploadC.status}, ID: ${uploadC.data.analysisId}`);
  if (uploadC.status !== 201) throw new Error(`Fixture C upload failed: ${JSON.stringify(uploadC.data)}`);

  const detailC = await requestJson(`${API_BASE}/analyses/${uploadC.data.analysisId}`);
  console.log(`Fixture C riskScore: ${detailC.data.riskScore} (Expected: 100)`);
  console.log(`Fixture C threatLevel: ${detailC.data.threatLevel} (Expected: CRITICAL)`);
  console.log(`Fixture C parsingStatus: ${detailC.data.parsingStatus} (Expected: PARTIAL)`);
  console.log(`Fixture C unparsedLines:`, detailC.data.unrecognizedFields?.unparsedLines);
  if (detailC.data.riskScore !== 100) throw new Error('Fixture C riskScore != 100!');
  if (detailC.data.parsingStatus !== 'PARTIAL') throw new Error('Fixture C parsingStatus was not PARTIAL!');

  // 5. Boundary Validation: Invalid Risk Score (riskScore = 150)
  console.log('\n[Step 5] Testing Boundary Validation (Invalid riskScore = 150)...');
  const invalidJson = JSON.stringify({
    hostname: 'BAD-HOST',
    riskScore: 150
  });
  const uploadInvalid = await uploadFile('invalid_score.json', invalidJson, 'application/json');
  console.log(`Invalid Score Upload Status: ${uploadInvalid.status} (Expected: 400)`);
  if (uploadInvalid.status !== 400) throw new Error('Invalid riskScore = 150 was NOT rejected with 400!');

  // 6. Verification of Module Endpoints for Fixture C
  console.log('\n[Step 6] Verifying Module Scoped REST Endpoints...');
  const threatIntelRes = await requestJson(`${API_BASE}/analyses/${uploadC.data.analysisId}/threat-intel`);
  console.log(`Threat Intel YARA count: ${threatIntelRes.data.yaraResults?.length}`);
  if (threatIntelRes.data.yaraResults?.length !== 1) throw new Error('Threat Intel YARA count != 1');

  const mitreRes = await requestJson(`${API_BASE}/analyses/${uploadC.data.analysisId}/mitre`);
  console.log(`MITRE endpoint technique count: ${mitreRes.data.totalCount}`);
  if (mitreRes.data.totalCount !== 1) throw new Error('MITRE count != 1');

  const siemRes = await requestJson(`${API_BASE}/analyses/${uploadC.data.analysisId}/siem`);
  console.log(`SIEM endpoint event count: ${siemRes.data.totalCount}`);
  if (siemRes.data.totalCount !== 1) throw new Error('SIEM count != 1');

  // 7. Isolation check: Fixture A should have 0 YARA rules
  const threatIntelA = await requestJson(`${API_BASE}/analyses/${uploadA.data.analysisId}/threat-intel`);
  console.log(`Fixture A YARA count (isolation check): ${threatIntelA.data.yaraResults?.length} (Expected: 0)`);
  if (threatIntelA.data.yaraResults?.length !== 0) throw new Error('Isolation failure: Fixture A has YARA rules from Fixture C!');

  console.log('\n=== ALL LIVE VERIFICATION CHECKS PASSED SUCCESSFULLY ===');
}

runLiveVerification().catch(err => {
  console.error('\n❌ VERIFICATION ERROR:', err.message);
  process.exit(1);
});
