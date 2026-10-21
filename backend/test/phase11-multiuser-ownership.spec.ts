import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import * as jwt from 'jsonwebtoken';
import { AppModule } from '../src/app.module';
import { PrismaService } from '../src/prisma/prisma.service';
import { TEST_JWT_SECRET } from './auth-helper';

describe('Phase 11: Multi-User Security, Ownership & IDOR Protection Verification', () => {
  let app: INestApplication;
  let prisma: PrismaService;

  let tokenAlpha: string;
  let tokenBeta: string;
  let tokenAdmin: string;
  let tokenReadOnly: string;
  let tokenDeactivated: string;
  let tokenForgedAdmin: string;

  let alphaAnalysisId: string;
  let betaAnalysisId: string;

  beforeAll(async () => {
    process.env.JWT_SECRET = TEST_JWT_SECRET;
    process.env.ALLOW_DEMO_TOKEN = 'true';
    process.env.ALLOW_DEMO_LOGIN = 'true';

    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.setGlobalPrefix('api/v1');
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        transform: true,
      }),
    );
    await app.init();

    prisma = app.get(PrismaService);

    // Create tokens for distinct users
    tokenAlpha = jwt.sign(
      { sub: 'user-analyst-alpha', username: 'analyst_alpha', role: 'SOC_ANALYST', email: 'alpha@soc.platform.local' },
      TEST_JWT_SECRET,
      { algorithm: 'HS256', expiresIn: '1h' },
    );

    tokenBeta = jwt.sign(
      { sub: 'user-analyst-beta', username: 'analyst_beta', role: 'SOC_ANALYST', email: 'beta@soc.platform.local' },
      TEST_JWT_SECRET,
      { algorithm: 'HS256', expiresIn: '1h' },
    );

    tokenAdmin = jwt.sign(
      { sub: 'admin-user-id', username: 'soc_admin', role: 'ADMIN', email: 'admin@soc.platform.local' },
      TEST_JWT_SECRET,
      { algorithm: 'HS256', expiresIn: '1h' },
    );

    tokenReadOnly = jwt.sign(
      { sub: 'readonly-user-id', username: 'readonly_analyst', role: 'READONLY_ANALYST', email: 'readonly@soc.platform.local' },
      TEST_JWT_SECRET,
      { algorithm: 'HS256', expiresIn: '1h' },
    );

    tokenDeactivated = jwt.sign(
      { sub: 'deactivated-user-id', username: 'deactivated_analyst', role: 'SOC_ANALYST', email: 'deactivated@soc.platform.local' },
      TEST_JWT_SECRET,
      { algorithm: 'HS256', expiresIn: '1h' },
    );

    // Forged token: Analyst Alpha claims role 'ADMIN' in client claims, but in DB is 'SOC_ANALYST'
    tokenForgedAdmin = jwt.sign(
      { sub: 'user-analyst-alpha', username: 'analyst_alpha', role: 'ADMIN', email: 'alpha@soc.platform.local' },
      TEST_JWT_SECRET,
      { algorithm: 'HS256', expiresIn: '1h' },
    );
  });

  afterAll(async () => {
    await app.close();
  });

  it('1. User Alpha uploads Analysis Alpha and User Beta uploads Analysis Beta with proper ownership binding', async () => {
    const alphaContent = JSON.stringify({
      system_host: 'HOST-ALPHA-01',
      logged_user: 'fin_analyst',
      os_name: 'Windows 11 Enterprise',
      risk_score: 25,
      severity_level: 'MEDIUM',
      yara_matches: [{ rule_name: 'Alpha_Suspicious_Script', description: 'PowerShell script execution' }],
      iocs: [{ type: 'IP', value: '192.168.1.100', category: 'Internal' }],
    });

    const betaContent = JSON.stringify({
      system_host: 'HOST-BETA-02',
      logged_user: 'sec_admin',
      os_name: 'Ubuntu 22.04 LTS',
      risk_score: 88,
      severity_level: 'CRITICAL',
      yara_matches: [{ rule_name: 'Beta_Ransomware_LockBit', description: 'LockBit ransomware signature' }],
      iocs: [{ type: 'DOMAIN', value: 'malicious-c2.net', category: 'Command & Control' }],
    });

    const uploadAlphaRes = await request(app.getHttpServer())
      .post('/api/v1/analyses/upload')
      .set('Authorization', `Bearer ${tokenAlpha}`)
      .attach('file', Buffer.from(alphaContent), 'alpha_telemetry.json');

    expect(uploadAlphaRes.status).toBe(201);
    expect(uploadAlphaRes.body.analysisId).toBeDefined();
    alphaAnalysisId = uploadAlphaRes.body.analysisId;

    const uploadBetaRes = await request(app.getHttpServer())
      .post('/api/v1/analyses/upload')
      .set('Authorization', `Bearer ${tokenBeta}`)
      .attach('file', Buffer.from(betaContent), 'beta_telemetry.json');

    expect(uploadBetaRes.status).toBe(201);
    expect(uploadBetaRes.body.analysisId).toBeDefined();
    betaAnalysisId = uploadBetaRes.body.analysisId;

    // Verify database foreign keys directly in MySQL
    const dbAlpha = await prisma.analysis.findUnique({ where: { analysisId: alphaAnalysisId } });
    const dbBeta = await prisma.analysis.findUnique({ where: { analysisId: betaAnalysisId } });

    expect(dbAlpha?.userId).toBe('user-analyst-alpha');
    expect(dbBeta?.userId).toBe('user-analyst-beta');
  });

  it('2. Analysis List Isolation: User Alpha only sees Alpha analyses; User Beta only sees Beta analyses; Admin sees both', async () => {
    const alphaListRes = await request(app.getHttpServer())
      .get('/api/v1/analyses')
      .set('Authorization', `Bearer ${tokenAlpha}`);

    expect(alphaListRes.status).toBe(200);
    const alphaIds = alphaListRes.body.map((a: any) => a.analysisId);
    expect(alphaIds).toContain(alphaAnalysisId);
    expect(alphaIds).not.toContain(betaAnalysisId);

    const betaListRes = await request(app.getHttpServer())
      .get('/api/v1/analyses')
      .set('Authorization', `Bearer ${tokenBeta}`);

    expect(betaListRes.status).toBe(200);
    const betaIds = betaListRes.body.map((a: any) => a.analysisId);
    expect(betaIds).toContain(betaAnalysisId);
    expect(betaIds).not.toContain(alphaAnalysisId);

    const adminListRes = await request(app.getHttpServer())
      .get('/api/v1/analyses')
      .set('Authorization', `Bearer ${tokenAdmin}`);

    expect(adminListRes.status).toBe(200);
    const adminIds = adminListRes.body.map((a: any) => a.analysisId);
    expect(adminIds).toContain(alphaAnalysisId);
    expect(adminIds).toContain(betaAnalysisId);
  });

  it('3. IDOR Read Protection: User Beta cannot access User Alpha analysis (403 Forbidden)', async () => {
    const res = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${alphaAnalysisId}`)
      .set('Authorization', `Bearer ${tokenBeta}`);

    expect(res.status).toBe(403);
    expect(res.body.message).toContain('Access denied');
  });

  it('4. IDOR Sub-resource Protection: User Beta cannot query Alpha sub-resources (403 Forbidden)', async () => {
    // SIEM
    const siemRes = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${alphaAnalysisId}/siem`)
      .set('Authorization', `Bearer ${tokenBeta}`);
    expect(siemRes.status).toBe(403);

    // IOCs
    const iocsRes = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${alphaAnalysisId}/iocs`)
      .set('Authorization', `Bearer ${tokenBeta}`);
    expect(iocsRes.status).toBe(403);

    // Threat Intel
    const threatIntelRes = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${alphaAnalysisId}/threat-intel`)
      .set('Authorization', `Bearer ${tokenBeta}`);
    expect(threatIntelRes.status).toBe(403);

    // MITRE
    const mitreRes = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${alphaAnalysisId}/mitre`)
      .set('Authorization', `Bearer ${tokenBeta}`);
    expect(mitreRes.status).toBe(403);

    // Behavior
    const behaviorRes = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${alphaAnalysisId}/behavior`)
      .set('Authorization', `Bearer ${tokenBeta}`);
    expect(behaviorRes.status).toBe(403);

    // Sandbox
    const sandboxRes = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${alphaAnalysisId}/sandbox`)
      .set('Authorization', `Bearer ${tokenBeta}`);
    expect(sandboxRes.status).toBe(403);

    // Incidents & Cases
    const incidentsRes = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${alphaAnalysisId}/incidents`)
      .set('Authorization', `Bearer ${tokenBeta}`);
    expect(incidentsRes.status).toBe(403);

    const casesRes = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${alphaAnalysisId}/cases`)
      .set('Authorization', `Bearer ${tokenBeta}`);
    expect(casesRes.status).toBe(403);

    // Assets & Endpoints
    const assetsRes = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${alphaAnalysisId}/assets`)
      .set('Authorization', `Bearer ${tokenBeta}`);
    expect(assetsRes.status).toBe(403);

    const endpointsRes = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${alphaAnalysisId}/endpoints`)
      .set('Authorization', `Bearer ${tokenBeta}`);
    expect(endpointsRes.status).toBe(403);

    // Vulnerabilities
    const vulnRes = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${alphaAnalysisId}/vulnerabilities`)
      .set('Authorization', `Bearer ${tokenBeta}`);
    expect(vulnRes.status).toBe(403);

    // SOAR
    const soarRes = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${alphaAnalysisId}/soar`)
      .set('Authorization', `Bearer ${tokenBeta}`);
    expect(soarRes.status).toBe(403);
  });

  it('5. IDOR Report & Export Protection: User Beta cannot view or export reports for Alpha (403 Forbidden)', async () => {
    // JSON report
    const reportRes = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${alphaAnalysisId}/reports/analysis-summary`)
      .set('Authorization', `Bearer ${tokenBeta}`);
    expect(reportRes.status).toBe(403);

    // PDF Export
    const pdfRes = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${alphaAnalysisId}/reports/analysis-summary/export?format=pdf`)
      .set('Authorization', `Bearer ${tokenBeta}`);
    expect(pdfRes.status).toBe(403);

    // CSV Export
    const csvRes = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${alphaAnalysisId}/reports/vulnerabilities/export?format=csv`)
      .set('Authorization', `Bearer ${tokenBeta}`);
    expect(csvRes.status).toBe(403);
  });

  it('6. IDOR Mutation Protection: User Beta cannot mutate Alpha records (403 Forbidden)', async () => {
    // Attempt incident creation on Alpha by Beta
    const incidentRes = await request(app.getHttpServer())
      .post(`/api/v1/analyses/${alphaAnalysisId}/incidents`)
      .set('Authorization', `Bearer ${tokenBeta}`)
      .send({ title: 'Unauthorized Incident by Beta', reason: 'Cross-tenant probe' });
    expect(incidentRes.status).toBe(403);

    // Attempt case creation on Alpha by Beta
    const caseRes = await request(app.getHttpServer())
      .post(`/api/v1/analyses/${alphaAnalysisId}/cases`)
      .set('Authorization', `Bearer ${tokenBeta}`)
      .send({ title: 'Unauthorized Case by Beta' });
    expect(caseRes.status).toBe(403);

    // Attempt SOAR execution on Alpha by Beta
    const soarRes = await request(app.getHttpServer())
      .post(`/api/v1/analyses/${alphaAnalysisId}/soar`)
      .set('Authorization', `Bearer ${tokenBeta}`)
      .send({ actionName: 'Isolate Host', target: 'HOST-ALPHA-01' });
    expect(soarRes.status).toBe(403);

    // Attempt asset creation on Alpha by Beta
    const assetRes = await request(app.getHttpServer())
      .post(`/api/v1/analyses/${alphaAnalysisId}/assets`)
      .set('Authorization', `Bearer ${tokenBeta}`)
      .send({ assetName: 'Malicious Asset Injection' });
    expect(assetRes.status).toBe(403);

    // Attempt endpoint creation on Alpha by Beta
    const endpointRes = await request(app.getHttpServer())
      .post(`/api/v1/analyses/${alphaAnalysisId}/endpoints`)
      .set('Authorization', `Bearer ${tokenBeta}`)
      .send({ hostname: 'Injected-Host' });
    expect(endpointRes.status).toBe(403);

    // Attempt vulnerability creation on Alpha by Beta
    const vulnRes = await request(app.getHttpServer())
      .post(`/api/v1/analyses/${alphaAnalysisId}/vulnerabilities`)
      .set('Authorization', `Bearer ${tokenBeta}`)
      .send({ title: 'Fabricated CVE', cveId: 'CVE-9999-9999' });
    expect(vulnRes.status).toBe(403);
  });

  it('7. Legitimate Owner Access: User Alpha can read, mutate, export reports, and trigger SOAR simulation on Alpha', async () => {
    // Read
    const getRes = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${alphaAnalysisId}`)
      .set('Authorization', `Bearer ${tokenAlpha}`);
    expect(getRes.status).toBe(200);
    expect(getRes.body.hostname).toBe('HOST-ALPHA-01');

    // Case creation
    const caseRes = await request(app.getHttpServer())
      .post(`/api/v1/analyses/${alphaAnalysisId}/cases`)
      .set('Authorization', `Bearer ${tokenAlpha}`)
      .send({ title: 'Authorized Alpha Case Investigation', priority: 'HIGH' });
    expect(caseRes.status).toBe(201);
    expect(caseRes.body.caseNumber).toBeDefined();

    // SOAR Simulation
    const soarRes = await request(app.getHttpServer())
      .post(`/api/v1/analyses/${alphaAnalysisId}/soar`)
      .set('Authorization', `Bearer ${tokenAlpha}`)
      .send({ actionName: 'Isolate Host', target: 'HOST-ALPHA-01', confirmed: true });
    expect(soarRes.status).toBe(201);
    expect(soarRes.body.status).toBe('SIMULATION');

    // PDF Export
    const pdfRes = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${alphaAnalysisId}/reports/analysis-summary/export?format=pdf`)
      .set('Authorization', `Bearer ${tokenAlpha}`);
    expect(pdfRes.status).toBe(200);
    expect(pdfRes.headers['content-type']).toContain('application/pdf');
  });

  it('8. Administrator Policy Override: Admin user can access and export both Alpha and Beta analyses (200 OK)', async () => {
    // Admin reads Alpha
    const alphaAdminRes = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${alphaAnalysisId}`)
      .set('Authorization', `Bearer ${tokenAdmin}`);
    expect(alphaAdminRes.status).toBe(200);

    // Admin reads Beta
    const betaAdminRes = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${betaAnalysisId}`)
      .set('Authorization', `Bearer ${tokenAdmin}`);
    expect(betaAdminRes.status).toBe(200);

    // Admin exports Beta
    const exportAdminRes = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${betaAnalysisId}/reports/analysis-summary/export?format=csv`)
      .set('Authorization', `Bearer ${tokenAdmin}`);
    expect(exportAdminRes.status).toBe(200);
    expect(exportAdminRes.headers['content-type']).toContain('text/csv');
  });

  it('9. Server Identity Authoritative: Token with forged client claim role="ADMIN" is checked against DB and rejected (403 Forbidden)', async () => {
    // tokenForgedAdmin has role='ADMIN' in payload, but user-analyst-alpha is 'SOC_ANALYST' in DB
    const forgedRes = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${betaAnalysisId}`)
      .set('Authorization', `Bearer ${tokenForgedAdmin}`);

    // Server-side identity validation must reject unauthorized cross-user access
    expect(forgedRes.status).toBe(403);
    expect(forgedRes.body.message).toContain('Access denied');
  });

  it('10. Role-Based Permissions: READONLY_ANALYST cannot mutate analyses or trigger SOAR actions (403 Forbidden)', async () => {
    // Associate Alpha with ReadOnly user for testing write restriction
    await prisma.analysis.update({
      where: { analysisId: alphaAnalysisId },
      data: { userId: 'readonly-user-id' },
    });

    try {
      // ReadOnly can read
      const readRes = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${alphaAnalysisId}`)
        .set('Authorization', `Bearer ${tokenReadOnly}`);
      expect(readRes.status).toBe(200);

      // ReadOnly cannot create case
      const caseRes = await request(app.getHttpServer())
        .post(`/api/v1/analyses/${alphaAnalysisId}/cases`)
        .set('Authorization', `Bearer ${tokenReadOnly}`)
        .send({ title: 'ReadOnly Attempted Mutation' });
      expect(caseRes.status).toBe(403);
      expect(caseRes.body.message).toContain('READONLY_ANALYST');

      // ReadOnly cannot trigger SOAR
      const soarRes = await request(app.getHttpServer())
        .post(`/api/v1/analyses/${alphaAnalysisId}/soar`)
        .set('Authorization', `Bearer ${tokenReadOnly}`)
        .send({ actionName: 'Trigger Playbook' });
      expect(soarRes.status).toBe(403);
      expect(soarRes.body.message).toContain('READONLY_ANALYST');
    } finally {
      // Restore ownership to Alpha
      await prisma.analysis.update({
        where: { analysisId: alphaAnalysisId },
        data: { userId: 'user-analyst-alpha' },
      });
    }
  });

  it('11. Deactivated Account Protection: Deactivated user is rejected with 401 Unauthorized', async () => {
    const res = await request(app.getHttpServer())
      .get('/api/v1/analyses')
      .set('Authorization', `Bearer ${tokenDeactivated}`);

    expect(res.status).toBe(401);
    expect(res.body.message).toContain('inactive or disabled');
  });

  it('12. Non-existent analysisId returns 404 Not Found (distinct from 403 Forbidden)', async () => {
    const res = await request(app.getHttpServer())
      .get('/api/v1/analyses/analysis_non_existent_99999999')
      .set('Authorization', `Bearer ${tokenAlpha}`);

    expect(res.status).toBe(404);
    expect(res.body.message).toContain('not found');
  });

  it('13. Unauthenticated request to analysis endpoint returns 401 Unauthorized', async () => {
    const res = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${alphaAnalysisId}`);

    expect(res.status).toBe(401);
    expect(res.body.message).toContain('Authentication token missing');
  });

  it('14. Scoped Enterprise Analytics: Cross-analysis data disclosure is prevented for non-admin analysts', async () => {
    // User Alpha analytics: scope restricted to User Alpha records
    const alphaAnalyticsRes = await request(app.getHttpServer())
      .get('/api/v1/analytics/enterprise')
      .set('Authorization', `Bearer ${tokenAlpha}`);

    expect(alphaAnalyticsRes.status).toBe(200);
    expect(alphaAnalyticsRes.body.scope).toContain('User-Scoped Analytics');
    expect(alphaAnalyticsRes.body.scope).toContain('analyst_alpha');
    expect(alphaAnalyticsRes.body.isGlobalAdmin).toBe(false);

    // Admin analytics: global enterprise view
    const adminAnalyticsRes = await request(app.getHttpServer())
      .get('/api/v1/analytics/enterprise')
      .set('Authorization', `Bearer ${tokenAdmin}`);

    expect(adminAnalyticsRes.status).toBe(200);
    expect(adminAnalyticsRes.body.scope).toContain('Enterprise-Wide Historical Records');
    expect(adminAnalyticsRes.body.isGlobalAdmin).toBe(true);
    expect(adminAnalyticsRes.body.totalAnalyses).toBeGreaterThanOrEqual(2);
  });
});
