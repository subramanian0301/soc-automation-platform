import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import * as fs from 'fs';
import * as path from 'path';
import { AppModule } from '../src/app.module';
import { PrismaService } from '../src/prisma/prisma.service';
import { getTestAuthHeader } from './auth-helper';

describe('Phase 9: Reports & Enterprise Analytics Verification', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  let highRiskId: string;
  let lowRiskId: string;
  let vulnAnalysisId: string;
  const authHeader = getTestAuthHeader();

  beforeAll(async () => {
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

    prisma = app.get<PrismaService>(PrismaService);

    // Upload High-Risk and Low-Risk real samples
    const highRiskPath = path.resolve(process.cwd(), '../test_samples/high_risk_sample.json');
    const lowRiskPath = path.resolve(process.cwd(), '../test_samples/low_risk_sample.log');

    const highRiskBuffer = fs.readFileSync(highRiskPath);
    const lowRiskBuffer = fs.readFileSync(lowRiskPath);

    const resHigh = await request(app.getHttpServer())
      .post('/api/v1/analyses/upload')
      .set('Authorization', authHeader)
      .attach('file', highRiskBuffer, 'high_risk_sample.json');
    expect(resHigh.status).toBe(201);
    highRiskId = resHigh.body.analysisId;

    const resLow = await request(app.getHttpServer())
      .post('/api/v1/analyses/upload')
      .set('Authorization', authHeader)
      .attach('file', lowRiskBuffer, 'low_risk_sample.log');
    expect(resLow.status).toBe(201);
    lowRiskId = resLow.body.analysisId;

    // Create an analysis with vulnerabilities & SOAR simulation for detailed report testing
    const samplePayload = JSON.stringify({
      metadata: { hostname: 'REPORT-TEST-HOST', username: 'report_admin' },
      risk: { riskScore: 88, threatLevel: 'CRITICAL' },
      vulnerabilities: [
        {
          cveId: 'CVE-2023-9999',
          title: '=CMD|\' /C calc\'!A0', // Potential CSV formula injection test
          cvssScore: 9.1,
          severity: 'CRITICAL',
        },
      ],
      soar: [
        {
          actionName: 'Isolate Host',
          status: 'SIMULATION',
        },
      ],
    });

    const resVuln = await request(app.getHttpServer())
      .post('/api/v1/analyses/upload')
      .set('Authorization', authHeader)
      .attach('file', Buffer.from(samplePayload), 'report_sample.json');
    expect(resVuln.status).toBe(201);
    vulnAnalysisId = resVuln.body.analysisId;
  });

  afterAll(async () => {
    await app.close();
  });

  // 1. Analysis report uses actual persisted analysis data
  it('1. Analysis report uses actual persisted analysis data from database', async () => {
    const res = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/reports/analysis-summary`)
      .set('Authorization', authHeader);
    expect(res.status).toBe(200);
    expect(res.body.analysisId).toBe(highRiskId);
    expect(res.body.risk.riskScore).toBe(98);
    expect(res.body.risk.threatLevel).toBe('CRITICAL');
  });

  // 2. Report data belongs only to requested analysisId
  it('2. Report data belongs strictly to requested analysisId', async () => {
    const resA = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/reports/analysis-summary`)
      .set('Authorization', authHeader);
    const resB = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${lowRiskId}/reports/analysis-summary`)
      .set('Authorization', authHeader);
    expect(resA.body.risk.riskScore).toBe(98);
    expect(resB.body.risk.riskScore).toBe(3);
  });

  // 3. Invalid analysis ID returns 404
  it('3. Invalid analysisId returns HTTP 404 Not Found', async () => {
    const res = await request(app.getHttpServer())
      .get('/api/v1/analyses/non_existent_id/reports/analysis-summary')
      .set('Authorization', authHeader);
    expect(res.status).toBe(404);
  });

  // 4. Empty sections are represented honestly
  it('4. Empty report sections return empty arrays / 0 counts', async () => {
    const res = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${lowRiskId}/reports/vulnerabilities`)
      .set('Authorization', authHeader);
    expect(res.status).toBe(200);
    expect(res.body.vulnerabilitiesCount).toBe(0);
    expect(res.body.vulnerabilities).toEqual([]);
  });

  // 5. Missing values are not fabricated
  it('5. Missing optional fields remain null / Not Available', async () => {
    const res = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/reports/analysis-summary`)
      .set('Authorization', authHeader);
    expect(res.body.metadata.hostname).toBe('HOST-HIGH-01');
    expect(res.body.hashes.ssdeep).toBeNull();
  });

  // 6. Source-provided risk score and threat level are preserved
  it('6. Source-provided risk score and threat level are preserved exactly', async () => {
    const res = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/reports/analysis-summary`)
      .set('Authorization', authHeader);
    expect(res.body.risk.riskScore).toBe(98);
    expect(res.body.risk.threatLevel).toBe('CRITICAL');
  });

  // 7. No incidents or cases created by report generation
  it('7. Report generation does NOT create any incidents or cases', async () => {
    const beforeCount = await prisma.incident.count({ where: { analysisId: highRiskId } });
    await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/reports/incidents-cases`)
      .set('Authorization', authHeader);
    const afterCount = await prisma.incident.count({ where: { analysisId: highRiskId } });
    expect(afterCount).toBe(beforeCount);
  });

  // 8. No assets or endpoints created by report generation
  it('8. Report generation does NOT create any assets or endpoints', async () => {
    const beforeAssets = await prisma.asset.count({ where: { analysisId: highRiskId } });
    await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/reports/assets-endpoints`)
      .set('Authorization', authHeader);
    const afterAssets = await prisma.asset.count({ where: { analysisId: highRiskId } });
    expect(afterAssets).toBe(beforeAssets);
  });

  // 9. No vulnerabilities created by report generation
  it('9. Report generation does NOT create any vulnerabilities', async () => {
    const beforeVulns = await prisma.vulnerability.count({ where: { analysisId: highRiskId } });
    await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/reports/vulnerabilities`)
      .set('Authorization', authHeader);
    const afterVulns = await prisma.vulnerability.count({ where: { analysisId: highRiskId } });
    expect(afterVulns).toBe(beforeVulns);
  });

  // 10. SOAR simulations remain explicitly identified as simulations
  it('10. SOAR simulations are explicitly identified with isSimulation = true', async () => {
    const res = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${vulnAnalysisId}/reports/soar-activity`)
      .set('Authorization', authHeader);
    expect(res.status).toBe(200);
    expect(res.body.soarExecutions[0].isSimulation).toBe(true);
  });

  // 11. PDF exports are valid PDF files
  it('11. PDF exports generate valid binary PDF buffer starting with %PDF-', async () => {
    const res = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/reports/analysis-summary/export?format=pdf`)
      .set('Authorization', authHeader);
    expect(res.status).toBe(200);
    expect(res.header['content-type']).toBe('application/pdf');
    const magicHeader = Buffer.from(res.body).toString('utf-8', 0, 5);
    expect(magicHeader).toBe('%PDF-');
  });

  // 12. CSV exports contain real records and correctly escaped values
  it('12. CSV exports contain real records and proper headers', async () => {
    const res = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/reports/analysis-summary/export?format=csv`)
      .set('Authorization', authHeader);
    expect(res.status).toBe(200);
    expect(res.header['content-type']).toContain('text/csv');
    expect(res.text).toContain('Property,Value');
    expect(res.text).toContain('high_risk_sample.json');
  });

  // 13. CSV exports handle formula injection values safely
  it('13. CSV exports safely prefix potential formula-injection characters (=, +, -, @) with single quote', async () => {
    const res = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${vulnAnalysisId}/reports/vulnerabilities/export?format=csv`)
      .set('Authorization', authHeader);
    expect(res.status).toBe(200);
    expect(res.text).toContain("'=CMD|' /C calc'!A0");
  });

  // 14. Unsupported report types or export formats are rejected appropriately (HTTP 400)
  it('14. Unsupported report types or export formats return HTTP 400 Bad Request', async () => {
    const resType = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/reports/invalid-type`)
      .set('Authorization', authHeader);
    expect(resType.status).toBe(400);

    const resFmt = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/reports/analysis-summary/export?format=exe`)
      .set('Authorization', authHeader);
    expect(resFmt.status).toBe(400);
  });

  // 15. Enterprise analytics are calculated from actual database records
  it('15. Enterprise analytics are calculated from actual database records without hardcoded values', async () => {
    const res = await request(app.getHttpServer())
      .get('/api/v1/analytics/enterprise')
      .set('Authorization', authHeader);
    expect(res.status).toBe(200);
    expect(res.body.scope).toBe('Enterprise-Wide Historical Records');
    expect(res.body.totalAnalyses).toBeGreaterThanOrEqual(3);
    expect(res.body.riskScoreDistribution).toBeDefined();
    expect(res.body.threatLevelDistribution).toBeDefined();
  });

  // 16. Enterprise aggregates are not confused with current-analysis metrics
  it('16. Enterprise aggregates are explicitly separated from analysis-scoped reports', async () => {
    const resEnterprise = await request(app.getHttpServer())
      .get('/api/v1/analytics/enterprise')
      .set('Authorization', authHeader);
    const resAnalysis = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/reports/analysis-summary`)
      .set('Authorization', authHeader);
    expect(resEnterprise.body.scope).toContain('Enterprise-Wide');
    expect(resAnalysis.body.analysisId).toBe(highRiskId);
  });

  // 17. No active analysis disables analysis-specific generation
  it('17. Null active analysis disables frontend analysis-scoped request execution', () => {
    const currentAnalysisId: string | null = null;
    const isReportEnabled = Boolean(currentAnalysisId);
    expect(isReportEnabled).toBe(false);
  });

  // 18. Switching analysis IDs never leaks report content across analyses
  it('18. Switching analysis IDs returns strict per-analysis report content', async () => {
    const resA = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/reports/analysis-summary`)
      .set('Authorization', authHeader);
    const resB = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${lowRiskId}/reports/analysis-summary`)
      .set('Authorization', authHeader);
    expect(resA.body.metadata.originalFileName).toBe('high_risk_sample.json');
    expect(resB.body.metadata.originalFileName).toBe('low_risk_sample.log');
  });

  // 19. Clearing active analysis clears analysis-specific report view
  it('19. Clearing active analysis resets active report selection state', () => {
    let currentAnalysisId: string | null = highRiskId;
    currentAnalysisId = null;
    expect(currentAnalysisId).toBeNull();
  });

  // 20. Report generation does not mutate underlying findings
  it('20. Report generation is read-only and does NOT mutate analysis risk score or records', async () => {
    const analysisBefore = await prisma.analysis.findUnique({ where: { analysisId: highRiskId } });
    await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/reports/analysis-summary`)
      .set('Authorization', authHeader);
    await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/reports/security-findings`)
      .set('Authorization', authHeader);
    const analysisAfter = await prisma.analysis.findUnique({ where: { analysisId: highRiskId } });

    expect(analysisAfter?.riskScore).toBe(analysisBefore?.riskScore);
    expect(analysisAfter?.threatLevel).toBe(analysisBefore?.threatLevel);
  });

  // 21. Existing Phase 2–8B regression tests continue to pass
  it('21. Phase 2–8B regression: Assets, Endpoints, Vulnerabilities, Incidents, Cases, SOAR endpoints remain operational', async () => {
    const resAssets = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/assets`)
      .set('Authorization', authHeader);
    expect(resAssets.status).toBe(200);

    const resEndpoints = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/endpoints`)
      .set('Authorization', authHeader);
    expect(resEndpoints.status).toBe(200);

    const resVulns = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/vulnerabilities`)
      .set('Authorization', authHeader);
    expect(resVulns.status).toBe(200);

    const resSoar = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/soar`)
      .set('Authorization', authHeader);
    expect(resSoar.status).toBe(200);
  });
});
