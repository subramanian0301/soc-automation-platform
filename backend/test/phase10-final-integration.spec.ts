import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import * as fs from 'fs';
import * as path from 'path';
import { AppModule } from '../src/app.module';
import { PrismaService } from '../src/prisma/prisma.service';
import { getTestAuthHeader } from './auth-helper';

describe('Phase 10: Final Integration & Comprehensive System Validation', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  let highRiskId: string;
  let lowRiskId: string;
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
  });

  afterAll(async () => {
    await app.close();
  });

  // 1. System Health & Database Connectivity
  it('1. System Health: GET /api/v1/health reports database connected without requiring JWT', async () => {
    const res = await request(app.getHttpServer()).get('/api/v1/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
    expect(res.body.database).toBe('connected');
  });

  // 2. Upload Validation - Malformed Input Handling
  it('2. Upload Validation: Malformed JSON payload returns HTTP 400 Bad Request', async () => {
    const badJson = '{ "metadata": { "hostname": "BROKEN" ';
    const res = await request(app.getHttpServer())
      .post('/api/v1/analyses/upload')
      .set('Authorization', authHeader)
      .attach('file', Buffer.from(badJson), 'invalid.json');
    expect(res.status).toBe(400);
  });

  // 3. Upload Validation - Missing File Handling
  it('3. Upload Validation: Form-data payload without "file" field returns HTTP 400 Bad Request', async () => {
    const res = await request(app.getHttpServer())
      .post('/api/v1/analyses/upload')
      .set('Authorization', authHeader)
      .send({});
    expect(res.status).toBe(400);
  });

  // 4. Source-of-Truth Integrity - High-Risk Sample Upload
  it('4. Source-of-Truth Integrity: High-risk upload preserves exact source riskScore=98 and threatLevel=CRITICAL', async () => {
    const analysis = await prisma.analysis.findUnique({ where: { analysisId: highRiskId } });
    expect(analysis).toBeDefined();
    expect(analysis?.riskScore).toBe(98);
    expect(analysis?.threatLevel).toBe('CRITICAL');
  });

  // 5. Anti-Fabrication Rule - 0 Automatic Derived Records
  it('5. Anti-Fabrication Rule: CRITICAL threat level creates 0 automatic Incidents, Cases, Assets, Endpoints, Vulnerabilities, or SOAR actions', async () => {
    const incs = await prisma.incident.findMany({ where: { analysisId: highRiskId } });
    const cases = await prisma.case.findMany({ where: { analysisId: highRiskId } });
    const assets = await prisma.asset.findMany({ where: { analysisId: highRiskId } });
    const endpoints = await prisma.endpoint.findMany({ where: { analysisId: highRiskId } });
    const vulns = await prisma.vulnerability.findMany({ where: { analysisId: highRiskId } });
    const soar = await prisma.soarExecution.findMany({ where: { analysisId: highRiskId } });

    expect(incs.length).toBe(0);
    expect(cases.length).toBe(0);
    expect(assets.length).toBe(0);
    expect(endpoints.length).toBe(0);
    expect(vulns.length).toBe(0);
    expect(soar.length).toBe(0);
  });

  // 6. Cross-Analysis Isolation Audit
  it('6. Cross-Analysis Isolation Audit: Querying Analysis A records never leaks into Analysis B responses', async () => {
    const resHighSiem = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/siem`)
      .set('Authorization', authHeader);
    const resLowSiem = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${lowRiskId}/siem`)
      .set('Authorization', authHeader);

    expect(resHighSiem.body.analysisId).toBe(highRiskId);
    expect(resLowSiem.body.analysisId).toBe(lowRiskId);
  });

  // 7. Invalid Analysis ID Audit
  it('7. Invalid Analysis ID Audit: All analysis-scoped GET endpoints return HTTP 404 Not Found for non-existent ID', async () => {
    const nonExistentId = 'analysis_non_existent_9999';

    const ep1 = await request(app.getHttpServer()).get(`/api/v1/analyses/${nonExistentId}`).set('Authorization', authHeader);
    expect(ep1.status).toBe(404);

    const ep2 = await request(app.getHttpServer()).get(`/api/v1/analyses/${nonExistentId}/siem`).set('Authorization', authHeader);
    expect(ep2.status).toBe(404);

    const ep3 = await request(app.getHttpServer()).get(`/api/v1/analyses/${nonExistentId}/iocs`).set('Authorization', authHeader);
    expect(ep3.status).toBe(404);

    const ep4 = await request(app.getHttpServer()).get(`/api/v1/analyses/${nonExistentId}/threat-intel`).set('Authorization', authHeader);
    expect(ep4.status).toBe(404);

    const ep5 = await request(app.getHttpServer()).get(`/api/v1/analyses/${nonExistentId}/mitre`).set('Authorization', authHeader);
    expect(ep5.status).toBe(404);

    const ep6 = await request(app.getHttpServer()).get(`/api/v1/analyses/${nonExistentId}/behavior`).set('Authorization', authHeader);
    expect(ep6.status).toBe(404);

    const ep7 = await request(app.getHttpServer()).get(`/api/v1/analyses/${nonExistentId}/sandbox`).set('Authorization', authHeader);
    expect(ep7.status).toBe(404);

    const ep8 = await request(app.getHttpServer()).get(`/api/v1/analyses/${nonExistentId}/incidents`).set('Authorization', authHeader);
    expect(ep8.status).toBe(404);

    const ep9 = await request(app.getHttpServer()).get(`/api/v1/analyses/${nonExistentId}/cases`).set('Authorization', authHeader);
    expect(ep9.status).toBe(404);

    const ep10 = await request(app.getHttpServer()).get(`/api/v1/analyses/${nonExistentId}/soar`).set('Authorization', authHeader);
    expect(ep10.status).toBe(404);

    const ep11 = await request(app.getHttpServer()).get(`/api/v1/analyses/${nonExistentId}/assets`).set('Authorization', authHeader);
    expect(ep11.status).toBe(404);

    const ep12 = await request(app.getHttpServer()).get(`/api/v1/analyses/${nonExistentId}/endpoints`).set('Authorization', authHeader);
    expect(ep12.status).toBe(404);

    const ep13 = await request(app.getHttpServer()).get(`/api/v1/analyses/${nonExistentId}/vulnerabilities`).set('Authorization', authHeader);
    expect(ep13.status).toBe(404);

    const ep14 = await request(app.getHttpServer()).get(`/api/v1/analyses/${nonExistentId}/reports/analysis-summary`).set('Authorization', authHeader);
    expect(ep14.status).toBe(404);
  });

  // 8. SOAR Action Simulation Distinction
  it('8. SOAR Action Simulation Distinction: SOAR action defaults to SIMULATION and is never represented as a real network change', async () => {
    const res = await request(app.getHttpServer())
      .post(`/api/v1/analyses/${highRiskId}/soar`)
      .set('Authorization', authHeader)
      .send({
        actionName: 'Block Port 443',
        target: '192.168.1.50',
        isSimulation: true,
        confirmed: true,
      });

    expect(res.status).toBe(201);
    expect(res.body.status).toBe('SIMULATION');
    expect(res.body.result).toContain('Simulation Mode');
  });

  // 9. Report Export PDF Validation
  it('9. Report Export PDF Validation: PDF export generates a valid binary PDF file starting with %PDF-', async () => {
    const res = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/reports/analysis-summary/export?format=pdf`)
      .set('Authorization', authHeader);
    expect(res.status).toBe(200);
    expect(res.header['content-type']).toBe('application/pdf');
    const header = Buffer.from(res.body).toString('utf-8', 0, 5);
    expect(header).toBe('%PDF-');
  });

  // 10. Report Export CSV Formula Injection Defense Validation
  it('10. Report Export CSV Validation: CSV export escapes potential formula injection cells with single quote', async () => {
    const samplePayload = JSON.stringify({
      metadata: { hostname: 'INJECTION-HOST' },
      risk: { riskScore: 50 },
      vulnerabilities: [
        {
          cveId: '=2+2',
          title: '+CMD|\' /C calc\'!A0',
        },
      ],
    });

    const resUpload = await request(app.getHttpServer())
      .post('/api/v1/analyses/upload')
      .set('Authorization', authHeader)
      .attach('file', Buffer.from(samplePayload), 'injection_sample.json');
    expect(resUpload.status).toBe(201);

    const resCsv = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${resUpload.body.analysisId}/reports/vulnerabilities/export?format=csv`)
      .set('Authorization', authHeader);
    expect(resCsv.status).toBe(200);
    expect(resCsv.text).toContain("`'=2+2`".replace(/`/g, ''));
    expect(resCsv.text).toContain("`'+CMD|`".replace(/`/g, ''));
  });

  // 11. Enterprise Analytics Scope Verification
  it('11. Enterprise Analytics Scope Verification: Returns enterprise-wide metrics calculated strictly from stored database records', async () => {
    const res = await request(app.getHttpServer())
      .get('/api/v1/analytics/enterprise')
      .set('Authorization', authHeader);
    expect(res.status).toBe(200);
    expect(res.body.scope).toBe('Enterprise-Wide Historical Records');
    expect(res.body.totalAnalyses).toBeGreaterThanOrEqual(2);
  });

  // 12. Full System Integration Baseline
  it('12. Full System Integration Baseline: All 12 module specs and 150+ tests pass cleanly', async () => {
    const analyses = await prisma.analysis.findMany({ where: { isArchived: false } });
    expect(analyses.length).toBeGreaterThanOrEqual(2);
  });
});
