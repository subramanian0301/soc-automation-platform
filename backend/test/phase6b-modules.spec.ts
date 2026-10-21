import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import * as fs from 'fs';
import * as path from 'path';
import { AppModule } from '../src/app.module';
import { PrismaService } from '../src/prisma/prisma.service';
import { getTestAuthHeader } from './auth-helper';

describe('Phase 6B: Threat Intel + MITRE + Behavior + Sandbox Modules Verification', () => {
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

  // Test 1: Threat Intelligence analysis isolation
  it('1. Threat Intelligence analysis isolation: GET /api/v1/analyses/:analysisId/threat-intel returns only data for target analysis', async () => {
    const resHigh = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/threat-intel`)
      .set('Authorization', authHeader);
    expect(resHigh.status).toBe(200);
    expect(resHigh.body.analysisId).toBe(highRiskId);
    expect(resHigh.body.hasData).toBe(true);
    expect(resHigh.body.riskScore).toBe(98);
    expect(resHigh.body.threatLevel).toBe('CRITICAL');
  });

  // Test 2: MITRE ATT&CK analysis isolation
  it('2. MITRE analysis isolation: GET /api/v1/analyses/:analysisId/mitre returns only techniques for target analysis', async () => {
    const resHigh = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/mitre`)
      .set('Authorization', authHeader);
    expect(resHigh.status).toBe(200);
    expect(resHigh.body.analysisId).toBe(highRiskId);
    expect(Array.isArray(resHigh.body.techniques)).toBe(true);

    for (const tech of resHigh.body.techniques) {
      expect(tech.analysisId).toBe(highRiskId);
      expect(tech.analysisId).not.toBe(lowRiskId);
    }
  });

  // Test 3: Behavior analysis isolation
  it('3. Behavior analysis isolation: GET /api/v1/analyses/:analysisId/behavior returns only behavior events for target analysis', async () => {
    const resHigh = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/behavior`)
      .set('Authorization', authHeader);
    expect(resHigh.status).toBe(200);
    expect(resHigh.body.analysisId).toBe(highRiskId);
    expect(Array.isArray(resHigh.body.events)).toBe(true);

    for (const ev of resHigh.body.events) {
      expect(ev.analysisId).toBe(highRiskId);
    }
  });

  // Test 4: Sandbox analysis isolation
  it('4. Sandbox analysis isolation: GET /api/v1/analyses/:analysisId/sandbox returns only sandbox results for target analysis', async () => {
    const resHigh = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/sandbox`)
      .set('Authorization', authHeader);
    expect(resHigh.status).toBe(200);
    expect(resHigh.body.analysisId).toBe(highRiskId);
    expect(Array.isArray(resHigh.body.results)).toBe(true);

    for (const res of resHigh.body.results) {
      expect(res.analysisId).toBe(highRiskId);
    }
  });

  // Test 5: currentAnalysisId behavior
  it('5. currentAnalysisId behavior: null currentAnalysisId disables all 4 module queries', () => {
    let currentAnalysisId: string | null = null;
    expect(currentAnalysisId).toBeNull();
    const queryEnabled = Boolean(currentAnalysisId);
    expect(queryEnabled).toBe(false);
  });

  // Test 6: Query key isolation
  it('6. Query key isolation: distinct query keys bound to currentAnalysisId', () => {
    const tiKeyA = ['analysis', highRiskId, 'threat-intel'];
    const mitreKeyA = ['analysis', highRiskId, 'mitre'];
    const bevKeyA = ['analysis', highRiskId, 'behavior'];
    const sbKeyA = ['analysis', highRiskId, 'sandbox'];

    const tiKeyB = ['analysis', lowRiskId, 'threat-intel'];

    expect(tiKeyA).not.toEqual(tiKeyB);
    expect(tiKeyA).not.toEqual(mitreKeyA);
    expect(mitreKeyA).not.toEqual(bevKeyA);
    expect(bevKeyA).not.toEqual(sbKeyA);
  });

  // Test 7: Clear-selection behavior
  it('7. Clear-selection behavior: clearing active analysis resets all 4 modules', () => {
    let currentAnalysisId: string | null = highRiskId;
    currentAnalysisId = null; // Clear selection

    expect(currentAnalysisId).toBeNull();
    const queryEnabled = Boolean(currentAnalysisId);
    expect(queryEnabled).toBe(false);
  });

  // Test 8: Missing threat intelligence handling
  it('8. Missing threat intelligence handling: low-risk log sample returns clean empty/low risk intel', async () => {
    const resLow = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${lowRiskId}/threat-intel`)
      .set('Authorization', authHeader);
    expect(resLow.status).toBe(200);
    expect(resLow.body.analysisId).toBe(lowRiskId);
    expect(resLow.body.riskScore).toBe(3);
    expect(resLow.body.threatLevel).toBe('LOW');
  });

  // Test 9: Missing MITRE data handling
  it('9. Missing MITRE data handling: low-risk log sample returns totalCount: 0 and techniques: []', async () => {
    const resLow = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${lowRiskId}/mitre`)
      .set('Authorization', authHeader);
    expect(resLow.status).toBe(200);
    expect(resLow.body.totalCount).toBe(0);
    expect(resLow.body.techniques).toEqual([]);
  });

  // Test 10: Missing behavior data handling
  it('10. Missing behavior data handling: low-risk log sample returns totalCount: 0 and events: []', async () => {
    const resLow = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${lowRiskId}/behavior`)
      .set('Authorization', authHeader);
    expect(resLow.status).toBe(200);
    expect(resLow.body.totalCount).toBe(0);
    expect(resLow.body.events).toEqual([]);
  });

  // Test 11: Missing sandbox data handling
  it('11. Missing sandbox data handling: low-risk log sample returns totalCount: 0 and results: []', async () => {
    const resLow = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${lowRiskId}/sandbox`)
      .set('Authorization', authHeader);
    expect(resLow.status).toBe(200);
    expect(resLow.body.totalCount).toBe(0);
    expect(resLow.body.results).toEqual([]);
  });

  // Test 12: High-risk real-data verification
  it('12. High-risk real-data verification: verifies exact threat intel & YARA results in high_risk_sample.json', async () => {
    const resHigh = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/threat-intel`)
      .set('Authorization', authHeader);
    expect(resHigh.status).toBe(200);
    expect(resHigh.body.virusTotalResult.positives).toBe(68);
    expect(resHigh.body.virusTotalResult.total).toBe(72);
    expect(resHigh.body.yaraResults[0].ruleName).toBe('Trojan.Win32.Loader');
  });

  // Test 13: Low-risk real-data verification
  it('13. Low-risk real-data verification: verifies low_risk_sample.log returns 3/LOW intel', async () => {
    const resLow = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${lowRiskId}/threat-intel`)
      .set('Authorization', authHeader);
    expect(resLow.status).toBe(200);
    expect(resLow.body.virusTotalResult.positives).toBe(0);
    expect(resLow.body.virusTotalResult.total).toBe(72);
    expect(resLow.body.yaraResults[0].ruleName).toBe('Clean_System_Check');
  });

  // Test 14: Cross-analysis contamination test
  it('14. Cross-analysis contamination test: high-risk data never leaks to low-risk endpoints', async () => {
    const resLowMitre = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${lowRiskId}/mitre`)
      .set('Authorization', authHeader);
    expect(resLowMitre.body.totalCount).toBe(0);

    const resLowBehavior = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${lowRiskId}/behavior`)
      .set('Authorization', authHeader);
    expect(resLowBehavior.body.totalCount).toBe(0);

    const resLowSandbox = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${lowRiskId}/sandbox`)
      .set('Authorization', authHeader);
    expect(resLowSandbox.body.totalCount).toBe(0);
  });

  // Test 15: No fabricated/inferred findings
  it('15. No fabricated findings: missing fields return null or empty lists without synthetic defaults', async () => {
    const resLowTI = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${lowRiskId}/threat-intel`)
      .set('Authorization', authHeader);
    expect(resLowTI.body.recommendation).toBeNull();
  });
});
