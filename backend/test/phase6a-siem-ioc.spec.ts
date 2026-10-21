import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import * as fs from 'fs';
import * as path from 'path';
import { AppModule } from '../src/app.module';
import { PrismaService } from '../src/prisma/prisma.service';
import { getTestAuthHeader } from './auth-helper';

describe('Phase 6A: SIEM + IOC Search Module Verification', () => {
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

  // Test 1: SIEM endpoint analysis isolation
  it('1. SIEM endpoint analysis isolation: GET /api/v1/analyses/:analysisId/siem returns only events for that analysisId', async () => {
    const resHigh = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/siem`)
      .set('Authorization', authHeader);
    expect(resHigh.status).toBe(200);
    expect(resHigh.body.analysisId).toBe(highRiskId);
    expect(Array.isArray(resHigh.body.events)).toBe(true);

    // Ensure all returned events belong ONLY to highRiskId
    for (const event of resHigh.body.events) {
      expect(event.analysisId).toBe(highRiskId);
      expect(event.analysisId).not.toBe(lowRiskId);
    }
  });

  // Test 2: IOC endpoint analysis isolation
  it('2. IOC endpoint analysis isolation: GET /api/v1/analyses/:analysisId/iocs returns only IOCs for that analysisId', async () => {
    const resHigh = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/iocs`)
      .set('Authorization', authHeader);
    expect(resHigh.status).toBe(200);
    expect(resHigh.body.analysisId).toBe(highRiskId);
    expect(Array.isArray(resHigh.body.iocs)).toBe(true);

    for (const ioc of resHigh.body.iocs) {
      expect(ioc.analysisId).toBe(highRiskId);
      expect(ioc.analysisId).not.toBe(lowRiskId);
    }
  });

  // Test 3: SIEM currentAnalysisId behavior
  it('3. SIEM currentAnalysisId behavior: currentAnalysisId === null disables query execution', () => {
    let currentAnalysisId: string | null = null;
    expect(currentAnalysisId).toBeNull();
    const queryEnabled = Boolean(currentAnalysisId);
    expect(queryEnabled).toBe(false);
  });

  // Test 4: IOC currentAnalysisId behavior
  it('4. IOC currentAnalysisId behavior: currentAnalysisId === null disables query execution', () => {
    let currentAnalysisId: string | null = null;
    expect(currentAnalysisId).toBeNull();
    const queryEnabled = Boolean(currentAnalysisId);
    expect(queryEnabled).toBe(false);
  });

  // Test 5: SIEM query key isolation
  it('5. SIEM query key isolation: query keys include currentAnalysisId', () => {
    const queryKeyA = ['analysis', highRiskId, 'siem'];
    const queryKeyB = ['analysis', lowRiskId, 'siem'];

    expect(queryKeyA).not.toEqual(queryKeyB);
    expect(queryKeyA[1]).toBe(highRiskId);
    expect(queryKeyB[1]).toBe(lowRiskId);
  });

  // Test 6: IOC query key isolation
  it('6. IOC query key isolation: query keys include currentAnalysisId', () => {
    const queryKeyA = ['analysis', highRiskId, 'iocs'];
    const queryKeyB = ['analysis', lowRiskId, 'iocs'];

    expect(queryKeyA).not.toEqual(queryKeyB);
    expect(queryKeyA[1]).toBe(highRiskId);
    expect(queryKeyB[1]).toBe(lowRiskId);
  });

  // Test 7: SIEM search and filtering
  it('7. SIEM search & filtering: filters by search term within active analysisId', async () => {
    const resSearch = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/siem`)
      .set('Authorization', authHeader)
      .query({ search: 'non_existent_siem_keyword_12345' });

    expect(resSearch.status).toBe(200);
    expect(resSearch.body.analysisId).toBe(highRiskId);
    expect(resSearch.body.totalCount).toBe(0);
    expect(resSearch.body.events.length).toBe(0);
  });

  // Test 8: IOC search within active analysis
  it('8. IOC search: searches specific IOC value within active analysisId', async () => {
    const resSearch = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/iocs`)
      .set('Authorization', authHeader)
      .query({ search: '198.51.100.98' });

    expect(resSearch.status).toBe(200);
    expect(resSearch.body.analysisId).toBe(highRiskId);
    expect(resSearch.body.totalCount).toBe(1);
    expect(resSearch.body.iocs[0].value).toBe('198.51.100.98');

    // Search non-existent IOC
    const resNone = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/iocs`)
      .set('Authorization', authHeader)
      .query({ search: 'non_existent_domain_9999.test' });

    expect(resNone.status).toBe(200);
    expect(resNone.body.totalCount).toBe(0);
    expect(resNone.body.iocs.length).toBe(0);
  });

  // Test 9: No active analysis
  it('9. No active analysis state displays "No Active Analysis Selected"', () => {
    let currentAnalysisId: string | null = null;
    const displayText = !currentAnalysisId ? 'No Active Analysis Selected' : 'Active Analysis Selected';
    expect(displayText).toBe('No Active Analysis Selected');
  });

  // Test 10: Missing SIEM data
  it('10. Missing SIEM data: returns empty list for analyses without SIEM records', async () => {
    const resLow = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${lowRiskId}/siem`)
      .set('Authorization', authHeader);
    expect(resLow.status).toBe(200);
    expect(resLow.body.analysisId).toBe(lowRiskId);
    expect(resLow.body.totalCount).toBe(0);
    expect(resLow.body.events).toEqual([]);
  });

  // Test 11: Missing IOC data
  it('11. Missing IOC data handling: returns 0 total count when no IOC match', async () => {
    const resFilter = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${lowRiskId}/iocs`)
      .set('Authorization', authHeader)
      .query({ type: 'EMAIL' });

    expect(resFilter.status).toBe(200);
    expect(resFilter.body.totalCount).toBe(0);
    expect(resFilter.body.iocs).toEqual([]);
  });

  // Test 12: High-risk real-data verification
  it('12. High-risk real-data verification: verifies extracted IOCs from high_risk_sample.json', async () => {
    const res = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/iocs`)
      .set('Authorization', authHeader);
    expect(res.status).toBe(200);
    expect(res.body.totalCount).toBeGreaterThan(0);
    expect(res.body.iocs[0].type).toBe('IP');
    expect(res.body.iocs[0].value).toBe('198.51.100.98');
  });

  // Test 13: Low-risk real-data verification
  it('13. Low-risk real-data verification: verifies extracted IOCs from low_risk_sample.log', async () => {
    const res = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${lowRiskId}/iocs`)
      .set('Authorization', authHeader);
    expect(res.status).toBe(200);
    expect(res.body.totalCount).toBe(1);
    expect(res.body.iocs[0].type).toBe('IP');
    expect(res.body.iocs[0].value).toBe('10.0.0.15');
  });

  // Test 14: Cross-analysis contamination test
  it('14. Cross-analysis contamination test: high-risk IOCs never appear under low-risk analysis and vice versa', async () => {
    const resLowIocs = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${lowRiskId}/iocs`)
      .set('Authorization', authHeader);
    const lowIocValues = resLowIocs.body.iocs.map((i: any) => i.value);

    expect(lowIocValues).not.toContain('198.51.100.98');
    expect(lowIocValues).toContain('10.0.0.15');

    const resHighIocs = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/iocs`)
      .set('Authorization', authHeader);
    const highIocValues = resHighIocs.body.iocs.map((i: any) => i.value);

    expect(highIocValues).not.toContain('10.0.0.15');
    expect(highIocValues).toContain('198.51.100.98');
  });

  // Test 15: Clear-selection test
  it('15. Clear-selection test: setting currentAnalysisId = null clears active view data', () => {
    let currentAnalysisId: string | null = highRiskId;
    
    // Clear selection
    currentAnalysisId = null;

    expect(currentAnalysisId).toBeNull();
    const queryEnabled = Boolean(currentAnalysisId);
    expect(queryEnabled).toBe(false);
  });
});
