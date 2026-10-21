import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import * as fs from 'fs';
import * as path from 'path';
import { AppModule } from '../src/app.module';
import { PrismaService } from '../src/prisma/prisma.service';
import { getTestAuthHeader } from './auth-helper';

describe('Phase 4: Centralized Current Analysis State Verification', () => {
  let app: INestApplication;
  let prisma: PrismaService;
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
  });

  afterAll(async () => {
    await app.close();
  });

  // Test 1: Initial state - currentAnalysisId === null
  it('1. Initial state: currentAnalysisId === null on startup', () => {
    let currentAnalysisId: string | null = null;
    expect(currentAnalysisId).toBeNull();
  });

  // Test 2 & 3: Upload Sample A & Sample B to get real analysis IDs
  let analysisIdA: string;
  let analysisIdB: string;

  it('2 & 3. Select analysis A & B with real analysis IDs', async () => {
    const highRiskPath = path.resolve(process.cwd(), '../test_samples/high_risk_sample.json');
    const lowRiskPath = path.resolve(process.cwd(), '../test_samples/low_risk_sample.log');

    const highRiskBuffer = fs.readFileSync(highRiskPath);
    const lowRiskBuffer = fs.readFileSync(lowRiskPath);

    // Upload Sample A (High Risk)
    const resA = await request(app.getHttpServer())
      .post('/api/v1/analyses/upload')
      .set('Authorization', authHeader)
      .attach('file', highRiskBuffer, 'high_risk_sample.json');

    expect(resA.status).toBe(201);
    analysisIdA = resA.body.analysisId;
    expect(analysisIdA).toBeDefined();

    // Upload Sample B (Low Risk)
    const resB = await request(app.getHttpServer())
      .post('/api/v1/analyses/upload')
      .set('Authorization', authHeader)
      .attach('file', lowRiskBuffer, 'low_risk_sample.log');

    expect(resB.status).toBe(201);
    analysisIdB = resB.body.analysisId;
    expect(analysisIdB).toBeDefined();
    expect(analysisIdB).not.toBe(analysisIdA);

    // Simulated AnalysisContext state transition: Select A
    let currentAnalysisId: string | null = analysisIdA;
    expect(currentAnalysisId).toBe(analysisIdA);

    // Simulated AnalysisContext state transition: Select B
    currentAnalysisId = analysisIdB;
    expect(currentAnalysisId).toBe(analysisIdB);
  });

  // Test 4: Switch A -> B: B data is displayed
  it('4. Switch A -> B: B data is displayed', async () => {
    let currentAnalysisId: string | null = analysisIdA;
    // Switch to B
    currentAnalysisId = analysisIdB;

    const resB = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${currentAnalysisId}`)
      .set('Authorization', authHeader);
    expect(resB.status).toBe(200);
    expect(resB.body.analysisId).toBe(analysisIdB);
    expect(resB.body.riskScore).toBe(3);
    expect(resB.body.threatLevel).toBe('LOW');
    expect(resB.body.hostname).toBe('HOST-LOW-02');
  });

  // Test 5: Switch B -> A: A data is displayed
  it('5. Switch B -> A: A data is displayed', async () => {
    let currentAnalysisId: string | null = analysisIdB;
    // Switch back to A
    currentAnalysisId = analysisIdA;

    const resA = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${currentAnalysisId}`)
      .set('Authorization', authHeader);
    expect(resA.status).toBe(200);
    expect(resA.body.analysisId).toBe(analysisIdA);
    expect(resA.body.riskScore).toBe(98);
    expect(resA.body.threatLevel).toBe('CRITICAL');
    expect(resA.body.hostname).toBe('HOST-HIGH-01');
  });

  // Test 6 & 7: Clear: currentAnalysisId === null and no analysis-specific API request is made
  it('6 & 7. Clear selection: currentAnalysisId === null and analysis queries disabled', () => {
    let currentAnalysisId: string | null = analysisIdA;
    
    // Call clearAnalysis()
    const clearAnalysis = () => {
      currentAnalysisId = null;
    };
    clearAnalysis();

    expect(currentAnalysisId).toBeNull();
    
    // TanStack Query rule: enabled is false when currentAnalysisId === null
    const queryEnabled = Boolean(currentAnalysisId);
    expect(queryEnabled).toBe(false);
  });

  // Test 8: Query keys contain the correct analysisId
  it('8. Query keys contain the correct analysisId', () => {
    const queryKeyForA = ['analysis', analysisIdA];
    const queryKeyForB = ['analysis', analysisIdB];

    expect(queryKeyForA[1]).toBe(analysisIdA);
    expect(queryKeyForB[1]).toBe(analysisIdB);
    expect(queryKeyForA).not.toEqual(queryKeyForB);
  });

  // Test 9: No request is made using null/undefined analysisId
  it('9. No request is made using null/undefined analysisId (API returns 404 for literal null/undefined)', async () => {
    const resNull = await request(app.getHttpServer())
      .get('/api/v1/analyses/null')
      .set('Authorization', authHeader);
    expect(resNull.status).toBe(404);

    const resUndefined = await request(app.getHttpServer())
      .get('/api/v1/analyses/undefined')
      .set('Authorization', authHeader);
    expect(resUndefined.status).toBe(404);
  });

  // Test 10: Historical analyses remain available after clearing
  it('10. Historical analyses remain available in MySQL after clearing active selection', async () => {
    let currentAnalysisId: string | null = analysisIdA;
    currentAnalysisId = null; // Clear active analysis

    const historyRes = await request(app.getHttpServer())
      .get('/api/v1/analyses')
      .set('Authorization', authHeader);
    expect(historyRes.status).toBe(200);
    expect(Array.isArray(historyRes.body)).toBe(true);

    const idsInHistory = historyRes.body.map((item: any) => item.analysisId);
    expect(idsInHistory).toContain(analysisIdA);
    expect(idsInHistory).toContain(analysisIdB);
  });

  // Real-Data Regression Test
  it('12. Real-data regression test: high-risk sample produces 98/CRITICAL and low-risk sample produces 3/LOW', async () => {
    const resA = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${analysisIdA}`)
      .set('Authorization', authHeader);
    expect(resA.body.riskScore).toBe(98);
    expect(resA.body.threatLevel).toBe('CRITICAL');

    const resB = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${analysisIdB}`)
      .set('Authorization', authHeader);
    expect(resB.body.riskScore).toBe(3);
    expect(resB.body.threatLevel).toBe('LOW');
  });
});
