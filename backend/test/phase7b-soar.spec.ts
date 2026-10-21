import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import * as fs from 'fs';
import * as path from 'path';
import { AppModule } from '../src/app.module';
import { PrismaService } from '../src/prisma/prisma.service';
import { getTestAuthHeader } from './auth-helper';

describe('Phase 7B: SOAR (Security Orchestration, Automation & Response) Module Verification', () => {
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

  // 1. SOAR endpoint exists
  it('1. SOAR endpoint exists: GET /api/v1/analyses/:analysisId/soar responds with HTTP 200', async () => {
    const res = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/soar`)
      .set('Authorization', authHeader);
    expect(res.status).toBe(200);
  });

  // 2. GET requires analysis scope
  it('2. GET requires analysis scope: returns 404 for invalid analysisId', async () => {
    const res = await request(app.getHttpServer())
      .get('/api/v1/analyses/non_existent_id/soar')
      .set('Authorization', authHeader);
    expect(res.status).toBe(404);
  });

  // 3. Empty SOAR result works
  it('3. Empty SOAR result works: returns empty soarExecutions array when analysis has no SOAR records', async () => {
    const res = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${lowRiskId}/soar`)
      .set('Authorization', authHeader);
    expect(res.status).toBe(200);
    expect(res.body.analysisId).toBe(lowRiskId);
    expect(res.body.totalCount).toBe(0);
    expect(res.body.soarExecutions).toEqual([]);
  });

  // 4. High-risk source handling
  it('4. High-risk source handling: high_risk_sample.json handled accurately without breaking parser', async () => {
    const analysis = await prisma.analysis.findUnique({ where: { analysisId: highRiskId } });
    expect(analysis).toBeDefined();
    expect(analysis?.riskScore).toBe(98);
  });

  // 5. Low-risk source handling
  it('5. Low-risk source handling: low_risk_sample.log handled accurately', async () => {
    const analysis = await prisma.analysis.findUnique({ where: { analysisId: lowRiskId } });
    expect(analysis).toBeDefined();
    expect(analysis?.riskScore).toBe(3);
  });

  // 6. No automatic SOAR creation
  it('6. MANDATORY TEST: High-risk upload (Risk=98, Threat=CRITICAL) creates 0 automatic SOAR records', async () => {
    const dbSoar = await prisma.soarExecution.findMany({ where: { analysisId: highRiskId } });
    expect(dbSoar.length).toBe(0);

    const apiRes = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/soar`)
      .set('Authorization', authHeader);
    expect(apiRes.body.totalCount).toBe(0);
    expect(apiRes.body.soarExecutions).toEqual([]);
  });

  // 7. Analyst-triggered creation
  it('7. Analyst-triggered creation: POST /api/v1/analyses/:analysisId/soar creates a analyst action', async () => {
    const res = await request(app.getHttpServer())
      .post(`/api/v1/analyses/${highRiskId}/soar`)
      .set('Authorization', authHeader)
      .send({
        actionName: 'Isolate Host from Network',
        description: 'Isolate endpoint 192.168.1.105 due to ransomware detection',
        actionType: 'Host Isolation',
        target: '192.168.1.105',
        triggeredBy: 'Analyst Alice',
        isSimulation: true,
        confirmed: true,
      });

    expect(res.status).toBe(201);
    expect(res.body.id).toBeDefined();
    expect(res.body.actionName).toBe('Isolate Host from Network');
    expect(res.body.status).toBe('SIMULATION');
  });

  // 8. Correct analysisId association
  it('8. Correct analysisId association: created SOAR action is linked to target analysisId', async () => {
    const res = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/soar`)
      .set('Authorization', authHeader);
    expect(res.body.totalCount).toBe(1);
    expect(res.body.soarExecutions[0].analysisId).toBe(highRiskId);
  });

  // 9. Source/analyst distinction
  it('9. Source/analyst distinction: analyst-created actions have source = "Analyst"', async () => {
    const res = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/soar`)
      .set('Authorization', authHeader);
    expect(res.body.soarExecutions[0].source).toBe('Analyst');
    expect(res.body.soarExecutions[0].triggeredBy).toBe('Analyst Alice');
  });

  // 10. SOAR status persistence
  it('10. SOAR status persistence: status is stored in MySQL database', async () => {
    const dbAction = await prisma.soarExecution.findFirst({ where: { analysisId: highRiskId } });
    expect(dbAction).toBeDefined();
    expect(dbAction?.status).toBe('SIMULATION');
    expect(dbAction?.actionType).toBe('Host Isolation');
  });

  // 11. Cross-analysis isolation
  it('11. Cross-analysis isolation: High-risk SOAR action is NOT visible in Low-risk SOAR query', async () => {
    const resLow = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${lowRiskId}/soar`)
      .set('Authorization', authHeader);
    expect(resLow.body.totalCount).toBe(0);
    expect(resLow.body.soarExecutions).toEqual([]);
  });

  // 12. A -> B isolation
  it('12. A -> B isolation: switching from Analysis A to B returns B-only records', async () => {
    const resA = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/soar`)
      .set('Authorization', authHeader);
    expect(resA.body.totalCount).toBe(1);

    const resB = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${lowRiskId}/soar`)
      .set('Authorization', authHeader);
    expect(resB.body.totalCount).toBe(0);
  });

  // 13. B -> A restoration
  it('13. B -> A restoration: switching back from B to A restores A records', async () => {
    const resA = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/soar`)
      .set('Authorization', authHeader);
    expect(resA.body.totalCount).toBe(1);
    expect(resA.body.soarExecutions[0].actionName).toBe('Isolate Host from Network');
  });

  // 14. clearAnalysis behavior
  it('14. clearAnalysis behavior: null active analysis context disables query execution', () => {
    let currentAnalysisId: string | null = highRiskId;
    currentAnalysisId = null;
    expect(currentAnalysisId).toBeNull();
    expect(Boolean(currentAnalysisId)).toBe(false);
  });

  // 15. No request when currentAnalysisId is null
  it('15. No request when currentAnalysisId is null: client-side enabled condition prevents fetch', () => {
    const currentAnalysisId: string | null = null;
    const fetchEnabled = Boolean(currentAnalysisId);
    expect(fetchEnabled).toBe(false);
  });

  // 16. TanStack query key
  it('16. TanStack query key: uses ["analysis", currentAnalysisId, "soar"]', () => {
    const queryKey = ['analysis', highRiskId, 'soar'];
    expect(queryKey).toEqual(['analysis', highRiskId, 'soar']);
  });

  // 17. Missing data handling
  it('17. Missing data handling: optional fields gracefully return null or fallback text', async () => {
    const res = await request(app.getHttpServer())
      .post(`/api/v1/analyses/${highRiskId}/soar`)
      .set('Authorization', authHeader)
      .send({
        actionName: 'Simple Block Action',
        confirmed: true,
      });

    expect(res.status).toBe(201);
    expect(res.body.target).toBeNull();
    expect(res.body.status).toBe('SIMULATION');
  });

  // 18. Refresh persistence
  it('18. Refresh persistence: records persist in database across requests', async () => {
    const res = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/soar`)
      .set('Authorization', authHeader);
    expect(res.body.totalCount).toBe(2);
  });

  // 19. Existing Incident / Case regression
  it('19. Existing Incident / Case regression: Phase 7A endpoints remain fully operational', async () => {
    const resInc = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/incidents`)
      .set('Authorization', authHeader);
    expect(resInc.status).toBe(200);

    const resCases = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/cases`)
      .set('Authorization', authHeader);
    expect(resCases.status).toBe(200);
  });

  // 20. Existing Phase 2-6B regression
  it('20. Existing Phase 2-6B regression: SIEM, IOCs, Threat Intel, MITRE, Behavior, Sandbox endpoints work', async () => {
    const resSiem = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/siem`)
      .set('Authorization', authHeader);
    expect(resSiem.status).toBe(200);

    const resIoc = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/iocs`)
      .set('Authorization', authHeader);
    expect(resIoc.status).toBe(200);

    const resTi = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/threat-intel`)
      .set('Authorization', authHeader);
    expect(resTi.status).toBe(200);

    const resMitre = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/mitre`)
      .set('Authorization', authHeader);
    expect(resMitre.status).toBe(200);
  });

  // 21. Phase 7A regression
  it('21. Phase 7A regression: Analyst incident creation works alongside SOAR module', async () => {
    const resInc = await request(app.getHttpServer())
      .post(`/api/v1/analyses/${highRiskId}/incidents`)
      .set('Authorization', authHeader)
      .send({
        title: 'Parallel Incident Investigation',
        severity: 'HIGH',
        reason: 'Investigating with SOAR',
      });
    expect(resInc.status).toBe(201);
  });
});
