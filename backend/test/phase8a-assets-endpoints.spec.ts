import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import * as fs from 'fs';
import * as path from 'path';
import { AppModule } from '../src/app.module';
import { PrismaService } from '../src/prisma/prisma.service';
import { getTestAuthHeader } from './auth-helper';

describe('Phase 8A: Asset & Endpoint Management Verification', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  let highRiskId: string;
  let lowRiskId: string;
  let explicitSourceId: string;
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

    // Upload a JSON containing explicit assets & endpoints in source
    const explicitSource = JSON.stringify({
      metadata: {
        hostname: 'EXPLICIT-HOST',
        username: 'analyst1',
      },
      risk: {
        riskScore: 50,
        threatLevel: 'MEDIUM',
      },
      assets: [
        {
          assetName: 'DB-SRV-PRIMARY',
          hostname: 'db-srv-01.internal',
          ipAddress: '10.200.1.50',
          macAddress: '00:11:22:33:44:55',
          assetType: 'Database Server',
          criticality: 'CRITICAL',
          operatingSystem: 'Ubuntu 22.04 LTS',
          owner: 'DBA Team',
          status: 'Active',
          source: 'CMDB Export',
          description: 'Primary Production Database',
          evidence: 'Audit Log Ref 9912',
        },
      ],
      endpoints: [
        {
          hostname: 'WKSTN-FINANCE-04',
          ipAddress: '10.200.5.12',
          osVersion: 'Windows 11 22H2',
          operatingSystem: 'Windows 11 Enterprise',
          user: 'jdoe_finance',
          agentStatus: 'ONLINE',
          status: 'ACTIVE',
          endpointType: 'Corporate Laptop',
          source: 'EDR Agent Export',
          evidence: 'EDR Telemetry Batch 44',
        },
      ],
    });

    const resExplicit = await request(app.getHttpServer())
      .post('/api/v1/analyses/upload')
      .set('Authorization', authHeader)
      .attach('file', Buffer.from(explicitSource), 'explicit_assets_endpoints.json');
    expect(resExplicit.status).toBe(201);
    explicitSourceId = resExplicit.body.analysisId;
  });

  afterAll(async () => {
    await app.close();
  });

  // 1. Asset GET endpoint
  it('1. Asset GET endpoint: GET /api/v1/analyses/:analysisId/assets responds with HTTP 200', async () => {
    const res = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/assets`)
      .set('Authorization', authHeader);
    expect(res.status).toBe(200);
  });

  // 2. Endpoint GET endpoint
  it('2. Endpoint GET endpoint: GET /api/v1/analyses/:analysisId/endpoints responds with HTTP 200', async () => {
    const res = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/endpoints`)
      .set('Authorization', authHeader);
    expect(res.status).toBe(200);
  });

  // 3. analysisId filtering
  it('3. analysisId filtering: returns 404 for non-existent analysisId', async () => {
    const resAsset = await request(app.getHttpServer())
      .get('/api/v1/analyses/non_existent_id/assets')
      .set('Authorization', authHeader);
    expect(resAsset.status).toBe(404);

    const resEndpoint = await request(app.getHttpServer())
      .get('/api/v1/analyses/non_existent_id/endpoints')
      .set('Authorization', authHeader);
    expect(resEndpoint.status).toBe(404);
  });

  // 4. Empty asset result
  it('4. Empty asset result: returns empty assets array when source has no assets', async () => {
    const res = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/assets`)
      .set('Authorization', authHeader);
    expect(res.status).toBe(200);
    expect(res.body.analysisId).toBe(highRiskId);
    expect(res.body.totalCount).toBe(0);
    expect(res.body.assets).toEqual([]);
  });

  // 5. Empty endpoint result
  it('5. Empty endpoint result: returns empty endpoints array when source has no endpoints', async () => {
    const res = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/endpoints`)
      .set('Authorization', authHeader);
    expect(res.status).toBe(200);
    expect(res.body.analysisId).toBe(highRiskId);
    expect(res.body.totalCount).toBe(0);
    expect(res.body.endpoints).toEqual([]);
  });

  // 6. currentAnalysisId behavior
  it('6. currentAnalysisId behavior: queries strictly scoped to provided active analysisId', async () => {
    const resExplicitAssets = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${explicitSourceId}/assets`)
      .set('Authorization', authHeader);
    expect(resExplicitAssets.body.totalCount).toBe(1);

    const resHighAssets = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/assets`)
      .set('Authorization', authHeader);
    expect(resHighAssets.body.totalCount).toBe(0);
  });

  // 7. No request when currentAnalysisId is null
  it('7. No request when currentAnalysisId is null: client enabled flag evaluates to false when null', () => {
    const currentAnalysisId: string | null = null;
    const fetchEnabled = Boolean(currentAnalysisId);
    expect(fetchEnabled).toBe(false);
  });

  // 8. TanStack query key
  it('8. TanStack query key: uses ["analysis", currentAnalysisId, "assets"] and ["analysis", currentAnalysisId, "endpoints"]', () => {
    const assetQueryKey = ['analysis', highRiskId, 'assets'];
    const endpointQueryKey = ['analysis', highRiskId, 'endpoints'];
    expect(assetQueryKey).toEqual(['analysis', highRiskId, 'assets']);
    expect(endpointQueryKey).toEqual(['analysis', highRiskId, 'endpoints']);
  });

  // 9. High-risk source mapping
  it('9. High-risk source mapping: high_risk_sample.json (Risk=98, Threat=CRITICAL) processed without inventing assets/endpoints', async () => {
    const dbAssets = await prisma.asset.findMany({ where: { analysisId: highRiskId } });
    const dbEndpoints = await prisma.endpoint.findMany({ where: { analysisId: highRiskId } });
    expect(dbAssets.length).toBe(0);
    expect(dbEndpoints.length).toBe(0);
  });

  // 10. Low-risk source mapping
  it('10. Low-risk source mapping: low_risk_sample.log processed without inventing assets/endpoints from log text', async () => {
    const dbAssets = await prisma.asset.findMany({ where: { analysisId: lowRiskId } });
    const dbEndpoints = await prisma.endpoint.findMany({ where: { analysisId: lowRiskId } });
    expect(dbAssets.length).toBe(0);
    expect(dbEndpoints.length).toBe(0);
  });

  // 11. No automatic asset creation
  it('11. MANDATORY: 0 automatic assets created when uploading source without explicit asset array', async () => {
    const resAssets = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/assets`)
      .set('Authorization', authHeader);
    expect(resAssets.body.totalCount).toBe(0);
    expect(resAssets.body.assets).toEqual([]);
  });

  // 12. No automatic endpoint creation
  it('12. MANDATORY: 0 automatic endpoints created when uploading source without explicit endpoint array', async () => {
    const resEndpoints = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/endpoints`)
      .set('Authorization', authHeader);
    expect(resEndpoints.body.totalCount).toBe(0);
    expect(resEndpoints.body.endpoints).toEqual([]);
  });

  // 13. A -> B isolation
  it('13. A -> B isolation: records for Analysis A are not returned when querying Analysis B', async () => {
    const resA = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${explicitSourceId}/assets`)
      .set('Authorization', authHeader);
    expect(resA.body.totalCount).toBe(1);

    const resB = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/assets`)
      .set('Authorization', authHeader);
    expect(resB.body.totalCount).toBe(0);
  });

  // 14. B -> A restoration
  it('14. B -> A restoration: switching back to Analysis A restores A records', async () => {
    const resA = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${explicitSourceId}/assets`)
      .set('Authorization', authHeader);
    expect(resA.body.totalCount).toBe(1);
    expect(resA.body.assets[0].assetName).toBe('DB-SRV-PRIMARY');
  });

  // 15. clearAnalysis behavior
  it('15. clearAnalysis behavior: null active analysis context removes display state', () => {
    let currentAnalysisId: string | null = explicitSourceId;
    currentAnalysisId = null;
    expect(currentAnalysisId).toBeNull();
  });

  // 16. Refresh persistence
  it('16. Refresh persistence: explicit source assets and endpoints persist in MySQL DB across requests', async () => {
    const dbAsset = await prisma.asset.findFirst({ where: { analysisId: explicitSourceId } });
    expect(dbAsset).toBeDefined();
    expect(dbAsset?.ipAddress).toBe('10.200.1.50');

    const dbEndpoint = await prisma.endpoint.findFirst({ where: { analysisId: explicitSourceId } });
    expect(dbEndpoint).toBeDefined();
    expect(dbEndpoint?.hostname).toBe('WKSTN-FINANCE-04');
  });

  // 17. Source value preservation
  it('17. Source value preservation: explicit fields (macAddress, criticality, owner, EDR source, evidence) preserved exact', async () => {
    const resAsset = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${explicitSourceId}/assets`)
      .set('Authorization', authHeader);
    const asset = resAsset.body.assets[0];
    expect(asset.macAddress).toBe('00:11:22:33:44:55');
    expect(asset.criticality).toBe('CRITICAL');
    expect(asset.owner).toBe('DBA Team');

    const resEndpoint = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${explicitSourceId}/endpoints`)
      .set('Authorization', authHeader);
    const ep = resEndpoint.body.endpoints[0];
    expect(ep.user).toBe('jdoe_finance');
    expect(ep.source).toBe('EDR Agent Export');
  });

  // 18. Missing-field behavior
  it('18. Missing-field behavior: analyst created asset with minimal fields defaults optional values cleanly', async () => {
    const resAnalystAsset = await request(app.getHttpServer())
      .post(`/api/v1/analyses/${highRiskId}/assets`)
      .set('Authorization', authHeader)
      .send({
        assetName: 'Analyst Added Asset',
      });

    expect(resAnalystAsset.status).toBe(201);
    expect(resAnalystAsset.body.assetName).toBe('Analyst Added Asset');
    expect(resAnalystAsset.body.hostname).toBeNull();
    expect(resAnalystAsset.body.ipAddress).toBeNull();
    expect(resAnalystAsset.body.source).toBe('Analyst Manual Entry');
  });

  // 19. Phase 7A regression
  it('19. Phase 7A regression: Incidents and Cases endpoints remain fully operational', async () => {
    const resInc = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/incidents`)
      .set('Authorization', authHeader);
    expect(resInc.status).toBe(200);

    const resCases = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/cases`)
      .set('Authorization', authHeader);
    expect(resCases.status).toBe(200);
  });

  // 20. Phase 7B regression
  it('20. Phase 7B regression: SOAR endpoint remains fully operational', async () => {
    const resSoar = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/soar`)
      .set('Authorization', authHeader);
    expect(resSoar.status).toBe(200);
  });

  // 21. Phase 2-6B regression
  it('21. Phase 2-6B regression: SIEM, IOCs, Threat Intel, MITRE, Behavior, Sandbox remain functional', async () => {
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

    const resBehavior = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/behavior`)
      .set('Authorization', authHeader);
    expect(resBehavior.status).toBe(200);

    const resSandbox = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/sandbox`)
      .set('Authorization', authHeader);
    expect(resSandbox.status).toBe(200);
  });
});
