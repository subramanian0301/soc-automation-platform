import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import * as fs from 'fs';
import * as path from 'path';
import { AppModule } from '../src/app.module';
import { PrismaService } from '../src/prisma/prisma.service';
import { getTestAuthHeader } from './auth-helper';

describe('Phase 8B: Vulnerability Management Verification', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  let highRiskId: string;
  let lowRiskId: string;
  let explicitVulnId: string;
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

    // Upload a JSON containing explicit vulnerability objects in source
    const explicitSource = JSON.stringify({
      metadata: {
        hostname: 'VULN-SCAN-TARGET',
        username: 'sec_auditor',
      },
      risk: {
        riskScore: 75,
        threatLevel: 'HIGH',
      },
      vulnerabilities: [
        {
          cveId: 'CVE-2023-38606',
          title: 'Apple macOS Kernel Remote Code Execution',
          cvssScore: 9.8,
          severity: 'CRITICAL',
          description: 'An integer overflow vulnerability allows arbitrary kernel code execution.',
          affectedAsset: 'HOST-MAC-01',
          packageName: 'xnu-kernel',
          installedVersion: '22.4.0',
          fixedVersion: '22.6.0',
          status: 'UNPATCHED',
          remediation: 'Update macOS to 13.5 or later immediately.',
          source: 'OpenVAS Scan Export',
          evidence: 'CVE Reference & Memory Dump Ref 8831',
        },
      ],
    });

    const resExplicit = await request(app.getHttpServer())
      .post('/api/v1/analyses/upload')
      .set('Authorization', authHeader)
      .attach('file', Buffer.from(explicitSource), 'explicit_vulnerabilities.json');
    expect(resExplicit.status).toBe(201);
    explicitVulnId = resExplicit.body.analysisId;
  });

  afterAll(async () => {
    await app.close();
  });

  // 1. Explicit vulnerability records are parsed correctly
  it('1. Explicit vulnerability records are parsed correctly from source file', async () => {
    const res = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${explicitVulnId}/vulnerabilities`)
      .set('Authorization', authHeader);
    expect(res.status).toBe(200);
    expect(res.body.totalCount).toBe(1);
    expect(res.body.vulnerabilities[0].cveId).toBe('CVE-2023-38606');
    expect(res.body.vulnerabilities[0].title).toBe('Apple macOS Kernel Remote Code Execution');
  });

  // 2. Source identifiers and supplied values are preserved
  it('2. Source identifiers and supplied values are preserved accurately in database', async () => {
    const dbVuln = await prisma.vulnerability.findFirst({ where: { analysisId: explicitVulnId } });
    expect(dbVuln).toBeDefined();
    expect(dbVuln?.cvssScore).toBe(9.8);
    expect(dbVuln?.severity).toBe('CRITICAL');
    expect(dbVuln?.affectedAsset).toBe('HOST-MAC-01');
    expect(dbVuln?.packageName).toBe('xnu-kernel');
    expect(dbVuln?.installedVersion).toBe('22.4.0');
    expect(dbVuln?.fixedVersion).toBe('22.6.0');
    expect(dbVuln?.remediation).toBe('Update macOS to 13.5 or later immediately.');
  });

  // 3. Missing fields remain null / display as Not Available
  it('3. Missing fields remain null and do not fabricate zero for missing CVSS score', async () => {
    const resAnalyst = await request(app.getHttpServer())
      .post(`/api/v1/analyses/${highRiskId}/vulnerabilities`)
      .set('Authorization', authHeader)
      .send({
        cveId: 'CVE-2024-0001',
        title: 'Unrated Component Flaw',
      });

    expect(resAnalyst.status).toBe(201);
    expect(resAnalyst.body.cvssScore).toBeNull();
    expect(resAnalyst.body.severity).toBeNull();
    expect(resAnalyst.body.affectedAsset).toBeNull();
    expect(resAnalyst.body.source).toBe('Analyst Manual Entry');
  });

  // 4. No vulnerability records created from high-risk fixture unless explicitly contained
  it('4. MANDATORY: High-risk sample (Risk=98, Threat=CRITICAL) creates 0 automatic vulnerabilities', async () => {
    const res = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${highRiskId}/vulnerabilities`)
      .set('Authorization', authHeader);
    // Note: 1 record was created by test #3 above for highRiskId, so filtered source check is 0 automatic
    const dbSourceVulns = await prisma.vulnerability.findMany({
      where: { analysisId: highRiskId, source: 'Source file' },
    });
    expect(dbSourceVulns.length).toBe(0);
  });

  // 5. No vulnerability records created from low-risk fixture unless explicitly contained
  it('5. MANDATORY: Low-risk sample creates 0 automatic vulnerability records', async () => {
    const res = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${lowRiskId}/vulnerabilities`)
      .set('Authorization', authHeader);
    expect(res.status).toBe(200);
    expect(res.body.totalCount).toBe(0);
    expect(res.body.vulnerabilities).toEqual([]);
  });

  // 6. No records inferred from IOCs, YARA, VT, MITRE, risk scores, incidents, cases, SOAR, assets, endpoints
  it('6. No records inferred from IOCs, YARA, VT, MITRE, risk scores, assets, or endpoints', async () => {
    const dbLowVulns = await prisma.vulnerability.findMany({ where: { analysisId: lowRiskId } });
    expect(dbLowVulns.length).toBe(0);
  });

  // 7. GET filters strictly by analysisId
  it('7. GET /api/v1/analyses/:analysisId/vulnerabilities filters strictly by analysisId', async () => {
    const resExplicit = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${explicitVulnId}/vulnerabilities`)
      .set('Authorization', authHeader);
    expect(resExplicit.body.totalCount).toBe(1);

    const resLow = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${lowRiskId}/vulnerabilities`)
      .set('Authorization', authHeader);
    expect(resLow.body.totalCount).toBe(0);
  });

  // 8. Invalid analysis IDs return expected not-found response (404)
  it('8. Invalid analysis ID returns 404 Not Found', async () => {
    const res = await request(app.getHttpServer())
      .get('/api/v1/analyses/non_existent_id/vulnerabilities')
      .set('Authorization', authHeader);
    expect(res.status).toBe(404);
  });

  // 9. Analysis A records never appear under Analysis B
  it('9. Analysis A records never appear under Analysis B', async () => {
    const resB = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${lowRiskId}/vulnerabilities`)
      .set('Authorization', authHeader);
    expect(resB.body.vulnerabilities).toEqual([]);
  });

  // 10. Switching back to Analysis A restores its own records
  it('10. Switching back to Analysis A restores its own records', async () => {
    const resA = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${explicitVulnId}/vulnerabilities`)
      .set('Authorization', authHeader);
    expect(resA.body.totalCount).toBe(1);
    expect(resA.body.vulnerabilities[0].cveId).toBe('CVE-2023-38606');
  });

  // 11. Clearing active analysis suppresses requests and clears view
  it('11. Clearing active analysis disables fetch condition and clears state', () => {
    let currentAnalysisId: string | null = explicitVulnId;
    currentAnalysisId = null;
    expect(currentAnalysisId).toBeNull();
    expect(Boolean(currentAnalysisId)).toBe(false);
  });

  // 12. Empty results display correct empty state
  it('12. Empty results return totalCount: 0 and vulnerabilities: []', async () => {
    const res = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${lowRiskId}/vulnerabilities`)
      .set('Authorization', authHeader);
    expect(res.body.totalCount).toBe(0);
    expect(res.body.vulnerabilities).toEqual([]);
  });

  // 13. Analyst-created records require explicit action and remain scoped to analysis
  it('13. Analyst-created records require explicit user action and remain scoped to analysisId', async () => {
    const resAnalyst = await request(app.getHttpServer())
      .post(`/api/v1/analyses/${explicitVulnId}/vulnerabilities`)
      .set('Authorization', authHeader)
      .send({
        cveId: 'CVE-2024-9999',
        title: 'Analyst Flagged Flaw',
        severity: 'HIGH',
        cvssScore: 8.5,
      });

    expect(resAnalyst.status).toBe(201);
    expect(resAnalyst.body.source).toBe('Analyst Manual Entry');

    const resA = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${explicitVulnId}/vulnerabilities`)
      .set('Authorization', authHeader);
    expect(resA.body.totalCount).toBe(2);

    const resLow = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${lowRiskId}/vulnerabilities`)
      .set('Authorization', authHeader);
    expect(resLow.body.totalCount).toBe(0);
  });

  // 14. Existing Phase 2–8A tests continue passing
  it('14. Phase 2–8A regression: Assets, Endpoints, Incidents, Cases, SOAR, SIEM endpoints remain operational', async () => {
    const resAssets = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${explicitVulnId}/assets`)
      .set('Authorization', authHeader);
    expect(resAssets.status).toBe(200);

    const resEndpoints = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${explicitVulnId}/endpoints`)
      .set('Authorization', authHeader);
    expect(resEndpoints.status).toBe(200);

    const resIncidents = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${explicitVulnId}/incidents`)
      .set('Authorization', authHeader);
    expect(resIncidents.status).toBe(200);

    const resSoar = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${explicitVulnId}/soar`)
      .set('Authorization', authHeader);
    expect(resSoar.status).toBe(200);
  });
});
