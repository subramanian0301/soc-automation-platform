import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import * as jwt from 'jsonwebtoken';
import * as fs from 'fs';
import * as path from 'path';
import { AppModule } from '../src/app.module';
import { PrismaService } from '../src/prisma/prisma.service';
import { TEST_JWT_SECRET } from './auth-helper';
import { AnalysisNormalizer } from '../src/parser/normalizer/analysis.normalizer';

describe('Phase 12: IOC Extraction Pipeline & Verification', () => {
  let app: INestApplication;
  let prisma: PrismaService;

  let tokenAlpha: string;
  let tokenBeta: string;
  let tokenAdmin: string;

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

    // 1. Upload soc_sample_security.log as Analyst Alpha
    const sampleLogPath = path.resolve(process.cwd(), '../test_samples/soc_sample_security.log');
    const sampleLogBuffer = fs.readFileSync(sampleLogPath);

    const resAlpha = await request(app.getHttpServer())
      .post('/api/v1/analyses/upload')
      .set('Authorization', `Bearer ${tokenAlpha}`)
      .attach('file', sampleLogBuffer, 'soc_sample_security.log');

    expect(resAlpha.status).toBe(201);
    expect(resAlpha.body.analysisId).toBeDefined();
    alphaAnalysisId = resAlpha.body.analysisId;

    // 2. Upload low_risk_sample.log as Analyst Beta for cross-analysis isolation tests
    const lowRiskPath = path.resolve(process.cwd(), '../test_samples/low_risk_sample.log');
    const lowRiskBuffer = fs.readFileSync(lowRiskPath);

    const resBeta = await request(app.getHttpServer())
      .post('/api/v1/analyses/upload')
      .set('Authorization', `Bearer ${tokenBeta}`)
      .attach('file', lowRiskBuffer, 'low_risk_sample.log');

    expect(resBeta.status).toBe(201);
    expect(resBeta.body.analysisId).toBeDefined();
    betaAnalysisId = resBeta.body.analysisId;
  });

  afterAll(async () => {
    await app.close();
  });

  describe('1. Positive IOC Extraction from soc_sample_security.log', () => {
    it('should extract non-zero IOCs and persist them in the database scoped to analysisId', async () => {
      const res = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${alphaAnalysisId}/iocs`)
        .set('Authorization', `Bearer ${tokenAlpha}`);

      expect(res.status).toBe(200);
      expect(res.body.analysisId).toBe(alphaAnalysisId);
      expect(res.body.totalCount).toBeGreaterThanOrEqual(9);
      expect(Array.isArray(res.body.iocs)).toBe(true);
      expect(res.body.iocs.length).toBe(res.body.totalCount);

      const iocValues = res.body.iocs.map((i: any) => i.value);

      // Verify key IP addresses
      expect(iocValues).toContain('198.51.100.23'); // sshd brute force
      expect(iocValues).toContain('192.0.2.44'); // sshd deploy
      expect(iocValues).toContain('203.0.113.77'); // curl payload & firewall DST
      expect(iocValues).toContain('192.0.2.91'); // nginx probe & app auth fail
      expect(iocValues).toContain('10.20.4.15'); // firewall SRC
      expect(iocValues).toContain('192.0.2.17'); // sshd ops

      // Verify URLs
      expect(iocValues).toContain('http://203.0.113.77/payload.sh');
      expect(iocValues).toContain('https://alpha-web-01/login');

      // Verify Domains
      expect(iocValues).toContain('alpha-web-01');
    });

    it('should assign appropriate categories, types, and confidence scores to extracted IOCs', async () => {
      const res = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${alphaAnalysisId}/iocs`)
        .set('Authorization', `Bearer ${tokenAlpha}`);

      expect(res.status).toBe(200);
      const iocs = res.body.iocs;

      const payloadUrl = iocs.find((i: any) => i.value === 'http://203.0.113.77/payload.sh');
      expect(payloadUrl).toBeDefined();
      expect(payloadUrl.type).toBe('URL');
      expect(payloadUrl.category).toContain('Payload URL');
      expect(payloadUrl.confidence).toBeGreaterThanOrEqual(90);

      const internalIp = iocs.find((i: any) => i.value === '10.20.4.15');
      expect(internalIp).toBeDefined();
      expect(internalIp.type).toBe('IP');
      expect(internalIp.category).toContain('Internal IP');

      const bruteForceIp = iocs.find((i: any) => i.value === '198.51.100.23');
      expect(bruteForceIp).toBeDefined();
      expect(bruteForceIp.type).toBe('IP');
      expect(bruteForceIp.category).toContain('External IP');
      expect(bruteForceIp.confidence).toBeGreaterThanOrEqual(90);
    });
  });

  describe('2. Invalid-Value and False-Positive Rejection', () => {
    it('should NOT treat timestamps, usernames, HTTP status codes, or arbitrary numbers as IOCs', async () => {
      const res = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${alphaAnalysisId}/iocs`)
        .set('Authorization', `Bearer ${tokenAlpha}`);

      expect(res.status).toBe(200);
      const values = res.body.iocs.map((i: any) => i.value.toLowerCase());

      // Reject usernames
      const invalidUsernames = ['admin', 'administrator', 'root', 'deploy', 'backupsvc', 'oracle', 'ops', 'service-account'];
      for (const username of invalidUsernames) {
        expect(values).not.toContain(username);
      }

      // Reject HTTP status codes
      const invalidStatusCodes = ['200', '401', '404', '403'];
      for (const code of invalidStatusCodes) {
        expect(values).not.toContain(code);
      }

      // Reject timestamps and audit tokens
      expect(values).not.toContain('1791710344.000:811');
      expect(values).not.toContain('1791711554.000:901');
      expect(values).not.toContain('09:14:02');

      // Reject User-Agent strings and versions
      expect(values).not.toContain('chrome/129.0.0.0');
      expect(values).not.toContain('129.0.0.0');
      expect(values).not.toContain('webkit/537.36');
      expect(values).not.toContain('curl/8.4.0');

      // Reject file names/paths as domains
      expect(values).not.toContain('update.sh');
      expect(values).not.toContain('payload.sh');
      expect(values).not.toContain('wp-config.php');
      expect(values).not.toContain('auditd.service');
      expect(values).not.toContain('nightly-report');

      // Reject ports and PIDs
      expect(values).not.toContain('51422');
      expect(values).not.toContain('60214');
      expect(values).not.toContain('1842');
      expect(values).not.toContain('2014');
    });
  });

  describe('3. Duplicate Handling and Unification', () => {
    it('should deduplicate multiple occurrences in log events into single unique records', async () => {
      const res = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${alphaAnalysisId}/iocs`)
        .set('Authorization', `Bearer ${tokenAlpha}`);

      expect(res.status).toBe(200);

      // In soc_sample_security.log, 198.51.100.23 appears 7 times
      const matches198 = res.body.iocs.filter((i: any) => i.value === '198.51.100.23');
      expect(matches198.length).toBe(1);

      // 203.0.113.77 appears in curl download and iptables lines
      const matches203 = res.body.iocs.filter((i: any) => i.value === '203.0.113.77');
      expect(matches203.length).toBe(1);

      // 192.0.2.91 appears across 7 lines
      const matches192 = res.body.iocs.filter((i: any) => i.value === '192.0.2.91');
      expect(matches192.length).toBe(1);
    });

    it('AnalysisNormalizer should merge duplicate items retaining the highest confidence and non-null metadata', () => {
      const normalizer = new AnalysisNormalizer();
      const rawWithDupes = {
        iocs: [
          { type: 'IP', value: '198.51.100.23', category: null, confidence: 50, description: null },
          { type: 'IP', value: '198.51.100.23', category: 'External IP', confidence: 95, description: 'Brute force IP' },
          { type: 'IP', value: '198.51.100.23', category: 'External IP', confidence: 80, description: 'Repeated attempt' },
        ],
      };

      const normalized = normalizer.normalize(rawWithDupes as any);
      expect(normalized.iocs).toBeDefined();
      expect(normalized.iocs!.length).toBe(1);
      expect(normalized.iocs![0].value).toBe('198.51.100.23');
      expect(normalized.iocs![0].confidence).toBe(95);
      expect(normalized.iocs![0].category).toBe('External IP');
      expect(normalized.iocs![0].description).toBe('Brute force IP');
    });
  });

  describe('4. Cross-Analysis Isolation', () => {
    it('should isolate IOCs between distinct analyses without cross-contamination', async () => {
      const resAlpha = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${alphaAnalysisId}/iocs`)
        .set('Authorization', `Bearer ${tokenAlpha}`);

      const resBeta = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${betaAnalysisId}/iocs`)
        .set('Authorization', `Bearer ${tokenBeta}`);

      expect(resAlpha.status).toBe(200);
      expect(resBeta.status).toBe(200);

      const alphaValues = resAlpha.body.iocs.map((i: any) => i.value);
      const betaValues = resBeta.body.iocs.map((i: any) => i.value);

      // Alpha IOCs must not appear in Beta
      expect(betaValues).not.toContain('198.51.100.23');
      expect(betaValues).not.toContain('203.0.113.77');
      expect(betaValues).not.toContain('http://203.0.113.77/payload.sh');

      // Beta IOCs (10.0.0.15) must not appear in Alpha
      expect(alphaValues).not.toContain('10.0.0.15');

      // Verify all IOC records in the database belong strictly to their analysisId
      for (const ioc of resAlpha.body.iocs) {
        expect(ioc.analysisId).toBe(alphaAnalysisId);
      }
      for (const ioc of resBeta.body.iocs) {
        expect(ioc.analysisId).toBe(betaAnalysisId);
      }
    });
  });

  describe('5. IOC Search API Filtering & Scoping', () => {
    it('should filter IOCs by type within the active analysis', async () => {
      const resIp = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${alphaAnalysisId}/iocs?type=IP`)
        .set('Authorization', `Bearer ${tokenAlpha}`);

      expect(resIp.status).toBe(200);
      expect(resIp.body.iocs.length).toBeGreaterThanOrEqual(6);
      for (const ioc of resIp.body.iocs) {
        expect(ioc.type).toBe('IP');
      }

      const resUrl = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${alphaAnalysisId}/iocs?type=URL`)
        .set('Authorization', `Bearer ${tokenAlpha}`);

      expect(resUrl.status).toBe(200);
      expect(resUrl.body.iocs.length).toBeGreaterThanOrEqual(2);
      for (const ioc of resUrl.body.iocs) {
        expect(ioc.type).toBe('URL');
      }
    });

    it('should search IOCs by substring within the active analysis', async () => {
      const resSearch = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${alphaAnalysisId}/iocs?search=payload.sh`)
        .set('Authorization', `Bearer ${tokenAlpha}`);

      expect(resSearch.status).toBe(200);
      expect(resSearch.body.iocs.length).toBeGreaterThanOrEqual(1);
      expect(resSearch.body.iocs.some((i: any) => i.value.includes('payload.sh'))).toBe(true);

      const resEmpty = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${alphaAnalysisId}/iocs?search=nonexistent_token_xyz_999`)
        .set('Authorization', `Bearer ${tokenAlpha}`);

      expect(resEmpty.status).toBe(200);
      expect(resEmpty.body.totalCount).toBe(0);
      expect(resEmpty.body.iocs).toEqual([]);
    });
  });

  describe('6. Multi-User Access Control on IOC Search Endpoint', () => {
    it('should deny unauthorized user from accessing another user IOCs (IDOR prevention)', async () => {
      const resForbidden = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${alphaAnalysisId}/iocs`)
        .set('Authorization', `Bearer ${tokenBeta}`);

      expect(resForbidden.status).toBe(403);
      expect(resForbidden.body.message).toContain('Access denied');
    });

    it('should allow administrator to view any analysis IOCs', async () => {
      const resAdmin = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${alphaAnalysisId}/iocs`)
        .set('Authorization', `Bearer ${tokenAdmin}`);

      expect(resAdmin.status).toBe(200);
      expect(resAdmin.body.analysisId).toBe(alphaAnalysisId);
      expect(resAdmin.body.totalCount).toBeGreaterThanOrEqual(9);
    });

    it('should reject unauthenticated request with 401', async () => {
      const resUnauth = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${alphaAnalysisId}/iocs`);

      expect(resUnauth.status).toBe(401);
    });
  });
});
