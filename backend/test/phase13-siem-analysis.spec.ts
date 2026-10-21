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

describe('Phase 13: SIEM Log & Event Analysis Pipeline & Verification', () => {
  let app: INestApplication;
  let prisma: PrismaService;

  let tokenAlpha: string;
  let tokenBeta: string;
  let tokenAdmin: string;

  let alphaAnalysisId: string;
  let betaAnalysisId: string;
  let jsonAnalysisId: string;
  let clfAnalysisId: string;
  let sectionedAnalysisId: string;
  let csvAnalysisId: string;

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

    // 2. Upload low_risk_sample.log as Analyst Beta (static threat analysis report with 0 SIEM events)
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

  describe('1. Positive SIEM Event Extraction from soc_sample_security.log', () => {
    it('should parse and persist non-zero SIEM events with preserved timestamps, IPs, and severities', async () => {
      const res = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${alphaAnalysisId}/siem`)
        .set('Authorization', `Bearer ${tokenAlpha}`);

      expect(res.status).toBe(200);
      expect(res.body.analysisId).toBe(alphaAnalysisId);
      expect(res.body.totalCount).toBeGreaterThanOrEqual(30);
      expect(Array.isArray(res.body.events)).toBe(true);
      expect(res.body.events.length).toBe(res.body.totalCount);

      // Verify specific extracted fields
      const events = res.body.events;

      // Check that events preserve timestamps from the source log (e.g. 2026-10-11, month 9 for Oct)
      const octEvents = events.filter((e: any) => {
        const d = new Date(e.timestamp);
        return d.getUTCFullYear() === 2026 && d.getUTCMonth() === 9 && d.getUTCDate() === 11;
      });
      expect(octEvents.length).toBeGreaterThanOrEqual(25);

      // Verify source IP extraction across events
      const sourceIps = events.map((e: any) => e.sourceIp).filter(Boolean);
      expect(sourceIps).toContain('198.51.100.23');
      expect(sourceIps).toContain('192.0.2.44');
      expect(sourceIps).toContain('192.0.2.91');
      expect(sourceIps).toContain('10.20.4.15');

      // Verify destination IP extraction
      const destIps = events.map((e: any) => e.destIp).filter(Boolean);
      expect(destIps).toContain('203.0.113.77');

      // Verify port extraction
      const sourcePorts = events.map((e: any) => e.sourcePort).filter(Boolean);
      expect(sourcePorts).toContain(51422);
      expect(sourcePorts).toContain(60214);
      expect(sourcePorts).toContain(49152);

      const destPorts = events.map((e: any) => e.destPort).filter(Boolean);
      expect(destPorts).toContain(443);

      // Verify protocol extraction
      const protocols = events.map((e: any) => e.protocol).filter(Boolean);
      expect(protocols).toContain('SSH2');
      expect(protocols).toContain('TCP');

      // Verify severity normalization
      const severities = events.map((e: any) => e.severity).filter(Boolean);
      expect(severities).toContain('HIGH'); // Failed password lines
      expect(severities).toContain('INFO'); // Accepted publickey lines

      // Verify rawEvent integrity
      const failedEvent = events.find((e: any) => e.sourceIp === '198.51.100.23' && e.sourcePort === 51422);
      expect(failedEvent).toBeDefined();
      expect(failedEvent.rawEvent).toContain('Failed password for invalid user admin from 198.51.100.23 port 51422 ssh2');
      expect(failedEvent.action).toBe('AUTH_FAILED');
    });

    it('should process IOCs and SIEM events independently without treating one as proof of the other', async () => {
      // SIEM endpoint returns events
      const siemRes = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${alphaAnalysisId}/siem`)
        .set('Authorization', `Bearer ${tokenAlpha}`);

      // IOC endpoint returns IOCs
      const iocRes = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${alphaAnalysisId}/iocs`)
        .set('Authorization', `Bearer ${tokenAlpha}`);

      expect(siemRes.status).toBe(200);
      expect(iocRes.status).toBe(200);
      expect(siemRes.body.totalCount).toBeGreaterThanOrEqual(30);
      expect(iocRes.body.totalCount).toBeGreaterThanOrEqual(9);

      // Verify models are independent in database
      const dbSiemCount = await prisma.siemEvent.count({ where: { analysisId: alphaAnalysisId } });
      const dbIocCount = await prisma.ioc.count({ where: { analysisId: alphaAnalysisId } });

      expect(dbSiemCount).toBe(siemRes.body.totalCount);
      expect(dbIocCount).toBe(iocRes.body.totalCount);
      expect(dbSiemCount).not.toBe(dbIocCount);
    });
  });

  describe('2. Supported Format: Structured NDJSON / JSON Lines Log', () => {
    it('should parse and persist NDJSON log files containing streaming JSON events', async () => {
      const ndjsonContent = [
        JSON.stringify({
          timestamp: '2026-10-11T12:00:00Z',
          level: 'ERROR',
          message: 'Failed login for user admin',
          src_ip: '198.51.100.55',
          dst_ip: '10.0.0.1',
          sport: 54321,
          dport: 22,
          proto: 'TCP',
          action: 'AUTH_FAILED',
          event_id: 'EVT-JSON-001',
        }),
        JSON.stringify({
          timestamp: '2026-10-11T12:01:00Z',
          level: 'INFO',
          message: 'Firewall accepted connection',
          src_ip: '192.0.2.10',
          dst_ip: '10.0.0.2',
          sport: 61000,
          dport: 443,
          proto: 'TCP',
          action: 'ALLOW',
          event_id: 'EVT-JSON-002',
        }),
        JSON.stringify({
          timestamp: '2026-10-11T12:02:00Z',
          level: 'CRITICAL',
          message: 'Brute force alert triggered from external source',
          src_ip: '198.51.100.55',
          dst_ip: '10.0.0.1',
          action: 'BLOCK',
          event_id: 'EVT-JSON-003',
        }),
      ].join('\n');

      const resUpload = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', `Bearer ${tokenAlpha}`)
        .attach('file', Buffer.from(ndjsonContent, 'utf-8'), 'streaming_security_events.json');

      expect(resUpload.status).toBe(201);
      jsonAnalysisId = resUpload.body.analysisId;

      const resSiem = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${jsonAnalysisId}/siem`)
        .set('Authorization', `Bearer ${tokenAlpha}`);

      expect(resSiem.status).toBe(200);
      expect(resSiem.body.totalCount).toBe(3);
      expect(resSiem.body.events.length).toBe(3);

      const evtCrit = resSiem.body.events.find((e: any) => e.eventId === 'EVT-JSON-003');
      expect(evtCrit).toBeDefined();
      expect(evtCrit.severity).toBe('CRITICAL');
      expect(evtCrit.sourceIp).toBe('198.51.100.55');
      expect(evtCrit.action).toBe('BLOCK');

      const evtErr = resSiem.body.events.find((e: any) => e.eventId === 'EVT-JSON-001');
      expect(evtErr).toBeDefined();
      expect(evtErr.severity).toBe('HIGH');
      expect(evtErr.sourcePort).toBe(54321);
      expect(evtErr.destPort).toBe(22);
    });
  });

  describe('3. Supported Format: Web Server Access Logs (Common Log Format / CLF)', () => {
    it('should parse and persist Common Log Format access logs as SIEM events', async () => {
      const clfContent = [
        '198.51.100.99 - - [11/Oct/2026:14:10:00 +0000] "GET /login HTTP/1.1" 200 4520 "-" "Mozilla/5.0"',
        '198.51.100.99 - - [11/Oct/2026:14:10:05 +0000] "POST /api/auth HTTP/1.1" 401 210 "https://app/login" "curl/8.4.0"',
        '198.51.100.99 - - [11/Oct/2026:14:10:08 +0000] "POST /api/auth HTTP/1.1" 401 210 "https://app/login" "curl/8.4.0"',
        '192.0.2.88 - admin [11/Oct/2026:14:15:20 +0000] "GET /admin/dashboard HTTP/1.1" 200 12840 "-" "Mozilla/5.0"',
      ].join('\n');

      const resUpload = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', `Bearer ${tokenAlpha}`)
        .attach('file', Buffer.from(clfContent, 'utf-8'), 'access.log');

      expect(resUpload.status).toBe(201);
      clfAnalysisId = resUpload.body.analysisId;

      const resSiem = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${clfAnalysisId}/siem`)
        .set('Authorization', `Bearer ${tokenAlpha}`);

      expect(resSiem.status).toBe(200);
      expect(resSiem.body.totalCount).toBe(4);

      const events = resSiem.body.events;
      expect(events[0].sourceIp).toBeDefined();
      expect(['198.51.100.99', '192.0.2.88']).toContain(events[0].sourceIp);

      const postEvt = events.find((e: any) => e.rawEvent.includes('POST /api/auth'));
      expect(postEvt).toBeDefined();
      expect(postEvt.sourceIp).toBe('198.51.100.99');
      expect(postEvt.protocol).toBe('HTTP/1.1');
      expect(postEvt.action).toContain('POST');
    });
  });

  describe('4. Supported Format: Sectioned Text Report with === SIEM EVENTS ===', () => {
    it('should parse lines under SIEM EVENTS block sections into persisted events', async () => {
      const sectionedContent = [
        '================================================================================',
        'SOC PLATFORM - SECURITY REPORT',
        '================================================================================',
        'Hostname: SERVER-SEC-01',
        'Username: secadmin',
        '================================================================================',
        'SIEM EVENTS',
        '================================================================================',
        '2026-10-11 15:30:00  INFO      Security service initialized',
        '2026-10-11 15:31:15  WARNING   Multiple failed logins from 198.51.100.80',
        '2026-10-11 15:32:00  CRITICAL  Host containment rule triggered for 10.0.0.5',
        '================================================================================',
        'RISK SUMMARY',
        '================================================================================',
        'Risk Score: 85',
        'Threat Level: HIGH',
      ].join('\n');

      const resUpload = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', `Bearer ${tokenAlpha}`)
        .attach('file', Buffer.from(sectionedContent, 'utf-8'), 'sectioned_report.log');

      expect(resUpload.status).toBe(201);
      sectionedAnalysisId = resUpload.body.analysisId;

      const resSiem = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${sectionedAnalysisId}/siem`)
        .set('Authorization', `Bearer ${tokenAlpha}`);

      expect(resSiem.status).toBe(200);
      expect(resSiem.body.totalCount).toBe(3);

      const events = resSiem.body.events;
      const crit = events.find((e: any) => e.severity === 'CRITICAL');
      expect(crit).toBeDefined();
      expect(crit.rawEvent).toContain('Host containment rule triggered');

      const warn = events.find((e: any) => e.severity === 'MEDIUM');
      expect(warn).toBeDefined();
      expect(warn.sourceIp).toBe('198.51.100.80');
    });
  });

  describe('5. Supported Format: Tabular CSV Logs', () => {
    it('should parse CSV logs with timestamp, src, dst, severity, and action columns', async () => {
      const csvContent = [
        'timestamp,source_ip,dest_ip,sport,dport,proto,severity,action,message',
        '2026-10-11 16:00:00,198.51.100.12,10.0.0.10,41234,443,TCP,CRITICAL,BLOCK,Malicious payload dropped by IDS',
        '2026-10-11 16:05:00,192.0.2.77,10.0.0.10,51111,80,TCP,LOW,ALLOW,Normal HTTP healthcheck',
      ].join('\n');

      const resUpload = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', `Bearer ${tokenAlpha}`)
        .attach('file', Buffer.from(csvContent, 'utf-8'), 'security_events.csv');

      expect(resUpload.status).toBe(201);
      csvAnalysisId = resUpload.body.analysisId;

      const resSiem = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${csvAnalysisId}/siem`)
        .set('Authorization', `Bearer ${tokenAlpha}`);

      expect(resSiem.status).toBe(200);
      expect(resSiem.body.totalCount).toBe(2);

      const idsEvent = resSiem.body.events.find((e: any) => e.severity === 'CRITICAL');
      expect(idsEvent).toBeDefined();
      expect(idsEvent.sourceIp).toBe('198.51.100.12');
      expect(idsEvent.destIp).toBe('10.0.0.10');
      expect(idsEvent.action).toBe('BLOCK');
      expect(idsEvent.rawEvent).toContain('Malicious payload dropped');
    });
  });

  describe('6. Honest Handling of Static Reports (Zero Fake Events)', () => {
    it('should report 0 SIEM events for a static malware report without fabricating fake events', async () => {
      const res = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${betaAnalysisId}/siem`)
        .set('Authorization', `Bearer ${tokenBeta}`);

      expect(res.status).toBe(200);
      expect(res.body.analysisId).toBe(betaAnalysisId);
      expect(res.body.totalCount).toBe(0);
      expect(res.body.events).toEqual([]);

      // Verify that provenance identifies provided sections without fake SIEM
      if (res.body.provenance?.providedSections) {
        expect(res.body.provenance.providedSections).not.toContain('siem');
      }
    });
  });

  describe('7. Malformed Input and Empty Files', () => {
    it('should handle empty log files gracefully without server crash', async () => {
      const emptyContent = '';
      const resUpload = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', `Bearer ${tokenAlpha}`)
        .attach('file', Buffer.from(emptyContent, 'utf-8'), 'empty_log.log');

      expect(resUpload.status).toBe(201);
      const emptyId = resUpload.body.analysisId;

      const resSiem = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${emptyId}/siem`)
        .set('Authorization', `Bearer ${tokenAlpha}`);

      expect(resSiem.status).toBe(200);
      expect(resSiem.body.totalCount).toBe(0);
      expect(resSiem.body.events).toEqual([]);
    });

    it('should reject malformed JSON with 400 Bad Request and descriptive message', async () => {
      const badJson = '{ "name": "broken", invalid_syntax_here';
      const resUpload = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', `Bearer ${tokenAlpha}`)
        .attach('file', Buffer.from(badJson, 'utf-8'), 'broken.json');

      expect(resUpload.status).toBe(400);
      expect(resUpload.body.message).toContain('Malformed JSON document');
    });
  });

  describe('8. Duplicate Event Deduplication', () => {
    it('should deduplicate identical log entries with matching timestamps and raw content', () => {
      const normalizer = new AnalysisNormalizer();
      const rawWithDupes = {
        siem: [
          {
            rawEvent: 'Oct 11 09:14:02 alpha-web-01 sshd[1842]: Failed password for invalid user admin from 198.51.100.23',
            sourceIp: '198.51.100.23',
            severity: 'HIGH',
            timestamp: new Date('2026-10-11T09:14:02.000Z'),
          },
          {
            rawEvent: 'Oct 11 09:14:02 alpha-web-01 sshd[1842]: Failed password for invalid user admin from 198.51.100.23',
            sourceIp: '198.51.100.23',
            severity: 'HIGH',
            timestamp: new Date('2026-10-11T09:14:02.000Z'),
          },
          {
            rawEvent: 'Oct 11 09:15:00 alpha-web-01 sshd[1870]: Accepted login from 192.0.2.44',
            sourceIp: '192.0.2.44',
            severity: 'INFO',
            timestamp: new Date('2026-10-11T09:15:00.000Z'),
          },
        ],
      };

      const normalized = normalizer.normalize(rawWithDupes as any);
      expect(normalized.siem).toBeDefined();
      expect(normalized.siem!.length).toBe(2);
      expect(normalized.siem![0].sourceIp).toBe('198.51.100.23');
      expect(normalized.siem![1].sourceIp).toBe('192.0.2.44');
    });
  });

  describe('9. Cross-Analysis Isolation & Authorization', () => {
    it('should prevent Analyst Beta from viewing Alpha SIEM events (403 Forbidden)', async () => {
      const res = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${alphaAnalysisId}/siem`)
        .set('Authorization', `Bearer ${tokenBeta}`);

      expect(res.status).toBe(403);
      expect(res.body.message).toContain('Access denied');
    });

    it('should allow Administrator to access any analysis SIEM events', async () => {
      const res = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${alphaAnalysisId}/siem`)
        .set('Authorization', `Bearer ${tokenAdmin}`);

      expect(res.status).toBe(200);
      expect(res.body.analysisId).toBe(alphaAnalysisId);
      expect(res.body.totalCount).toBeGreaterThanOrEqual(30);
    });

    it('should reject unauthenticated request with 401 Unauthorized', async () => {
      const res = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${alphaAnalysisId}/siem`);

      expect(res.status).toBe(401);
    });
  });

  describe('10. SIEM Search & Filtering within Active Analysis', () => {
    it('should filter events by severity', async () => {
      const res = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${alphaAnalysisId}/siem?severity=HIGH`)
        .set('Authorization', `Bearer ${tokenAlpha}`);

      expect(res.status).toBe(200);
      expect(res.body.events.length).toBeGreaterThanOrEqual(1);
      for (const ev of res.body.events) {
        expect(ev.severity).toBe('HIGH');
      }
    });

    it('should search events by substring keyword', async () => {
      const res = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${alphaAnalysisId}/siem?search=sshd`)
        .set('Authorization', `Bearer ${tokenAlpha}`);

      expect(res.status).toBe(200);
      expect(res.body.events.length).toBeGreaterThanOrEqual(5);
      for (const ev of res.body.events) {
        expect(ev.rawEvent.toLowerCase()).toContain('sshd');
      }
    });
  });
});
