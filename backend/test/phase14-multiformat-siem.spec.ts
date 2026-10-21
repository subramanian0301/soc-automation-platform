import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import * as jwt from 'jsonwebtoken';
import * as fs from 'fs';
import * as path from 'path';
import { AppModule } from '../src/app.module';
import { PrismaService } from '../src/prisma/prisma.service';
import { TEST_JWT_SECRET } from './auth-helper';

describe('Phase 14: Multi-Format SIEM Log Parsing & Pipeline Verification', () => {
  let app: INestApplication;
  let prisma: PrismaService;

  let tokenAlpha: string;
  let tokenBeta: string;
  let tokenAdmin: string;

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
  });

  afterAll(async () => {
    await app.close();
  });

  describe('1. Baseline Verification: Existing Working Sample (soc_sample_security.log)', () => {
    let analysisId: string;

    it('should upload and ingest soc_sample_security.log successfully', async () => {
      const samplePath = path.resolve(process.cwd(), '../test_samples/soc_sample_security.log');
      const buffer = fs.readFileSync(samplePath);

      const res = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', `Bearer ${tokenAlpha}`)
        .attach('file', buffer, 'soc_sample_security.log');

      expect(res.status).toBe(201);
      expect(res.body.analysisId).toBeDefined();
      analysisId = res.body.analysisId;
    });

    it('should extract valid SIEM events with timestamps, IPs, and severities', async () => {
      const res = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${analysisId}/siem`)
        .set('Authorization', `Bearer ${tokenAlpha}`);

      expect(res.status).toBe(200);
      expect(res.body.totalCount).toBeGreaterThan(0);
      expect(Array.isArray(res.body.events)).toBe(true);

      // Verify DB persistence matches API
      const dbCount = await prisma.siemEvent.count({ where: { analysisId } });
      expect(dbCount).toBe(res.body.totalCount);

      const firstEvent = res.body.events[0];
      expect(firstEvent.timestamp).toBeDefined();
      expect(firstEvent.severity).toBeDefined();
      expect(firstEvent.rawEvent).toContain('sshd');
    });
  });

  describe('2. Multi-Format Support: Plain-Text Formats (.log and .txt)', () => {
    it('Format 2A: Cisco ASA Firewall logs (.log)', async () => {
      const ciscoContent = [
        '# Cisco ASA Firewall Log Sample',
        '%ASA-4-106023: Deny tcp src outside:198.51.100.23/51422 dst inside:10.0.0.1/22 by access-group "acl_in"',
        '%ASA-4-106023: Deny tcp src outside:198.51.100.25/51425 dst inside:10.0.0.1/22 by access-group "acl_in"',
        '%ASA-6-302013: Built outbound TCP connection 49152 for inside:10.0.0.5/443 to outside:203.0.113.88/443',
      ].join('\n');

      const res = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', `Bearer ${tokenAlpha}`)
        .attach('file', Buffer.from(ciscoContent), 'cisco_firewall.log');

      expect(res.status).toBe(201);
      const ciscoId = res.body.analysisId;

      const siemRes = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${ciscoId}/siem`)
        .set('Authorization', `Bearer ${tokenAlpha}`);

      expect(siemRes.status).toBe(200);
      expect(siemRes.body.totalCount).toBe(3);

      const dbEvents = await prisma.siemEvent.findMany({
        where: { analysisId: ciscoId },
        orderBy: { id: 'asc' },
      });
      expect(dbEvents.length).toBe(3);

      const denyEvent = dbEvents.find(e => e.action === 'DENIED' && e.sourceIp === '198.51.100.23');
      expect(denyEvent).toBeDefined();
      expect(denyEvent?.sourceIp).toBe('198.51.100.23');
      expect(denyEvent?.destIp).toBe('10.0.0.1');
      expect(denyEvent?.destPort).toBe(22);
      expect(denyEvent?.eventId).toBe('%ASA-4-106023');
    });

    it('Format 2B: Snort / Suricata NIDS alert log (.txt)', async () => {
      const snortContent = [
        '[**] [1:1000001:1] ET SCAN Potential SSH Brute Force [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 198.51.100.77:43210 -> 10.0.0.2:22',
        '[**] [1:2001219:2] ET MALWARE Suspicious Inbound Beacon [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 203.0.113.99:8080 -> 10.0.0.15:49152',
      ].join('\n');

      const res = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', `Bearer ${tokenAlpha}`)
        .attach('file', Buffer.from(snortContent), 'snort_alerts.txt');

      expect(res.status).toBe(201);
      const snortId = res.body.analysisId;

      const siemRes = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${snortId}/siem`)
        .set('Authorization', `Bearer ${tokenAlpha}`);

      expect(siemRes.status).toBe(200);
      expect(siemRes.body.totalCount).toBe(2);

      const dbEvents = await prisma.siemEvent.findMany({ where: { analysisId: snortId } });
      expect(dbEvents.length).toBe(2);
      const snort1 = dbEvents.find(e => e.eventId === '1000001');
      expect(snort1).toBeDefined();
      expect(snort1?.sourceIp).toBe('198.51.100.77');
      expect(snort1?.destIp).toBe('10.0.0.2');
      expect(snort1?.protocol).toBe('TCP');
    });

    it('Format 2C: Windows Security Event log with slashes and Event IDs (.log)', async () => {
      const winContent = [
        '2026/10/11 10:15:00 Microsoft-Windows-Security-Auditing 4625 An account failed to log on. Account Name: admin. Source Network Address: 198.51.100.88',
        '2026/10/11 10:15:30 Microsoft-Windows-Security-Auditing 4624 An account was successfully logged on. Account Name: sysadmin. Source Network Address: 10.0.0.50',
      ].join('\n');

      const res = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', `Bearer ${tokenAlpha}`)
        .attach('file', Buffer.from(winContent), 'windows_security.log');

      expect(res.status).toBe(201);
      const winId = res.body.analysisId;

      const siemRes = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${winId}/siem`)
        .set('Authorization', `Bearer ${tokenAlpha}`);

      expect(siemRes.status).toBe(200);
      expect(siemRes.body.totalCount).toBe(2);

      const dbEvents = await prisma.siemEvent.findMany({ where: { analysisId: winId } });
      expect(dbEvents.length).toBe(2);
      const failEvent = dbEvents.find(e => e.eventId === '4625');
      expect(failEvent).toBeDefined();
      expect(failEvent?.action).toBe('AUTH_FAILED');
      expect(failEvent?.sourceIp).toBe('198.51.100.88');
      expect(failEvent?.severity).toBe('HIGH');
    });
  });

  describe('3. Multi-Format Support: Structured JSON (.json, JSON Arrays, and NDJSON)', () => {
    it('Format 3A: JSON Array of SIEM Events (.json)', async () => {
      const jsonArrayContent = JSON.stringify([
        {
          timestamp: '2026-10-11T12:00:00Z',
          level: 'HIGH',
          message: 'Firewall dropped packet from untrusted network',
          src_ip: '198.51.100.40',
          dst_ip: '10.0.0.5',
          sport: 44123,
          dport: 80,
          proto: 'TCP',
          action: 'DROPPED',
          event_id: 'EVT-ARR-001',
        },
        {
          timestamp: '2026-10-11T12:05:00Z',
          level: 'MEDIUM',
          message: 'Port scan attempt detected',
          src_ip: '198.51.100.40',
          dst_ip: '10.0.0.5',
          sport: 44124,
          dport: 443,
          proto: 'TCP',
          action: 'BLOCKED',
          event_id: 'EVT-ARR-002',
        },
      ]);

      const res = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', `Bearer ${tokenAlpha}`)
        .attach('file', Buffer.from(jsonArrayContent), 'siem_events_array.json');

      expect(res.status).toBe(201);
      const arrayId = res.body.analysisId;

      const siemRes = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${arrayId}/siem`)
        .set('Authorization', `Bearer ${tokenAlpha}`);

      expect(siemRes.status).toBe(200);
      expect(siemRes.body.totalCount).toBe(2);

      const dbEvents = await prisma.siemEvent.findMany({ where: { analysisId: arrayId } });
      expect(dbEvents.length).toBe(2);
      const evt1 = dbEvents.find(e => e.eventId === 'EVT-ARR-001');
      expect(evt1).toBeDefined();
      expect(evt1?.sourceIp).toBe('198.51.100.40');
      expect(evt1?.destIp).toBe('10.0.0.5');
      expect(evt1?.severity).toBe('HIGH');
    });

    it('Format 3B: Single JSON SIEM Event Object (.json)', async () => {
      const singleEventContent = JSON.stringify({
        timestamp: '2026-10-11T13:30:00Z',
        severity: 'CRITICAL',
        rawEvent: 'Ransomware C2 traffic detected on internal interface',
        sourceIp: '10.0.0.22',
        destIp: '203.0.113.199',
        sourcePort: 55432,
        destPort: 443,
        protocol: 'TCP',
        action: 'BLOCKED',
        eventId: 'EVT-SINGLE-999',
      });

      const res = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', `Bearer ${tokenAlpha}`)
        .attach('file', Buffer.from(singleEventContent), 'single_siem_event.json');

      expect(res.status).toBe(201);
      const singleId = res.body.analysisId;

      const siemRes = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${singleId}/siem`)
        .set('Authorization', `Bearer ${tokenAlpha}`);

      expect(siemRes.status).toBe(200);
      expect(siemRes.body.totalCount).toBe(1);

      const dbEvents = await prisma.siemEvent.findMany({ where: { analysisId: singleId } });
      expect(dbEvents.length).toBe(1);
      expect(dbEvents[0].eventId).toBe('EVT-SINGLE-999');
      expect(dbEvents[0].severity).toBe('CRITICAL');
      expect(dbEvents[0].sourceIp).toBe('10.0.0.22');
      expect(dbEvents[0].destIp).toBe('203.0.113.199');
    });

    it('Format 3C: JSON Lines / NDJSON (.ndjson or .jsonl)', async () => {
      const ndjsonContent = [
        JSON.stringify({ timestamp: '2026-10-11T14:00:00Z', level: 'WARN', src_ip: '192.168.1.10', dst_ip: '10.0.0.1', action: 'DENY', message: 'Unauthorized SSH' }),
        JSON.stringify({ timestamp: '2026-10-11T14:01:00Z', level: 'INFO', src_ip: '192.168.1.12', dst_ip: '10.0.0.1', action: 'ALLOW', message: 'Authorized SSH' }),
      ].join('\n');

      const res = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', `Bearer ${tokenAlpha}`)
        .attach('file', Buffer.from(ndjsonContent), 'stream.ndjson');

      expect(res.status).toBe(201);
      const streamId = res.body.analysisId;

      const siemRes = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${streamId}/siem`)
        .set('Authorization', `Bearer ${tokenAlpha}`);

      expect(siemRes.status).toBe(200);
      expect(siemRes.body.totalCount).toBe(2);
    });
  });

  describe('4. Resilient Edge Cases: Empty, Malformed, Missing Fields, and Deduplication', () => {
    it('Empty file should complete cleanly with 0 events without server error', async () => {
      const res = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', `Bearer ${tokenAlpha}`)
        .attach('file', Buffer.from(''), 'empty.log');

      expect(res.status).toBe(201);
      const emptyId = res.body.analysisId;

      const siemRes = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${emptyId}/siem`)
        .set('Authorization', `Bearer ${tokenAlpha}`);

      expect(siemRes.status).toBe(200);
      expect(siemRes.body.totalCount).toBe(0);
      expect(siemRes.body.events).toEqual([]);
    });

    it('Malformed JSON document should return 400 Bad Request with descriptive message', async () => {
      const brokenJson = '{ "timestamp": "2026-10-11", "invalid": ';

      const res = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', `Bearer ${tokenAlpha}`)
        .attach('file', Buffer.from(brokenJson), 'broken.json');

      expect(res.status).toBe(400);
      expect(res.body.message).toMatch(/Malformed JSON document/i);
    });

    it('Static malware reports with NO telemetry should honestly report 0 SIEM events', async () => {
      const staticReport = [
        'File Name: static_report.log',
        'Risk Score: 10/100',
        'Threat Level: Low',
        'Hostname: WORKSTATION-01',
        'MD5: 11111122222233333344444455555566',
        'YARA Rule: Clean_Binary',
      ].join('\n');

      const res = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', `Bearer ${tokenAlpha}`)
        .attach('file', Buffer.from(staticReport), 'static_report.log');

      expect(res.status).toBe(201);
      const staticId = res.body.analysisId;

      const siemRes = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${staticId}/siem`)
        .set('Authorization', `Bearer ${tokenAlpha}`);

      expect(siemRes.status).toBe(200);
      expect(siemRes.body.totalCount).toBe(0);
      expect(siemRes.body.events).toEqual([]);
    });

    it('Missing fields in SIEM logs should be handled without crashing', async () => {
      const missingFieldsLog = [
        'Oct 11 12:00:00 app[100]: message without any IP or ports',
        '2026-10-11 12:01:00 kernel: failed password from 10.0.0.1',
      ].join('\n');

      const res = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', `Bearer ${tokenAlpha}`)
        .attach('file', Buffer.from(missingFieldsLog), 'missing_fields.log');

      expect(res.status).toBe(201);
      const missingId = res.body.analysisId;

      const siemRes = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${missingId}/siem`)
        .set('Authorization', `Bearer ${tokenAlpha}`);

      expect(siemRes.status).toBe(200);
      expect(siemRes.body.totalCount).toBe(2);

      const dbEvents = await prisma.siemEvent.findMany({ where: { analysisId: missingId } });
      expect(dbEvents.length).toBe(2);
      const appEvent = dbEvents.find(e => e.rawEvent.includes('app[100]'));
      const kernelEvent = dbEvents.find(e => e.rawEvent.includes('kernel'));
      expect(appEvent?.sourceIp).toBeNull();
      expect(appEvent?.destIp).toBeNull();
      expect(kernelEvent?.sourceIp).toBe('10.0.0.1');
    });

    it('Duplicate events with matching eventId or timestamp + rawEvent should deduplicate', async () => {
      const duplicateLog = [
        'Oct 11 09:14:02 alpha-web-01 sshd[1842]: Failed password for root from 198.51.100.23 port 51422 ssh2',
        'Oct 11 09:14:02 alpha-web-01 sshd[1842]: Failed password for root from 198.51.100.23 port 51422 ssh2',
        'Oct 11 09:14:05 alpha-web-01 sshd[1844]: Failed password for root from 198.51.100.23 port 51427 ssh2',
      ].join('\n');

      const res = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', `Bearer ${tokenAlpha}`)
        .attach('file', Buffer.from(duplicateLog), 'duplicate.log');

      expect(res.status).toBe(201);
      const dupId = res.body.analysisId;

      const siemRes = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${dupId}/siem`)
        .set('Authorization', `Bearer ${tokenAlpha}`);

      expect(siemRes.status).toBe(200);
      // The identical line should have been deduplicated
      expect(siemRes.body.totalCount).toBe(2);
    });
  });

  describe('5. Database Persistence, Isolation & Authorization', () => {
    let alphaId: string;
    let betaId: string;

    beforeAll(async () => {
      const logA = 'Oct 11 10:00:00 host-alpha kernel: Drop packet SRC=10.1.1.1 DST=10.2.2.2';
      const logB = 'Oct 11 10:00:00 host-beta kernel: Drop packet SRC=10.3.3.3 DST=10.4.4.4';

      const resA = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', `Bearer ${tokenAlpha}`)
        .attach('file', Buffer.from(logA), 'alpha.log');
      alphaId = resA.body.analysisId;

      const resB = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', `Bearer ${tokenBeta}`)
        .attach('file', Buffer.from(logB), 'beta.log');
      betaId = resB.body.analysisId;
    });

    it('Database persistence: events must be stored against their specific analysisId', async () => {
      const eventsA = await prisma.siemEvent.findMany({ where: { analysisId: alphaId } });
      const eventsB = await prisma.siemEvent.findMany({ where: { analysisId: betaId } });

      expect(eventsA.length).toBe(1);
      expect(eventsA[0].sourceIp).toBe('10.1.1.1');

      expect(eventsB.length).toBe(1);
      expect(eventsB[0].sourceIp).toBe('10.3.3.3');
    });

    it('Ownership check: Analyst Beta cannot access Analyst Alpha SIEM events (403 Forbidden)', async () => {
      const res = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${alphaId}/siem`)
        .set('Authorization', `Bearer ${tokenBeta}`);

      expect(res.status).toBe(403);
    });

    it('Administrator can access any analysis SIEM events', async () => {
      const res = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${alphaId}/siem`)
        .set('Authorization', `Bearer ${tokenAdmin}`);

      expect(res.status).toBe(200);
      expect(res.body.totalCount).toBe(1);
      expect(res.body.events[0].sourceIp).toBe('10.1.1.1');
    });

    it('Unauthenticated requests are rejected with 401 Unauthorized', async () => {
      const res = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${alphaId}/siem`);

      expect(res.status).toBe(401);
    });
  });
});
