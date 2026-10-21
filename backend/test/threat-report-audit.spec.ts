import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import * as fs from 'fs';
import * as path from 'path';
import * as jwt from 'jsonwebtoken';
import { AppModule } from '../src/app.module';
import { PrismaService } from '../src/prisma/prisma.service';
import { JsonParser } from '../src/parser/parsers/json.parser';
import { AnalysisNormalizer } from '../src/parser/normalizer/analysis.normalizer';
import { TEST_JWT_SECRET } from './auth-helper';

describe('Threat Report Audit & Fix Verification', () => {
  jest.setTimeout(30000);

  let app: INestApplication;
  let prisma: PrismaService;
  let jsonParser: JsonParser;
  let normalizer: AnalysisNormalizer;

  let tokenUserA: string;
  let tokenUserB: string;

  const sampleReportPath = path.resolve(process.cwd(), '../sample_threat_report.json');
  const sampleReportContent = fs.readFileSync(sampleReportPath, 'utf8');

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
    jsonParser = moduleFixture.get(JsonParser);
    normalizer = moduleFixture.get(AnalysisNormalizer);

    const activeSecret = process.env.JWT_SECRET || TEST_JWT_SECRET;

    tokenUserA = jwt.sign(
      { sub: 'user-analyst-alpha', username: 'analyst_alpha', role: 'SOC_ANALYST', email: 'alpha@soc.platform.local' },
      activeSecret,
      { algorithm: 'HS256', expiresIn: '1h' },
    );

    tokenUserB = jwt.sign(
      { sub: 'user-analyst-beta', username: 'analyst_beta', role: 'SOC_ANALYST', email: 'beta@soc.platform.local' },
      activeSecret,
      { algorithm: 'HS256', expiresIn: '1h' },
    );
  });

  afterAll(async () => {
    await app.close();
  });

  // --------------------------------------------------------------------------
  // TEST 1: Unit tests for the report parser using sample_threat_report.json
  // --------------------------------------------------------------------------
  describe('1. Report Parser Unit Tests with sample_threat_report.json', () => {
    it('should extract exact counts without dropping MITRE, Sandbox, Behavior, or IOCs', () => {
      const parsed = jsonParser.parse(sampleReportContent, {
        originalFileName: 'sample_threat_report.json',
        fileSize: Buffer.byteLength(sampleReportContent),
        mimeType: 'application/json',
        extension: '.json',
      });

      // 1. MITRE Techniques: exactly 3
      expect(parsed.mitre).toBeDefined();
      expect(parsed.mitre).toHaveLength(3);
      const techniqueIds = parsed.mitre!.map((t) => t.techniqueId);
      expect(techniqueIds).toEqual(
        expect.arrayContaining(['T1059.001', 'T1547.001', 'T1071.001']),
      );

      // 2. Sandbox Runs: exactly 1 run with verdict and score
      expect(parsed.sandbox).toBeDefined();
      expect(parsed.sandbox).toHaveLength(1);
      expect(parsed.sandbox![0].verdict).toBe('MALICIOUS');
      expect(parsed.sandbox![0].score).toBe(9);
      expect(parsed.sandbox![0].sandboxName).toBe('Windows 10 x64');

      // 3. Behavior Events: exactly 3 events (no placeholder rows from null/"No"/false values)
      expect(parsed.behavior).toBeDefined();
      expect(parsed.behavior).toHaveLength(3);
      const targets = parsed.behavior!.map((b) => b.target);
      expect(targets).toContain('powershell.exe -nop -w hidden -enc SQBFAFgA');
      expect(targets).toContain('HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater');
      expect(targets).toContain('203.0.113.45:443');

      // None of the negative attributes became behavior events
      for (const b of parsed.behavior!) {
        expect(b.target).not.toBe('None');
        expect(b.target).not.toBe('No');
        expect(b.target).not.toBe('null');
        expect(b.target).not.toBe('');
      }

      // 4. IOCs: exactly 2 IPs, 2 domains, 2 URLs, 3 hashes, 1 email = 10 total
      expect(parsed.iocs).toBeDefined();
      const ips = parsed.iocs!.filter((i) => i.type === 'IP');
      const domains = parsed.iocs!.filter((i) => i.type === 'DOMAIN');
      const urls = parsed.iocs!.filter((i) => i.type === 'URL');
      const hashes = parsed.iocs!.filter((i) => i.type === 'HASH');
      const emails = parsed.iocs!.filter((i) => i.type === 'EMAIL');

      expect(ips).toHaveLength(2);
      expect(ips.map((i) => i.value)).toEqual(expect.arrayContaining(['203.0.113.45', '198.51.100.23']));

      expect(domains).toHaveLength(2);
      expect(domains.map((i) => i.value)).toEqual(
        expect.arrayContaining(['cdn-update.badhost.example', 'c2.evil-domain.example']),
      );

      expect(urls).toHaveLength(2);
      expect(urls.map((i) => i.value)).toEqual(
        expect.arrayContaining([
          'http://cdn-update.badhost.example/payload.bin',
          'https://c2.evil-domain.example/gate.php?id=417',
        ]),
      );

      expect(hashes).toHaveLength(3);
      expect(hashes.map((i) => i.value)).toEqual(
        expect.arrayContaining([
          '5d41402abc4b2a76b9719d911017c592',
          'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d',
          '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae',
        ]),
      );

      expect(emails).toHaveLength(1);
      expect(emails[0].value).toBe('billing@spoofed-vendor.example');

      // 5. False positive checks: agent_version and invoice_update.exe must NOT be IOCs
      const allIocValues = parsed.iocs!.map((i) => i.value.toLowerCase());
      expect(allIocValues).not.toContain('4.2.1.88');
      expect(allIocValues).not.toContain('invoice_update.exe');

      // 6. YARA: exactly 2 matches
      expect(parsed.yara).toBeDefined();
      expect(parsed.yara).toHaveLength(2);
      expect(parsed.yara!.map((y) => y.ruleName)).toEqual(
        expect.arrayContaining(['Suspicious_Packer_UPX', 'Generic_Downloader_Strings']),
      );

      // 7. VirusTotal: 41/72
      expect(parsed.virusTotal).toBeDefined();
      expect(parsed.virusTotal!.positives).toBe(41);
      expect(parsed.virusTotal!.total).toBe(72);

      // 8. Unmatched lines from analyst_notes and custom_section_unknown in Parsing Notes with line numbers
      expect(parsed.parsingWarnings).toBeDefined();
      expect(parsed.parsingWarnings!.length).toBeGreaterThan(0);
      const joinedWarnings = parsed.parsingWarnings!.join('\n');
      expect(joinedWarnings).toMatch(/Line \d+: .*analyst_notes/i);
      expect(joinedWarnings).toMatch(/Line \d+: .*custom_section_unknown/i);

      // 9. Unprovided modules must remain empty / null
      expect(parsed.incident).toBeNull();
      expect(parsed.assets).toBeNull();
      expect(parsed.endpoints).toBeNull();
      expect(parsed.vulnerabilities).toBeNull();
      expect(parsed.soar).toBeNull();
      expect(parsed.siem).toBeNull();
    });
  });

  // --------------------------------------------------------------------------
  // TEST 2: None/null/false behavior values produce no event rows
  // --------------------------------------------------------------------------
  describe('2. Negative / Placeholder Behavior Values', () => {
    it('should never produce event rows for null, None, No, false, or empty values', () => {
      const dummyInput = {
        behavior: [
          { target: null, action: 'None' },
          { target: 'None', action: 'None' },
          { target: 'No', action: 'No' },
          { target: false, action: false },
          { target: '', action: '' },
          { target: 'Registry Modified : None', action: 'None' },
          { target: 'DROPPEDFILES DETECTED None', action: 'None' },
          { target: 'PERSISTENCE DETECTED No', action: 'No' },
          { target: 'HKLM\\Software\\Run\\Malware.exe', action: 'PERSISTENCE_DETECTED' },
        ],
      };

      const normalized = normalizer.normalize(dummyInput as any);
      expect(normalized.behavior).toBeDefined();
      expect(normalized.behavior).toHaveLength(1);
      expect(normalized.behavior![0].target).toBe('HKLM\\Software\\Run\\Malware.exe');
    });
  });

  let uploadAnalysisId: string;

  // --------------------------------------------------------------------------
  // TEST 3: Parser count == DB count == API count for each module
  // --------------------------------------------------------------------------
  describe('3. Persistence & Retrieval Consistency (Parser == DB == API)', () => {
    beforeAll(async () => {
      const res = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', `Bearer ${tokenUserA}`)
        .attach('file', Buffer.from(sampleReportContent), 'sample_threat_report.json');

      expect(res.status).toBe(201);
      uploadAnalysisId = res.body.analysisId;
    });

    it('should assert Parser count == DB count == API count across every module', async () => {
      // 1. MITRE: 3
      const dbMitre = await prisma.mitreTechnique.count({ where: { analysisId: uploadAnalysisId } });
      const apiMitre = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${uploadAnalysisId}/mitre`)
        .set('Authorization', `Bearer ${tokenUserA}`);
      expect(dbMitre).toBe(3);
      expect(apiMitre.body.totalCount).toBe(3);
      expect(apiMitre.body.techniques).toHaveLength(3);

      // 2. Sandbox: 1
      const dbSandbox = await prisma.sandboxResult.count({ where: { analysisId: uploadAnalysisId } });
      const apiSandbox = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${uploadAnalysisId}/sandbox`)
        .set('Authorization', `Bearer ${tokenUserA}`);
      expect(dbSandbox).toBe(1);
      expect(apiSandbox.body.totalCount).toBe(1);
      expect(apiSandbox.body.results).toHaveLength(1);

      // 3. Behavior: 3
      const dbBehavior = await prisma.behaviorEvent.count({ where: { analysisId: uploadAnalysisId } });
      const apiBehavior = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${uploadAnalysisId}/behavior`)
        .set('Authorization', `Bearer ${tokenUserA}`);
      expect(dbBehavior).toBe(3);
      expect(apiBehavior.body.totalCount).toBe(3);
      expect(apiBehavior.body.events).toHaveLength(3);

      // 4. IOCs: 10
      const dbIocs = await prisma.ioc.count({ where: { analysisId: uploadAnalysisId } });
      const apiIocs = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${uploadAnalysisId}/iocs`)
        .set('Authorization', `Bearer ${tokenUserA}`);
      expect(dbIocs).toBe(10);
      expect(apiIocs.body.totalCount).toBe(10);
      expect(apiIocs.body.iocs).toHaveLength(10);

      // 5. Threat Intel: 2 YARA matches, VT 41/72
      const dbYara = await prisma.yaraResult.count({ where: { analysisId: uploadAnalysisId } });
      const dbVt = await prisma.virusTotalResult.findUnique({ where: { analysisId: uploadAnalysisId } });
      const apiThreatIntel = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${uploadAnalysisId}/threat-intel`)
        .set('Authorization', `Bearer ${tokenUserA}`);
      expect(dbYara).toBe(2);
      expect(dbVt?.positives).toBe(41);
      expect(dbVt?.total).toBe(72);
      expect(apiThreatIntel.body.yaraResults).toHaveLength(2);
      expect(apiThreatIntel.body.virusTotalResult.positives).toBe(41);
      expect(apiThreatIntel.body.virusTotalResult.total).toBe(72);

      // 6. Empty modules remain 0 in Parser, DB, and API
      const dbIncidents = await prisma.incident.count({ where: { analysisId: uploadAnalysisId } });
      const apiIncidents = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${uploadAnalysisId}/incidents`)
        .set('Authorization', `Bearer ${tokenUserA}`);
      expect(dbIncidents).toBe(0);
      expect(apiIncidents.body.totalCount).toBe(0);

      const dbSoar = await prisma.soarExecution.count({ where: { analysisId: uploadAnalysisId } });
      const apiSoar = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${uploadAnalysisId}/soar`)
        .set('Authorization', `Bearer ${tokenUserA}`);
      expect(dbSoar).toBe(0);
      expect(apiSoar.body.totalCount).toBe(0);

      const dbAssets = await prisma.asset.count({ where: { analysisId: uploadAnalysisId } });
      const apiAssets = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${uploadAnalysisId}/assets`)
        .set('Authorization', `Bearer ${tokenUserA}`);
      expect(dbAssets).toBe(0);
      expect(apiAssets.body.totalCount).toBe(0);

      const dbEndpoints = await prisma.endpoint.count({ where: { analysisId: uploadAnalysisId } });
      const apiEndpoints = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${uploadAnalysisId}/endpoints`)
        .set('Authorization', `Bearer ${tokenUserA}`);
      expect(dbEndpoints).toBe(0);
      expect(apiEndpoints.body.totalCount).toBe(0);

      const dbVulns = await prisma.vulnerability.count({ where: { analysisId: uploadAnalysisId } });
      const apiVulns = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${uploadAnalysisId}/vulnerabilities`)
        .set('Authorization', `Bearer ${tokenUserA}`);
      expect(dbVulns).toBe(0);
      expect(apiVulns.body.totalCount).toBe(0);

      const dbSiem = await prisma.siemEvent.count({ where: { analysisId: uploadAnalysisId } });
      const apiSiem = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${uploadAnalysisId}/siem`)
        .set('Authorization', `Bearer ${tokenUserA}`);
      expect(dbSiem).toBe(0);
      expect(apiSiem.body.totalCount).toBe(0);
    });
  });

  // --------------------------------------------------------------------------
  // TEST 4: Upload two files and switch between analyses with no data bleed
  // --------------------------------------------------------------------------
  describe('4. Dual File Upload & Analysis Isolation (No Data Bleed)', () => {
    let id1: string;
    let id2: string;

    beforeAll(async () => {
      id1 = uploadAnalysisId;

      const telemetryContent = JSON.stringify({
        metadata: { hostname: 'ISOLATED-HOST-02' },
        siem_events: [
          { event_id: 'EVT-9001', raw_event: 'User logon success', severity: 'LOW', action: 'LOGON' },
        ],
      });

      const res2 = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', `Bearer ${tokenUserA}`)
        .attach('file', Buffer.from(telemetryContent), 'file2_telemetry.json');
      id2 = res2.body.analysisId;
    });

    it('should strictly isolate data between analysis 1 and analysis 2', async () => {
      // Analysis 1 has 3 MITRE techniques, Analysis 2 has 0
      const res1Mitre = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${id1}/mitre`)
        .set('Authorization', `Bearer ${tokenUserA}`);
      const res2Mitre = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${id2}/mitre`)
        .set('Authorization', `Bearer ${tokenUserA}`);

      expect(res1Mitre.body.totalCount).toBe(3);
      expect(res2Mitre.body.totalCount).toBe(0);

      // Analysis 1 has 0 SIEM events, Analysis 2 has 1
      const res1Siem = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${id1}/siem`)
        .set('Authorization', `Bearer ${tokenUserA}`);
      const res2Siem = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${id2}/siem`)
        .set('Authorization', `Bearer ${tokenUserA}`);

      expect(res1Siem.body.totalCount).toBe(0);
      expect(res2Siem.body.totalCount).toBe(1);
      expect(res2Siem.body.events[0].eventId).toBe('EVT-9001');
    });
  });

  // --------------------------------------------------------------------------
  // TEST 5: Cross-user access is denied (403/404)
  // --------------------------------------------------------------------------
  describe('5. Multi-User Authorization & IDOR Protection', () => {
    it('should deny User B access to User A analysis with 403 Forbidden', async () => {
      const res = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${uploadAnalysisId}`)
        .set('Authorization', `Bearer ${tokenUserB}`);
      expect(res.status).toBe(403);
    });

    it('should return 404 Not Found for non-existent analysis ID', async () => {
      const res = await request(app.getHttpServer())
        .get('/api/v1/analyses/analysis_non_existent_fake_id')
        .set('Authorization', `Bearer ${tokenUserA}`);
      expect(res.status).toBe(404);
    });
  });

  // --------------------------------------------------------------------------
  // TEST 6: Empty, oversized, and wrong-extension uploads return clear errors
  // --------------------------------------------------------------------------
  describe('6. Upload Validation Errors', () => {
    it('should return 400 for empty (0 bytes) file', async () => {
      const res = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', `Bearer ${tokenUserA}`)
        .attach('file', Buffer.from(''), 'empty.json');
      expect(res.status).toBe(400);
      expect(res.body.message).toContain('empty');
    });

    it('should return 400 for wrong-extension file (.exe)', async () => {
      const res = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', `Bearer ${tokenUserA}`)
        .attach('file', Buffer.from('console.log("hello");'), 'script.exe');
      expect(res.status).toBe(400);
      expect(res.body.message).toContain('Unsupported file type');
    });

    it('should return 400 for binary file containing null bytes', async () => {
      const binaryBuffer = Buffer.from([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00]);
      const res = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', `Bearer ${tokenUserA}`)
        .attach('file', binaryBuffer, 'binary.log');
      expect(res.status).toBe(400);
      expect(res.body.message).toContain('binary data');
    });
  });
});
