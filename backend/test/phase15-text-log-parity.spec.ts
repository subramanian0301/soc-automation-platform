import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import * as fs from 'fs';
import * as path from 'path';
import { AppModule } from '../src/app.module';
import { PrismaService } from '../src/prisma/prisma.service';
import { TextLogParser } from '../src/parser/parsers/text-log.parser';
import { AnalysisNormalizer } from '../src/parser/normalizer/analysis.normalizer';
import { ThreatLevel } from '@prisma/client';
import { getTestAuthHeader } from './auth-helper';

describe('Phase 15: Text Log Parity & Defect Regression Test Suite', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  let textLogParser: TextLogParser;
  let normalizer: AnalysisNormalizer;
  const authHeader = getTestAuthHeader();

  const lowlevelPath = path.resolve(process.cwd(), '../test_samples/lowlevel.txt');
  const sampleLogPath = path.resolve(process.cwd(), '../test_samples/sample.log');

  const lowlevelContent = fs.readFileSync(lowlevelPath, 'utf8');
  const sampleLogContent = fs.readFileSync(sampleLogPath, 'utf8');

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
    normalizer = app.get<AnalysisNormalizer>(AnalysisNormalizer);
    textLogParser = app.get<TextLogParser>(TextLogParser);
  });

  afterAll(async () => {
    await app.close();
  });

  describe('Part 1: Unit Level Parser Verification on Actual lowlevel.txt', () => {
    let result: any;

    beforeAll(() => {
      result = textLogParser.parse(lowlevelContent, {
        originalFileName: 'lowlevel.txt',
        fileSize: lowlevelContent.length,
        mimeType: 'text/plain',
        extension: '.txt',
      });
    });

    it('1. Extracts source analysis timestamp into metadata.analysisTime', () => {
      expect(result.metadata.analysisTime).toBeInstanceOf(Date);
      expect(result.metadata.analysisTime.toISOString()).toBe('2026-09-18T10:15:00.000Z');
    });

    it('2. Fixes false-positive behavior records for negative values (None, No)', () => {
      expect(result.behavior).toBeNull();
      expect(result.provenance.providedSections).toContain('behavior');
    });

    it('3. Parses and extracts SANDBOX RESULTS metrics', () => {
      expect(result.sandbox).not.toBeNull();
      expect(result.sandbox.length).toBe(1);
      const sb = result.sandbox[0];
      expect(sb.sandboxName).toBe('Automated Sandbox');
      expect(sb.verdict).toBe('CLEAN');
      expect(sb.score).toBe(3);
      expect(sb.details).toEqual({
        processesCreated: 0,
        filesCreated: 0,
        registryKeys: 0,
        networkRequests: 1,
      });
      expect(result.provenance.providedSections).toContain('sandbox');
    });

    it('4. Preserves multi-line recommendation bullets', () => {
      expect(result.risk.recommendation).not.toBeNull();
      expect(result.risk.recommendation).toContain('- Allow Execution');
      expect(result.risk.recommendation).toContain('- No Incident Required');
    });

    it('5. Attaches YARA matched strings to the appropriate rule without creating a fake rule', () => {
      expect(result.yara).not.toBeNull();
      expect(result.yara.length).toBe(1);
      const rule = result.yara[0];
      expect(rule.ruleName).toBe('Clean.Binary.Signed');
      expect(rule.tags).toEqual(['$cert_valid', '$clean_header']);
      expect(result.yara.some((y: any) => /matched\s*strings/i.test(y.ruleName))).toBe(false);
    });

    it('6. Removes the "Imports:" label from imported library names', () => {
      expect(result.fileProperties?.imports).toBeDefined();
      expect(result.fileProperties.imports).toEqual(['kernel32.dll', 'user32.dll', 'gdi32.dll']);
      expect(result.fileProperties.imports.some((i: string) => i.includes('Imports'))).toBe(false);
    });

    it('7. Accurately identifies static analysis without SIEM events', () => {
      expect(result.siem).toBeNull();
    });
  });

  describe('Part 2: Unit Level Parser Verification on Actual sample.log', () => {
    let result: any;

    beforeAll(() => {
      result = textLogParser.parse(sampleLogContent, {
        originalFileName: 'sample.log',
        fileSize: sampleLogContent.length,
        mimeType: 'text/plain',
        extension: '.log',
      });
    });

    it('8. Extracts analysis timestamp from sample.log', () => {
      expect(result.metadata.analysisTime).toBeInstanceOf(Date);
      expect(result.metadata.analysisTime.toISOString()).toBe('2026-08-06T14:20:35.000Z');
    });

    it('9. Retains real process behavior without duplicate or fragmented records (exactly 4 events)', () => {
      expect(result.behavior).not.toBeNull();
      expect(result.behavior.length).toBe(4);

      const targets = result.behavior.map((b: any) => b.target);
      expect(targets).toContain('powershell.exe -ExecutionPolicy Bypass');
      expect(targets).toContain('HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run');
      expect(targets).toContain('Persistence Mechanism');
      expect(targets).toContain('C:\\Users\\Public\\svchost.exe');

      // Ensure no split/header records exist
      expect(targets).not.toContain('Created Process :');
      expect(targets).not.toContain('Registry Modified :');
      expect(targets).not.toContain('Persistence :');
      expect(targets).not.toContain('Dropped Files :');
    });

    it('10. Parses and extracts SANDBOX RESULTS for sample.log', () => {
      expect(result.sandbox).not.toBeNull();
      expect(result.sandbox.length).toBe(1);
      const sb = result.sandbox[0];
      expect(sb.sandboxName).toBe('Automated Sandbox');
      expect(sb.verdict).toBe('MALICIOUS');
      expect(sb.score).toBe(95);
      expect(sb.details).toEqual({
        processesCreated: 12,
        filesCreated: 8,
        registryKeys: 14,
        networkRequests: 21,
      });
    });

    it('11. Preserves multi-line recommendation bullets in sample.log', () => {
      expect(result.risk.recommendation).toContain('- Isolate Endpoint');
      expect(result.risk.recommendation).toContain('- Block SHA256');
      expect(result.risk.recommendation).toContain('- Block Domains');
      expect(result.risk.recommendation).toContain('- Block IP Addresses');
      expect(result.risk.recommendation).toContain('- Create Incident');
      expect(result.risk.recommendation).toContain('- Trigger SOAR Playbook');
    });

    it('12. Attaches YARA matched strings to Trojan.Win32.Agent without creating a fake rule', () => {
      expect(result.yara).not.toBeNull();
      expect(result.yara.length).toBe(1);
      const rule = result.yara[0];
      expect(rule.ruleName).toBe('Trojan.Win32.Agent');
      expect(rule.tags).toEqual(['$mz_header', '$powershell', '$cmd_download']);
    });

    it('13. Strips "Imports:" prefix from sample.log imports', () => {
      expect(result.fileProperties?.imports).toEqual(['kernel32.dll', 'user32.dll', 'advapi32.dll', 'ws2_32.dll']);
    });
  });

  describe('Part 3: Negative cases, mixed cases & missing-field handling', () => {
    it('14. Negative behavior values (0, false, N/A, nil, clean) are not converted into detections', () => {
      const negativeLog = `
Risk Score: 10
Threat Level: Low
Created Process : 0
Registry Modified : false
Persistence : N/A
Dropped Files : clean
`;
      const res = textLogParser.parse(negativeLog, {
        originalFileName: 'negative.log',
        fileSize: negativeLog.length,
        mimeType: 'text/plain',
        extension: '.log',
      });

      expect(res.behavior).toBeNull();
      expect(res.provenance.providedSections).toContain('behavior');
    });

    it('15. Mixed behavior log: preserves positive process while ignoring negative findings', () => {
      const mixedLog = `
Risk Score: 50
Threat Level: Medium
Created Process :
cmd.exe /c whoami
Registry Modified : None
Persistence : No
Dropped Files : 0
`;
      const res = textLogParser.parse(mixedLog, {
        originalFileName: 'mixed.log',
        fileSize: mixedLog.length,
        mimeType: 'text/plain',
        extension: '.log',
      });

      expect(res.behavior).not.toBeNull();
      expect(res.behavior!.length).toBe(1);
      expect(res.behavior![0].target).toBe('cmd.exe /c whoami');
      expect(res.behavior![0].eventType).toBe('PROCESS');
    });

    it('16. Gracefully handles missing fields without crashing or creating default junk', () => {
      const emptyLog = `
File Name: empty.exe
Entropy: 1.0
`;
      const res = textLogParser.parse(emptyLog, {
        originalFileName: 'empty.log',
        fileSize: emptyLog.length,
        mimeType: 'text/plain',
        extension: '.log',
      });

      expect(res.risk.riskScore).toBeNull();
      expect(res.metadata.analysisTime).toBeNull();
      expect(res.risk.recommendation).toBeNull();
      expect(res.behavior).toBeNull();
      expect(res.sandbox).toBeNull();
      expect(res.yara).toBeNull();
    });
  });

  describe('Part 4: Full Pipeline End-to-End API and Database Persistence', () => {
    let lowlevelAnalysisId: string;
    let sampleLogAnalysisId: string;

    it('17. Uploads lowlevel.txt through API, persists and retrieves all corrected fields', async () => {
      const uploadRes = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', authHeader)
        .attach('file', Buffer.from(lowlevelContent), 'lowlevel.txt');

      expect(uploadRes.status).toBe(201);
      lowlevelAnalysisId = uploadRes.body.analysisId;
      expect(lowlevelAnalysisId).toBeDefined();

      // 1. Verify DB persistence directly via Prisma
      const dbRecord = await prisma.analysis.findUnique({
        where: { analysisId: lowlevelAnalysisId },
        include: {
          fileProperties: true,
          yaraResults: true,
          behaviorEvents: true,
          sandboxResults: true,
        },
      });

      expect(dbRecord).not.toBeNull();
      expect(dbRecord?.analysisTime).toBeInstanceOf(Date);
      expect(dbRecord?.analysisTime?.toISOString()).toBe('2026-09-18T10:15:00.000Z');
      expect(dbRecord?.recommendation).toContain('- Allow Execution');
      expect(dbRecord?.recommendation).toContain('- No Incident Required');

      // Behavior in DB has 0 records (clean empty state)
      expect(dbRecord?.behaviorEvents.length).toBe(0);

      // Sandbox in DB has 1 record with persisted metrics
      expect(dbRecord?.sandboxResults.length).toBe(1);
      expect(dbRecord?.sandboxResults[0].verdict).toBe('CLEAN');
      expect(dbRecord?.sandboxResults[0].details).toEqual({
        processesCreated: 0,
        filesCreated: 0,
        registryKeys: 0,
        networkRequests: 1,
      });

      // YARA in DB has 1 rule with no fake "Matched Strings" rule
      expect(dbRecord?.yaraResults.length).toBe(1);
      expect(dbRecord?.yaraResults[0].ruleName).toBe('Clean.Binary.Signed');
      expect(dbRecord?.yaraResults[0].tags).toEqual(['$cert_valid', '$clean_header']);

      // Imports in DB does not contain "Imports:" prefix
      expect(dbRecord?.fileProperties?.imports).toEqual(['kernel32.dll', 'user32.dll', 'gdi32.dll']);

      // 2. Verify API endpoint GET /analyses/:id
      const apiDetailRes = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${lowlevelAnalysisId}`)
        .set('Authorization', authHeader);

      expect(apiDetailRes.status).toBe(200);
      expect(apiDetailRes.body.analysisTime).toBe('2026-09-18T10:15:00.000Z');
      expect(apiDetailRes.body.fileProperties.imports).toEqual(['kernel32.dll', 'user32.dll', 'gdi32.dll']);

      // 3. Verify API endpoint GET /analyses/:id/behavior
      const apiBehaviorRes = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${lowlevelAnalysisId}/behavior`)
        .set('Authorization', authHeader);

      expect(apiBehaviorRes.status).toBe(200);
      expect(apiBehaviorRes.body.totalCount).toBe(0);
      expect(apiBehaviorRes.body.events).toEqual([]);

      // 4. Verify API endpoint GET /analyses/:id/sandbox
      const apiSandboxRes = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${lowlevelAnalysisId}/sandbox`)
        .set('Authorization', authHeader);

      expect(apiSandboxRes.status).toBe(200);
      expect(apiSandboxRes.body.totalCount).toBe(1);
      expect(apiSandboxRes.body.results[0].verdict).toBe('CLEAN');
      expect(apiSandboxRes.body.results[0].details.processesCreated).toBe(0);
      expect(apiSandboxRes.body.results[0].details.networkRequests).toBe(1);

      // 5. Verify API endpoint GET /analyses/:id/threat-intel
      const apiThreatIntelRes = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${lowlevelAnalysisId}/threat-intel`)
        .set('Authorization', authHeader);

      expect(apiThreatIntelRes.status).toBe(200);
      expect(apiThreatIntelRes.body.yaraResults.length).toBe(1);
      expect(apiThreatIntelRes.body.yaraResults[0].ruleName).toBe('Clean.Binary.Signed');
      expect(apiThreatIntelRes.body.recommendation).toContain('- Allow Execution');
    });

    it('18. Uploads sample.log through API, persists and returns unified behavior events and sandbox metrics', async () => {
      const uploadRes = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', authHeader)
        .attach('file', Buffer.from(sampleLogContent), 'sample.log');

      expect(uploadRes.status).toBe(201);
      sampleLogAnalysisId = uploadRes.body.analysisId;
      expect(sampleLogAnalysisId).toBeDefined();

      // 1. Verify DB persistence
      const dbRecord = await prisma.analysis.findUnique({
        where: { analysisId: sampleLogAnalysisId },
        include: {
          behaviorEvents: true,
          sandboxResults: true,
          yaraResults: true,
          fileProperties: true,
        },
      });

      expect(dbRecord).not.toBeNull();
      expect(dbRecord?.analysisTime?.toISOString()).toBe('2026-08-06T14:20:35.000Z');
      expect(dbRecord?.behaviorEvents.length).toBe(4);
      expect(dbRecord?.sandboxResults.length).toBe(1);
      expect(dbRecord?.sandboxResults[0].verdict).toBe('MALICIOUS');
      expect(dbRecord?.sandboxResults[0].details).toEqual({
        processesCreated: 12,
        filesCreated: 8,
        registryKeys: 14,
        networkRequests: 21,
      });

      // 2. Verify API endpoint GET /analyses/:id/behavior
      const apiBehaviorRes = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${sampleLogAnalysisId}/behavior`)
        .set('Authorization', authHeader);

      expect(apiBehaviorRes.status).toBe(200);
      expect(apiBehaviorRes.body.totalCount).toBe(4);
      const targets = apiBehaviorRes.body.events.map((e: any) => e.target);
      expect(targets).toContain('powershell.exe -ExecutionPolicy Bypass');
      expect(targets).toContain('HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run');
      expect(targets).toContain('Persistence Mechanism');
      expect(targets).toContain('C:\\Users\\Public\\svchost.exe');

      // 3. Verify API endpoint GET /analyses/:id/sandbox
      const apiSandboxRes = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${sampleLogAnalysisId}/sandbox`)
        .set('Authorization', authHeader);

      expect(apiSandboxRes.status).toBe(200);
      expect(apiSandboxRes.body.totalCount).toBe(1);
      expect(apiSandboxRes.body.results[0].verdict).toBe('MALICIOUS');
      expect(apiSandboxRes.body.results[0].details.processesCreated).toBe(12);
    });

    it('19. Cross-analysis isolation: lowlevel and sample.log sandbox & behavior records remain strictly isolated', async () => {
      const resLowBehavior = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${lowlevelAnalysisId}/behavior`)
        .set('Authorization', authHeader);
      expect(resLowBehavior.body.events.length).toBe(0);

      const resSampleBehavior = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${sampleLogAnalysisId}/behavior`)
        .set('Authorization', authHeader);
      expect(resSampleBehavior.body.events.length).toBe(4);

      const resLowSandbox = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${lowlevelAnalysisId}/sandbox`)
        .set('Authorization', authHeader);
      expect(resLowSandbox.body.results[0].verdict).toBe('CLEAN');

      const resSampleSandbox = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${sampleLogAnalysisId}/sandbox`)
        .set('Authorization', authHeader);
      expect(resSampleSandbox.body.results[0].verdict).toBe('MALICIOUS');
    });

    it('20. Authentication & Authorization: unauthorized requests are rejected with 401', async () => {
      const unauthRes = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${lowlevelAnalysisId}/sandbox`);
      expect(unauthRes.status).toBe(401);

      const unauthBehavior = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${lowlevelAnalysisId}/behavior`);
      expect(unauthBehavior.status).toBe(401);
    });
  });
});
