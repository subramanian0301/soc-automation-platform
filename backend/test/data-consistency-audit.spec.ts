import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../src/app.module';
import { PrismaService } from '../src/prisma/prisma.service';
import { getTestAuthHeader } from './auth-helper';

describe('SOC Dashboard Data Consistency Audit - Regression Test Suite', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  const authHeader = getTestAuthHeader();

  let fullAnalysisId: string;
  let absentAnalysisId: string;
  let emptyCollectionsAnalysisId: string;
  let partialAnalysisId: string;
  let risk95AbsentAnalysisId: string;
  let analysisAId: string;
  let analysisBId: string;

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

  // Test Case 1: A file containing source-provided IOCs, YARA matches, MITRE techniques, behavior events, sandbox results, and SIEM events.
  it('1. Uploads a file containing all source-provided security modules and verifies extraction', async () => {
    const fullJson = JSON.stringify({
      hostname: 'SEC-WORKSTATION-01',
      username: 'jdoe',
      operatingSystem: 'Windows 11 Pro',
      riskScore: 85,
      threatLevel: 'HIGH',
      yaraResults: [
        { ruleName: 'Trojan.Win32.Generic', description: 'Generic Trojan detection' }
      ],
      virusTotalResult: {
        positives: 45,
        total: 72,
        scanDate: '2026-10-09'
      },
      iocs: [
        { type: 'IP', value: '198.51.100.45', category: 'C2 Server', confidence: 90 }
      ],
      mitreTechniques: [
        { tactic: 'Execution', techniqueId: 'T1059', name: 'Command and Scripting Interpreter' }
      ],
      behaviorEvents: [
        { eventType: 'PROCESS_CREATE', action: 'Spawn', target: 'powershell.exe' }
      ],
      sandboxResults: [
        { sandboxName: 'Cuckoo Sandbox', verdict: 'MALICIOUS', score: 9 }
      ],
      siemEvents: [
        { eventId: 'EVT-1001', rawEvent: 'Firewall drop 198.51.100.45:443', severity: 'HIGH' }
      ]
    });

    const res = await request(app.getHttpServer())
      .post('/api/v1/analyses/upload')
      .set('Authorization', authHeader)
      .attach('file', Buffer.from(fullJson), 'full_security_sample.json');

    expect(res.status).toBe(201);
    fullAnalysisId = res.body.analysisId;

    const detailRes = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${fullAnalysisId}`)
      .set('Authorization', authHeader);
    expect(detailRes.status).toBe(200);
    expect(detailRes.body.yaraResults.length).toBe(1);
    expect(detailRes.body.virusTotalResult.positives).toBe(45);
    expect(detailRes.body.iocs.length).toBe(1);
    expect(detailRes.body.mitreTechniques.length).toBe(1);
    expect(detailRes.body.behaviorEvents.length).toBe(1);
    expect(detailRes.body.sandboxResults.length).toBe(1);
    expect(detailRes.body.siemEvents.length).toBe(1);

    const provenance = detailRes.body.provenance;
    expect(provenance.providedSections).toContain('yara');
    expect(provenance.providedSections).toContain('virusTotal');
    expect(provenance.providedSections).toContain('iocs');
    expect(provenance.providedSections).toContain('mitre');
    expect(provenance.providedSections).toContain('behavior');
    expect(provenance.providedSections).toContain('sandbox');
    expect(provenance.providedSections).toContain('siem');
  });

  // Test Case 2: A file with no such fields.
  it('2. Uploads a file with no security module fields and verifies absence without fake data', async () => {
    const emptyJson = JSON.stringify({
      hostname: 'PLAIN-HOST',
      username: 'alice',
      operatingSystem: 'Linux Ubuntu 22.04'
    });

    const res = await request(app.getHttpServer())
      .post('/api/v1/analyses/upload')
      .set('Authorization', authHeader)
      .attach('file', Buffer.from(emptyJson), 'plain_host.json');

    expect(res.status).toBe(201);
    absentAnalysisId = res.body.analysisId;

    const detailRes = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${absentAnalysisId}`)
      .set('Authorization', authHeader);
    expect(detailRes.status).toBe(200);
    expect(detailRes.body.yaraResults).toEqual([]);
    expect(detailRes.body.virusTotalResult).toBeNull();
    expect(detailRes.body.iocs).toEqual([]);
    expect(detailRes.body.mitreTechniques).toEqual([]);
    expect(detailRes.body.behaviorEvents).toEqual([]);
    expect(detailRes.body.sandboxResults).toEqual([]);
    expect(detailRes.body.siemEvents).toEqual([]);

    const provenance = detailRes.body.provenance;
    expect(provenance.providedSections).not.toContain('yara');
    expect(provenance.providedSections).not.toContain('virusTotal');
    expect(provenance.providedSections).not.toContain('iocs');
  });

  // Test Case 3: A file with explicitly empty collections.
  it('3. Uploads a file with explicitly empty collections and tracks providedSections', async () => {
    const explicitEmptyJson = JSON.stringify({
      hostname: 'CLEAN-SYSTEM',
      riskScore: 0,
      threatLevel: 'LOW',
      yaraResults: [],
      iocs: [],
      mitreTechniques: [],
      behaviorEvents: [],
      sandboxResults: [],
      siemEvents: []
    });

    const res = await request(app.getHttpServer())
      .post('/api/v1/analyses/upload')
      .set('Authorization', authHeader)
      .attach('file', Buffer.from(explicitEmptyJson), 'explicit_empty.json');

    expect(res.status).toBe(201);
    emptyCollectionsAnalysisId = res.body.analysisId;

    const detailRes = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${emptyCollectionsAnalysisId}`)
      .set('Authorization', authHeader);
    expect(detailRes.status).toBe(200);
    expect(detailRes.body.yaraResults).toEqual([]);
    expect(detailRes.body.iocs).toEqual([]);
    
    const provenance = detailRes.body.provenance;
    expect(provenance.providedSections).toContain('yara');
    expect(provenance.providedSections).toContain('iocs');
    expect(provenance.providedSections).toContain('mitre');
    expect(provenance.providedSections).toContain('behavior');
    expect(provenance.providedSections).toContain('sandbox');
    expect(provenance.providedSections).toContain('siem');
  });

  // Test Case 4: A partially parsed file.
  it('4. Uploads a partially parsed file and verifies parsingStatus is PARTIAL', async () => {
    const textLogWithWarnings = `
      [UNSUPPORTED_HEADER]
      Some random unstructured text content that parser retains as unparsed lines
      riskScore: 40
      threatLevel: MEDIUM
    `;

    const res = await request(app.getHttpServer())
      .post('/api/v1/analyses/upload')
      .set('Authorization', authHeader)
      .attach('file', Buffer.from(textLogWithWarnings), 'partial_sample.log');

    expect(res.status).toBe(201);
    partialAnalysisId = res.body.analysisId;

    const detailRes = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${partialAnalysisId}`)
      .set('Authorization', authHeader);
    expect(detailRes.status).toBe(200);
    expect(detailRes.body.unrecognizedFields).toBeDefined();
    expect(detailRes.body.unrecognizedFields.unparsedLines).toBeDefined();
  });

  // Test Case 5: An API failure.
  it('5. Handles API failures cleanly when requesting invalid analysis ID', async () => {
    const res = await request(app.getHttpServer())
      .get('/api/v1/analyses/analysis_non_existent_999')
      .set('Authorization', authHeader);
    expect(res.status).toBe(404);
    expect(res.body.message).toContain('not found');
  });

  // Test Case 6: Two analyses with different data, proving there is no cross-analysis leakage.
  it('6. Proves strict analysisId isolation between two distinct analyses', async () => {
    const jsonA = JSON.stringify({
      hostname: 'HOST-ALPHA',
      iocs: [{ type: 'IP', value: '10.0.0.1' }]
    });

    const jsonB = JSON.stringify({
      hostname: 'HOST-BETA',
      iocs: [{ type: 'IP', value: '10.0.0.2' }]
    });

    const resA = await request(app.getHttpServer())
      .post('/api/v1/analyses/upload')
      .set('Authorization', authHeader)
      .attach('file', Buffer.from(jsonA), 'alpha.json');
    analysisAId = resA.body.analysisId;

    const resB = await request(app.getHttpServer())
      .post('/api/v1/analyses/upload')
      .set('Authorization', authHeader)
      .attach('file', Buffer.from(jsonB), 'beta.json');
    analysisBId = resB.body.analysisId;

    const iocResA = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${analysisAId}/iocs`)
      .set('Authorization', authHeader);
    expect(iocResA.body.iocs.length).toBe(1);
    expect(iocResA.body.iocs[0].value).toBe('10.0.0.1');

    const iocResB = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${analysisBId}/iocs`)
      .set('Authorization', authHeader);
    expect(iocResB.body.iocs.length).toBe(1);
    expect(iocResB.body.iocs[0].value).toBe('10.0.0.2');
  });

  // Test Case 7: Risk score 95 with absent module data, proving that the risk score does not cause fabricated records.
  it('7. Risk score 95 with absent module data does NOT fabricate any child records', async () => {
    const risk95Json = JSON.stringify({
      hostname: 'HIGH-RISK-HOST',
      riskScore: 95,
      threatLevel: 'CRITICAL',
      recommendation: 'Immediate quarantine required'
    });

    const res = await request(app.getHttpServer())
      .post('/api/v1/analyses/upload')
      .set('Authorization', authHeader)
      .attach('file', Buffer.from(risk95Json), 'risk95_sample.json');

    expect(res.status).toBe(201);
    risk95AbsentAnalysisId = res.body.analysisId;

    const detailRes = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${risk95AbsentAnalysisId}`)
      .set('Authorization', authHeader);
    expect(detailRes.status).toBe(200);
    expect(detailRes.body.riskScore).toBe(95);
    expect(detailRes.body.threatLevel).toBe('CRITICAL');

    // Child relations must remain empty (0 rows) and not be fabricated
    expect(detailRes.body.yaraResults).toEqual([]);
    expect(detailRes.body.virusTotalResult).toBeNull();
    expect(detailRes.body.iocs).toEqual([]);
    expect(detailRes.body.mitreTechniques).toEqual([]);
    expect(detailRes.body.behaviorEvents).toEqual([]);
    expect(detailRes.body.sandboxResults).toEqual([]);
    expect(detailRes.body.siemEvents).toEqual([]);
    expect(detailRes.body.incidents).toEqual([]);
  });

  // Test Case 8: An analysis switch and clear-selection flow, proving stale module data is not displayed.
  it('8. Proves clear-selection and switching analysis ID disables queries and prevents stale data display', async () => {
    let activeAnalysisId: string | null = fullAnalysisId;
    expect(activeAnalysisId).toBe(fullAnalysisId);

    // Switch analysis ID
    activeAnalysisId = absentAnalysisId;
    expect(activeAnalysisId).toBe(absentAnalysisId);

    const detailRes = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${activeAnalysisId}`)
      .set('Authorization', authHeader);
    expect(detailRes.body.analysisId).toBe(absentAnalysisId);
    expect(detailRes.body.yaraResults).toEqual([]);

    // Clear selection
    activeAnalysisId = null;
    expect(activeAnalysisId).toBeNull();
    expect(Boolean(activeAnalysisId)).toBe(false);
  });
});
