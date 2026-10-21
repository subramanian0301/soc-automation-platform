import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../src/app.module';
import { PrismaService } from '../src/prisma/prisma.service';
import { getTestAuthHeader } from './auth-helper';

describe('End-to-End Validation with Previously Unseen Fixtures', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  const authHeader = getTestAuthHeader();

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.setGlobalPrefix('api/v1');
    app.useGlobalPipes(new ValidationPipe({ whitelist: true, transform: true }));
    await app.init();

    prisma = app.get<PrismaService>(PrismaService);
  });

  afterAll(async () => {
    await app.close();
  });

  it('1. Unseen Fixture #1: Deeply nested JSON with riskScore=0 and custom vendor telemetry', async () => {
    const unseenJson = JSON.stringify({
      cyber_analysis_report: {
        system_host: 'UNSEEN-NODE-99',
        logged_user: 'sec_operator',
        os_name: 'Debian 12 Bookworm',
        risk_metrics: {
          risk_score: 0,
          severity_level: 'LOW',
          suggested_action: 'Routine System Check Passed',
        },
        threat_indicators: [
          { indicator_type: 'IP', indicator_value: '192.168.99.100', comment: 'Internal Audit Probe' },
        ],
        cve_records: [
          { cve_id: 'CVE-2026-9999', vulnerability_title: 'Zero-Day Memory Leak', cvss_score: 5.4 },
        ],
        custom_unmapped_vendor_data: {
          vendor: 'ACME Security Engine',
          sensor_version: '9.1.2',
        },
      },
    });

    const uploadRes = await request(app.getHttpServer())
      .post('/api/v1/analyses/upload')
      .set('Authorization', authHeader)
      .attach('file', Buffer.from(unseenJson), 'unseen_sample_1.json');

    expect(uploadRes.status).toBe(201);
    const { analysisId } = uploadRes.body;

    const detailRes = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${analysisId}`)
      .set('Authorization', authHeader);
    expect(detailRes.status).toBe(200);
    const data = detailRes.body;

    // Verify source values extracted correctly
    expect(data.hostname).toBe('UNSEEN-NODE-99');
    expect(data.username).toBe('sec_operator');
    expect(data.operatingSystem).toBe('Debian 12 Bookworm');
    expect(data.riskScore).toBe(0); // Preserves explicit numeric 0
    expect(data.threatLevel).toBe('LOW');

    // Verify child entities
    expect(data.iocs.length).toBe(1);
    expect(data.iocs[0].value).toBe('192.168.99.100');
    expect(data.vulnerabilities.length).toBe(1);
    expect(data.vulnerabilities[0].cveId).toBe('CVE-2026-9999');

    // Verify unknown field preservation
    expect(data.unrecognizedFields).toBeDefined();
    expect(data.unrecognizedFields.cyber_analysis_report.custom_unmapped_vendor_data.vendor).toBe('ACME Security Engine');

    // Verify scoped API endpoint return formats
    const iocRes = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${analysisId}/iocs`)
      .set('Authorization', authHeader);
    expect(iocRes.status).toBe(200);
    expect(iocRes.body.totalCount).toBe(1);
    expect(iocRes.body.provenance).toBeDefined();
  });

  it('2. Unseen Fixture #2: Semicolon-delimited CSV with custom headers and quoted strings', async () => {
    const unseenCsv = `"Node Name";"User";"IP Address";"CVE ID";"Vulnerability Title";"CVSS Score";"Threat Severity";"Fix Version"
"PROD-DB-01";"dbadmin";"10.50.1.20";"CVE-2025-1111";"Database Injection Leak";"8.9";"HIGH";"v2.1.0"
`;
    const uploadRes = await request(app.getHttpServer())
      .post('/api/v1/analyses/upload')
      .set('Authorization', authHeader)
      .attach('file', Buffer.from(unseenCsv), 'unseen_sample_2.csv');

    expect(uploadRes.status).toBe(201);
    const { analysisId } = uploadRes.body;

    const detailRes = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${analysisId}`)
      .set('Authorization', authHeader);
    expect(detailRes.status).toBe(200);
    const data = detailRes.body;

    expect(data.hostname).toBe('PROD-DB-01');
    expect(data.username).toBe('dbadmin');
    expect(data.vulnerabilities.length).toBe(1);
    expect(data.vulnerabilities[0].cveId).toBe('CVE-2025-1111');
    expect(data.vulnerabilities[0].cvssScore).toBe(8.9);
    expect(data.vulnerabilities[0].fixedVersion).toBe('v2.1.0');
  });

  it('3. Unseen Fixture #3: Section-based log with => key-value pairs and unparsed diagnostic lines', async () => {
    const unseenLog = `
Node Host => AUDIT-SERVER-X
Risk Value => 85
Severity Level => High

=== YARA SIGNATURES ===
Rule_Unseen_APT_Backdoor

=== MITRE ATTACK ===
T1059.003 - Command and Scripting Interpreter: Windows Command Shell

Unparsed custom diagnostic line without entity signature 12345
`;

    const uploadRes = await request(app.getHttpServer())
      .post('/api/v1/analyses/upload')
      .set('Authorization', authHeader)
      .attach('file', Buffer.from(unseenLog), 'unseen_sample_3.log');

    expect(uploadRes.status).toBe(201);
    const { analysisId } = uploadRes.body;

    const detailRes = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${analysisId}`)
      .set('Authorization', authHeader);
    expect(detailRes.status).toBe(200);
    const data = detailRes.body;

    expect(data.hostname).toBe('AUDIT-SERVER-X');
    expect(data.riskScore).toBe(85);
    expect(data.threatLevel).toBe('HIGH');
    expect(data.yaraResults.length).toBe(1);
    expect(data.yaraResults[0].ruleName).toBe('Rule_Unseen_APT_Backdoor');
    expect(data.mitreTechniques.length).toBe(1);
    expect(data.mitreTechniques[0].techniqueId).toBe('T1059.003');

    // Partial parsing status & warnings
    expect(data.parsingStatus).toBe('PARTIAL');
    expect(data.parsingWarnings.length).toBeGreaterThan(0);
    expect(data.unrecognizedFields.unparsedLines).toContain('Unparsed custom diagnostic line without entity signature 12345');
  });
});
