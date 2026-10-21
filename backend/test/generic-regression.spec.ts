import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../src/app.module';
import { ThreatLevel } from '@prisma/client';
import { getTestAuthHeader } from './auth-helper';

describe('Generic Multi-Format Data Ingestion Regression Test Suite', () => {
  let app: INestApplication;
  const authHeader = getTestAuthHeader();

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.setGlobalPrefix('api/v1');
    app.useGlobalPipes(new ValidationPipe({ whitelist: true, transform: true }));
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  describe('1. Dynamic JSON Schema Processing', () => {
    it('1.1 Should parse deeply nested JSON reports with snake_case aliases and extract canonical fields', async () => {
      const nestedJson = JSON.stringify({
        data: {
          report_summary: {
            host_name: 'HOST-NESTED-01',
            logged_user: 'johndoe',
            os_name: 'Linux Ubuntu 22.04',
            risk_score: 82,
            threat_level: 'HIGH',
            suggested_action: 'Quarantine host',
          },
          file_hashes: {
            file_md5: '098f6bcd4621d373cade4e832627b4f6',
            file_sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
          },
          vulnerabilities_list: [
            { cve_id: 'CVE-2023-4911', title: 'Looney Tunables Glibc Buffer Overflow', cvss: 7.8, severity: 'HIGH' },
          ],
          unknown_custom_telemetry: {
            custom_sensor_id: 'SENSOR-999',
            debug_flag: true,
          },
        },
      });

      const uploadRes = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', authHeader)
        .attach('file', Buffer.from(nestedJson), 'nested_report.json');

      expect(uploadRes.status).toBe(201);
      const { analysisId } = uploadRes.body;

      const detailRes = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${analysisId}`)
        .set('Authorization', authHeader);
      expect(detailRes.status).toBe(200);
      const data = detailRes.body;

      expect(data.hostname).toBe('HOST-NESTED-01');
      expect(data.username).toBe('johndoe');
      expect(data.operatingSystem).toBe('Linux Ubuntu 22.04');
      expect(data.riskScore).toBe(82);
      expect(data.threatLevel).toBe('HIGH');
      expect(data.hashes.md5).toBe('098f6bcd4621d373cade4e832627b4f6');
      expect(data.hashes.sha256).toBe('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08');
      expect(data.vulnerabilities.length).toBe(1);
      expect(data.vulnerabilities[0].cveId).toBe('CVE-2023-4911');

      // Check unrecognized fields retention
      expect(data.unrecognizedFields).toBeDefined();
    });

    it('1.2 Should parse top-level JSON array of vulnerability records', async () => {
      const jsonArray = JSON.stringify([
        { cveId: 'CVE-2024-1001', title: 'Remote Code Execution A', cvssScore: 9.8, severity: 'CRITICAL', affectedAsset: 'WEB-SERVER-01' },
        { cveId: 'CVE-2024-1002', title: 'SQL Injection B', cvssScore: 8.5, severity: 'HIGH', affectedAsset: 'DB-SERVER-01' },
      ]);

      const uploadRes = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', authHeader)
        .attach('file', Buffer.from(jsonArray), 'vulnerabilities_array.json');

      expect(uploadRes.status).toBe(201);
      const detailRes = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${uploadRes.body.analysisId}`)
        .set('Authorization', authHeader);
      expect(detailRes.status).toBe(200);
      expect(detailRes.body.vulnerabilities.length).toBe(2);
      expect(detailRes.body.vulnerabilities.find((v: any) => v.cveId === 'CVE-2024-1001')).toBeDefined();
      expect(detailRes.body.vulnerabilities.find((v: any) => v.cveId === 'CVE-2024-1002')).toBeDefined();
    });

    it('1.3 Should reject malformed JSON with clear 400 validation error', async () => {
      const malformed = '{"metadata": { "hostname": "SERVER-01", unfinished_json...';
      const uploadRes = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', authHeader)
        .attach('file', Buffer.from(malformed), 'malformed.json');

      expect(uploadRes.status).toBe(400);
      expect(uploadRes.body.message).toContain('Malformed JSON');
    });
  });

  describe('2. Multi-Schema CSV Processing', () => {
    it('2.1 Should parse Vulnerabilities CSV with custom column headers', async () => {
      const csvContent = `CVE ID,Vulnerability Title,CVSS Score,Threat Severity,Package,Installed Version,Fixed Version,Affected Asset
CVE-2023-27534,Git Remote Code Execution,7.5,HIGH,git,2.39.1,2.39.2,BUILD-AGENT-01
CVE-2023-38606,Kernel Privilege Escalation,7.8,HIGH,kernel,5.15.0,5.15.1,BUILD-AGENT-01
`;
      const uploadRes = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', authHeader)
        .attach('file', Buffer.from(csvContent), 'vulns.csv');

      expect(uploadRes.status).toBe(201);
      const detailRes = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${uploadRes.body.analysisId}`)
        .set('Authorization', authHeader);
      expect(detailRes.status).toBe(200);

      expect(detailRes.body.vulnerabilities.length).toBe(2);
      const v1 = detailRes.body.vulnerabilities.find((v: any) => v.cveId === 'CVE-2023-27534');
      expect(v1).toBeDefined();
      expect(v1.title).toBe('Git Remote Code Execution');
      expect(v1.packageName).toBe('git');
    });

    it('2.2 Should parse Assets & Endpoints CSV with semicolon delimiter and quoted strings', async () => {
      const csvContent = `Asset Name;IP Address;MAC Address;Asset Type;Criticality;Operating System;Owner
"FIN-WORKSTATION-01";"192.168.10.50";"00:11:22:33:44:55";"Workstation";"High";"Windows 11 Pro";"Finance Dept"
"FIN-WORKSTATION-02";"192.168.10.51";"00:11:22:33:44:56";"Workstation";"High";"Windows 11 Pro";"Finance Dept"
`;
      const uploadRes = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', authHeader)
        .attach('file', Buffer.from(csvContent), 'assets.csv');

      expect(uploadRes.status).toBe(201);
      const detailRes = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${uploadRes.body.analysisId}`)
        .set('Authorization', authHeader);
      expect(detailRes.status).toBe(200);

      expect(detailRes.body.assets.length).toBe(2);
      const a1 = detailRes.body.assets.find((a: any) => a.assetName === 'FIN-WORKSTATION-01');
      expect(a1).toBeDefined();
      expect(a1.ipAddress).toBe('192.168.10.50');
      expect(a1.macAddress).toBe('00:11:22:33:44:55');
    });
  });

  describe('3. Text/Log Parser with Block Sections & Key-Value Variations', () => {
    it('3.1 Should parse log content containing block sections like [YARA] and [MITRE]', async () => {
      const logContent = `
System Host: SEC-SRV-01
Risk Level: HIGH
Score: 88

[YARA]
Rule_Malware_CobaltStrike_Beacon
Rule_Suspicious_Memory_Injected

[MITRE]
T1059.001 - Command and Scripting Interpreter: PowerShell
T1055 - Process Injection
`;

      const uploadRes = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', authHeader)
        .attach('file', Buffer.from(logContent), 'security_audit.log');

      expect(uploadRes.status).toBe(201);
      const detailRes = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${uploadRes.body.analysisId}`)
        .set('Authorization', authHeader);
      expect(detailRes.status).toBe(200);

      expect(detailRes.body.hostname).toBe('SEC-SRV-01');
      expect(detailRes.body.riskScore).toBe(88);
      expect(detailRes.body.threatLevel).toBe('HIGH');
      expect(detailRes.body.yaraResults.length).toBe(2);
      expect(detailRes.body.yaraResults.find((y: any) => y.ruleName === 'Rule_Malware_CobaltStrike_Beacon')).toBeDefined();
      expect(detailRes.body.mitreTechniques.length).toBe(2);
      expect(detailRes.body.mitreTechniques.find((m: any) => m.techniqueId === 'T1059.001')).toBeDefined();
    });
  });

  describe('4. Zero / False Semantics & Out-of-Bounds Validation', () => {
    it('4.1 Should preserve numeric zero (0) risk score as zero, not missing/null', async () => {
      const jsonZero = JSON.stringify({
        metadata: { hostname: 'SAFE-HOST-00' },
        risk: { riskScore: 0, threatLevel: 'LOW' },
      });

      const uploadRes = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', authHeader)
        .attach('file', Buffer.from(jsonZero), 'clean_sample.json');

      expect(uploadRes.status).toBe(201);
      const detailRes = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${uploadRes.body.analysisId}`)
        .set('Authorization', authHeader);
      expect(detailRes.status).toBe(200);
      expect(detailRes.body.riskScore).toBe(0);
      expect(detailRes.body.threatLevel).toBe('LOW');
    });

    it('4.2 Should reject invalid out-of-domain risk scores (>100 or <0) with 400 status', async () => {
      const invalidRiskJson = JSON.stringify({
        metadata: { hostname: 'BAD-SCORE-HOST' },
        risk: { riskScore: 999 },
      });

      const uploadRes = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', authHeader)
        .attach('file', Buffer.from(invalidRiskJson), 'bad_score.json');

      expect(uploadRes.status).toBe(400);
      expect(uploadRes.body.message).toContain('risk score must be between 0 and 100');
    });
  });

  describe('5. Calculated Bytes Hashes vs Document Reported Hashes Separation', () => {
    it('5.1 Should separate calculated file byte hashes from document reported sample hashes', async () => {
      const sampleContent = JSON.stringify({
        metadata: { hostname: 'HASH-TEST-HOST' },
        hashes: {
          md5: 'aaaaa11111bbbbb22222ccccc33333dd',
          sha256: '1111111111222222222233333333334444444444555555555566666666667777',
        },
      });

      const uploadRes = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', authHeader)
        .attach('file', Buffer.from(sampleContent), 'sample_with_hashes.json');

      expect(uploadRes.status).toBe(201);
      const detailRes = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${uploadRes.body.analysisId}`)
        .set('Authorization', authHeader);
      expect(detailRes.status).toBe(200);

      const data = detailRes.body;
      // Document reported hashes inside the payload
      expect(data.hashes.md5).toBe('aaaaa11111bbbbb22222ccccc33333dd');
      expect(data.hashes.sha256).toBe('1111111111222222222233333333334444444444555555555566666666667777');

      // Calculated file byte hashes computed by backend UploadService
      expect(data.fileMetadata).toBeDefined();
      expect(data.fileMetadata.calculatedMd5).toBeDefined();
      expect(data.fileMetadata.calculatedSha256).toBeDefined();
      expect(data.fileMetadata.calculatedMd5).not.toBe(data.hashes.md5);
    });
  });

  describe('6. Analysis Isolation Verification across Multiple Concurrent Files', () => {
    it('6.1 Should maintain strict analysisId isolation between File Alpha and File Beta', async () => {
      const contentAlpha = JSON.stringify({
        metadata: { hostname: 'ALPHA-HOST' },
        risk: { riskScore: 95, threatLevel: 'CRITICAL' },
        iocs: [{ type: 'IP', value: '10.99.88.77' }],
      });

      const contentBeta = JSON.stringify({
        metadata: { hostname: 'BETA-HOST' },
        risk: { riskScore: 10, threatLevel: 'LOW' },
        iocs: [{ type: 'DOMAIN', value: 'beta-clean-domain.org' }],
      });

      const uploadAlpha = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', authHeader)
        .attach('file', Buffer.from(contentAlpha), 'alpha.json');
      const uploadBeta = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', authHeader)
        .attach('file', Buffer.from(contentBeta), 'beta.json');

      const idAlpha = uploadAlpha.body.analysisId;
      const idBeta = uploadBeta.body.analysisId;
      expect(idAlpha).not.toBe(idBeta);

      const resAlpha = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${idAlpha}`)
        .set('Authorization', authHeader);
      const resBeta = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${idBeta}`)
        .set('Authorization', authHeader);

      expect(resAlpha.body.hostname).toBe('ALPHA-HOST');
      expect(resAlpha.body.riskScore).toBe(95);
      expect(resAlpha.body.iocs[0].value).toBe('10.99.88.77');

      expect(resBeta.body.hostname).toBe('BETA-HOST');
      expect(resBeta.body.riskScore).toBe(10);
      expect(resBeta.body.iocs[0].value).toBe('beta-clean-domain.org');
    });
  });
});
