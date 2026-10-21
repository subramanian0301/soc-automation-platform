import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import * as fs from 'fs';
import * as path from 'path';
import { AppModule } from '../src/app.module';
import { PrismaService } from '../src/prisma/prisma.service';
import { ThreatLevel } from '@prisma/client';
import { getTestAuthHeader } from './auth-helper';

describe('Phase 2 E2E & Cross-Sample Isolation Tests', () => {
  let app: INestApplication;
  let prisma: PrismaService;
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
  });

  afterAll(async () => {
    await app.close();
  });

  describe('1. File Type Validation & Security', () => {
    it('should reject unsupported file types like .exe', async () => {
      const response = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', authHeader)
        .attach('file', Buffer.from('MZ...'), 'malicious.exe');

      expect(response.status).toBe(400);
      expect(response.body.message).toContain('Unsupported file type');
    });

    it('should reject out-of-domain risk scores (e.g. 150)', async () => {
      const invalidRiskLog = `
File Name: invalid_risk.log
Risk Score: 150/100
Threat Level: High
`;
      const response = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', authHeader)
        .attach('file', Buffer.from(invalidRiskLog), 'invalid_risk.log');

      expect(response.status).toBe(400);
      expect(response.body.message).toContain('risk score must be between 0 and 100');
    });
  });

  describe('2. Mandatory Cross-Sample Isolation Test (Samples A, B, C, D)', () => {
    let analysisIdA: string;
    let analysisIdB: string;
    let analysisIdC: string;
    let analysisIdD: string;

    const sampleA_log = `
File Name: sample_a.log
Risk Score: 3/100
Threat Level: Low
Hostname: HOST-A-SAFE
MD5: aaaaaa00000000000000000000000001
IOC: IP - 10.0.0.1
YARA Rule: Rule_A_Benign
`;

    const sampleB_csv = `sourceIp,destIp,sourcePort,destPort,protocol,action,severity,riskScore,threatLevel,hostname
10.0.0.2,192.168.1.1,443,80,TCP,ALLOW,MEDIUM,33,Medium,HOST-B-SUSPICIOUS
`;

    const sampleC_log = `
File Name: sample_c.log
Risk Score: 75/100
Threat Level: High
Hostname: HOST-C-HIGH
MD5: ccccccc0000000000000000000000003
IOC: DOMAIN - malicious-host-c.com
YARA Rule: Rule_C_Trojan
MITRE: T1059.001 - PowerShell
`;

    const sampleD_json = JSON.stringify({
      metadata: {
        hostname: 'HOST-D-CRITICAL',
        username: 'victim_user',
      },
      risk: {
        riskScore: 98,
        threatLevel: 'CRITICAL',
        recommendation: 'Immediate Quarantine',
      },
      hashes: {
        sha256: 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd04',
      },
      iocs: [
        { type: 'DOMAIN', value: 'c2-critical-d.org', confidence: 100 },
      ],
      mitre: [
        { tactic: 'Execution', techniqueId: 'T1059.001', name: 'PowerShell' },
      ],
      incident: [
        { title: 'Critical Ransomware Outbreak D', severity: 'CRITICAL', status: 'OPEN', reason: 'Explicit ransom note' },
      ],
    });

    it('should upload Sample A and return unique analysisId (Risk 3, Low)', async () => {
      const res = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', authHeader)
        .attach('file', Buffer.from(sampleA_log), 'sample_a.log');

      expect(res.status).toBe(201);
      expect(res.body.analysisId).toBeDefined();
      expect(res.body.riskScore).toBe(3);
      expect(res.body.threatLevel).toBe(ThreatLevel.LOW);
      analysisIdA = res.body.analysisId;
    });

    it('should upload Sample B and return distinct analysisId (Risk 33, Medium)', async () => {
      const res = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', authHeader)
        .attach('file', Buffer.from(sampleB_csv), 'sample_b.csv');

      expect(res.status).toBe(201);
      expect(res.body.analysisId).toBeDefined();
      expect(res.body.analysisId).not.toBe(analysisIdA);
      expect(res.body.riskScore).toBe(33);
      expect(res.body.threatLevel).toBe(ThreatLevel.MEDIUM);
      analysisIdB = res.body.analysisId;
    });

    it('should upload Sample C and return distinct analysisId (Risk 75, High)', async () => {
      const res = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', authHeader)
        .attach('file', Buffer.from(sampleC_log), 'sample_c.log');

      expect(res.status).toBe(201);
      expect(res.body.analysisId).toBeDefined();
      expect(res.body.analysisId).not.toBe(analysisIdA);
      expect(res.body.analysisId).not.toBe(analysisIdB);
      expect(res.body.riskScore).toBe(75);
      expect(res.body.threatLevel).toBe(ThreatLevel.HIGH);
      analysisIdC = res.body.analysisId;
    });

    it('should upload Sample D and return distinct analysisId (Risk 98, CRITICAL)', async () => {
      const res = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', authHeader)
        .attach('file', Buffer.from(sampleD_json), 'sample_d.json');

      expect(res.status).toBe(201);
      expect(res.body.analysisId).toBeDefined();
      expect(res.body.riskScore).toBe(98);
      expect(res.body.threatLevel).toBe(ThreatLevel.CRITICAL);
      analysisIdD = res.body.analysisId;
    });

    it('should retrieve each analysis via fresh API request and verify zero cross-contamination', async () => {
      // Retrieve A
      const resA = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${analysisIdA}`)
        .set('Authorization', authHeader);
      expect(resA.status).toBe(200);
      expect(resA.body.riskScore).toBe(3);
      expect(resA.body.threatLevel).toBe(ThreatLevel.LOW);
      expect(resA.body.hostname).toBe('HOST-A-SAFE');
      expect(resA.body.hashes.md5).toBe('aaaaaa00000000000000000000000001');
      expect(resA.body.iocs[0].value).toBe('10.0.0.1');
      // Verify A has NO data from B, C, D
      expect(resA.body.hostname).not.toBe('HOST-B-SUSPICIOUS');
      expect(resA.body.hostname).not.toBe('HOST-C-HIGH');
      expect(resA.body.hostname).not.toBe('HOST-D-CRITICAL');
      expect(resA.body.iocs.some((i: any) => i.value === 'c2-critical-d.org')).toBe(false);

      // Retrieve B
      const resB = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${analysisIdB}`)
        .set('Authorization', authHeader);
      expect(resB.status).toBe(200);
      expect(resB.body.riskScore).toBe(33);
      expect(resB.body.threatLevel).toBe(ThreatLevel.MEDIUM);
      expect(resB.body.hostname).toBe('HOST-B-SUSPICIOUS');
      expect(resB.body.siemEvents[0].sourceIp).toBe('10.0.0.2');
      // Verify B has NO data from A, C, D
      expect(resB.body.hostname).not.toBe('HOST-A-SAFE');

      // Retrieve C
      const resC = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${analysisIdC}`)
        .set('Authorization', authHeader);
      expect(resC.status).toBe(200);
      expect(resC.body.riskScore).toBe(75);
      expect(resC.body.threatLevel).toBe(ThreatLevel.HIGH);
      expect(resC.body.hostname).toBe('HOST-C-HIGH');

      // Retrieve D
      const resD = await request(app.getHttpServer())
        .get(`/api/v1/analyses/${analysisIdD}`)
        .set('Authorization', authHeader);
      expect(resD.status).toBe(200);
      expect(resD.body.riskScore).toBe(98);
      expect(resD.body.threatLevel).toBe(ThreatLevel.CRITICAL);
      expect(resD.body.hostname).toBe('HOST-D-CRITICAL');
      expect(resD.body.incidents.length).toBe(1);
      expect(resD.body.incidents[0].title).toBe('Critical Ransomware Outbreak D');

      // Verify original file on disk exists for Sample D
      const fileMetadata = resD.body.fileMetadata;
      expect(fileMetadata).toBeDefined();
      expect(fs.existsSync(fileMetadata.filePath)).toBe(true);
    });
  });

  describe('3. Error, Rollback & Original File Preservation Test', () => {
    it('should roll back DB transaction on parser error while preserving uploaded source file on disk', async () => {
      const initialCount = await prisma.analysis.count();

      const res = await request(app.getHttpServer())
        .post('/api/v1/analyses/upload')
        .set('Authorization', authHeader)
        .attach('file', Buffer.from('{ malformed raw text json...'), 'malformed.json');

      expect(res.status).toBe(400);

      // Verify DB transaction rolled back
      const finalCount = await prisma.analysis.count();
      expect(finalCount).toBe(initialCount);

      // Verify disk files in /uploads folder are preserved
      const uploadDir = path.resolve(process.cwd(), '../uploads');
      const files = fs.readdirSync(uploadDir);
      const malformedSavedFile = files.find(f => f.includes('malformed.json'));
      expect(malformedSavedFile).toBeDefined();
    });
  });
});
