import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import * as fs from 'fs';
import * as path from 'path';
import { AppModule } from '../src/app.module';
import { PrismaService } from '../src/prisma/prisma.service';
import { getTestAuthHeader } from './auth-helper';

describe('Phase 3 Real-Data E2E Verification', () => {
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

  it('should test complete workflow with high-risk and low-risk real sample files', async () => {
    const highRiskPath = path.resolve(process.cwd(), '../test_samples/high_risk_sample.json');
    const lowRiskPath = path.resolve(process.cwd(), '../test_samples/low_risk_sample.log');

    const highRiskBuffer = fs.readFileSync(highRiskPath);
    const lowRiskBuffer = fs.readFileSync(lowRiskPath);

    // Step 1: Upload High-Risk Sample
    const uploadRes1 = await request(app.getHttpServer())
      .post('/api/v1/analyses/upload')
      .set('Authorization', authHeader)
      .attach('file', highRiskBuffer, 'high_risk_sample.json');

    expect(uploadRes1.status).toBe(201);
    const analysisId1 = uploadRes1.body.analysisId;
    expect(analysisId1).toBeDefined();

    // Step 2: Retrieve High-Risk Sample & verify exact source values
    const getRes1 = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${analysisId1}`)
      .set('Authorization', authHeader);
    expect(getRes1.status).toBe(200);
    expect(getRes1.body.riskScore).toBe(98);
    expect(getRes1.body.threatLevel).toBe('CRITICAL');
    expect(getRes1.body.hostname).toBe('HOST-HIGH-01');
    expect(getRes1.body.fileProperties.entropy).toBe(7.94);
    expect(getRes1.body.fileProperties.digitalSignature).toBe('Not Signed');
    expect(getRes1.body.fileProperties.isPacked).toBe(true);
    expect(getRes1.body.fileProperties.packer).toBe('UPX');
    expect(getRes1.body.yaraResults[0].ruleName).toBe('Trojan.Win32.Loader');
    expect(getRes1.body.virusTotalResult.positives).toBe(68);
    expect(getRes1.body.virusTotalResult.total).toBe(72);

    // Step 3: Upload Low-Risk Sample
    const uploadRes2 = await request(app.getHttpServer())
      .post('/api/v1/analyses/upload')
      .set('Authorization', authHeader)
      .attach('file', lowRiskBuffer, 'low_risk_sample.log');

    expect(uploadRes2.status).toBe(201);
    const analysisId2 = uploadRes2.body.analysisId;
    expect(analysisId2).toBeDefined();
    expect(analysisId2).not.toBe(analysisId1);

    // Step 4: Retrieve Low-Risk Sample & verify exact source values
    const getRes2 = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${analysisId2}`)
      .set('Authorization', authHeader);
    expect(getRes2.status).toBe(200);
    expect(getRes2.body.riskScore).toBe(3);
    expect(getRes2.body.threatLevel).toBe('LOW');
    expect(getRes2.body.hostname).toBe('HOST-LOW-02');
    expect(getRes2.body.virusTotalResult.positives).toBe(0);
    expect(getRes2.body.virusTotalResult.total).toBe(72);

    // Step 5: Switch back to Sample 1 & verify clean retrieval without contamination
    const switchRes1 = await request(app.getHttpServer())
      .get(`/api/v1/analyses/${analysisId1}`)
      .set('Authorization', authHeader);
    expect(switchRes1.status).toBe(200);
    expect(switchRes1.body.riskScore).toBe(98);
    expect(switchRes1.body.threatLevel).toBe('CRITICAL');
    expect(switchRes1.body.hostname).toBe('HOST-HIGH-01');
    expect(switchRes1.body.hostname).not.toBe('HOST-LOW-02');
  });
});
