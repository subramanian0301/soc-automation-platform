import { Test, TestingModule } from '@nestjs/testing';
import { AnalysisNormalizer } from '../src/parser/normalizer/analysis.normalizer';
import { JsonParser } from '../src/parser/parsers/json.parser';
import { CsvParser } from '../src/parser/parsers/csv.parser';
import { TextLogParser } from '../src/parser/parsers/text-log.parser';
import { ParserService } from '../src/parser/parser.service';
import { ThreatLevel } from '@prisma/client';
import { BadRequestException } from '@nestjs/common';

describe('Parser Engine Unit Tests', () => {
  let normalizer: AnalysisNormalizer;
  let jsonParser: JsonParser;
  let csvParser: CsvParser;
  let textLogParser: TextLogParser;
  let parserService: ParserService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AnalysisNormalizer,
        JsonParser,
        CsvParser,
        TextLogParser,
        ParserService,
      ],
    }).compile();

    normalizer = module.get<AnalysisNormalizer>(AnalysisNormalizer);
    jsonParser = module.get<JsonParser>(JsonParser);
    csvParser = module.get<CsvParser>(CsvParser);
    textLogParser = module.get<TextLogParser>(TextLogParser);
    parserService = module.get<ParserService>(ParserService);
  });

  describe('AnalysisNormalizer', () => {
    it('should normalize ThreatLevel enum correctly', () => {
      expect(normalizer.normalizeThreatLevel('Low')).toBe(ThreatLevel.LOW);
      expect(normalizer.normalizeThreatLevel('MEDIUM')).toBe(ThreatLevel.MEDIUM);
      expect(normalizer.normalizeThreatLevel('High')).toBe(ThreatLevel.HIGH);
      expect(normalizer.normalizeThreatLevel('CRITICAL')).toBe(ThreatLevel.CRITICAL);
      expect(normalizer.normalizeThreatLevel('INVALID')).toBeNull();
      expect(normalizer.normalizeThreatLevel(undefined)).toBeNull();
    });

    it('should NOT inject default values for missing fields', () => {
      const normalized = normalizer.normalize({});
      expect(normalized.risk.riskScore).toBeNull();
      expect(normalized.risk.threatLevel).toBeNull();
      expect(normalized.hashes).toBeNull();
      expect(normalized.iocs).toBeNull();
      expect(normalized.mitre).toBeNull();
      expect(normalized.siem).toBeNull();
      expect(normalized.incident).toBeNull();
      expect(normalized.soar).toBeNull();
    });

    it('should reject out-of-domain risk scores instead of silently clamping', () => {
      expect(() => normalizer.normalizeRiskScore(150)).toThrow(BadRequestException);
      expect(() => normalizer.normalizeRiskScore(-10)).toThrow(BadRequestException);
      expect(normalizer.normalizeRiskScore(75)).toBe(75);
      expect(normalizer.normalizeRiskScore('75/100')).toBe(75);
    });
  });

  describe('TextLogParser', () => {
    it('should parse key-value text log and preserve source values', async () => {
      const logContent = `
File Name: sample_malware.exe
Risk Score: 75/100
Threat Level: High
Hostname: WORKSTATION-75
MD5: c157a79031e1c40f85931829bc5fc552
SHA256: 7d10e53a25d2b70f05e324021200dfd3d493a74360e28509d3161c47101859c2
IOC: IP - 198.51.100.75
YARA Rule: Suspicious_PowerShell
`;
      const result = await textLogParser.parse(logContent, {
        originalFileName: 'sample_c.log',
        fileSize: logContent.length,
        mimeType: 'text/plain',
        extension: '.log',
      });

      expect(result.risk.riskScore).toBe(75);
      expect(result.risk.threatLevel).toBe(ThreatLevel.HIGH);
      expect(result.metadata.hostname).toBe('WORKSTATION-75');
      expect(result.hashes?.md5).toBe('c157a79031e1c40f85931829bc5fc552');
      expect(result.hashes?.sha256).toBe('7d10e53a25d2b70f05e324021200dfd3d493a74360e28509d3161c47101859c2');
      expect(result.iocs?.length).toBe(1);
      expect(result.iocs?.[0].value).toBe('198.51.100.75');
      expect(result.yara?.length).toBe(1);
      expect(result.yara?.[0].ruleName).toBe('Suspicious_PowerShell');
    });
  });

  describe('JsonParser', () => {
    it('should parse structured security JSON and preserve source values', async () => {
      const jsonContent = JSON.stringify({
        metadata: {
          hostname: 'SERVER-CRITICAL',
          username: 'admin',
        },
        risk: {
          riskScore: 98,
          threatLevel: 'CRITICAL',
          recommendation: 'Isolate endpoint immediately',
        },
        hashes: {
          sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        },
        iocs: [
          { type: 'DOMAIN', value: 'evil-c2-server.org', confidence: 99 },
        ],
      });

      const result = await jsonParser.parse(jsonContent, {
        originalFileName: 'sample_d.json',
        fileSize: jsonContent.length,
        mimeType: 'application/json',
        extension: '.json',
      });

      expect(result.risk.riskScore).toBe(98);
      expect(result.risk.threatLevel).toBe(ThreatLevel.CRITICAL);
      expect(result.metadata.hostname).toBe('SERVER-CRITICAL');
      expect(result.hashes?.sha256).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
      expect(result.iocs?.length).toBe(1);
      expect(result.iocs?.[0].value).toBe('evil-c2-server.org');
    });
  });

  describe('CsvParser', () => {
    it('should parse CSV event logs into SIEM events and extract risk score', async () => {
      const csvContent = `sourceIp,destIp,sourcePort,destPort,protocol,action,severity,riskScore,threatLevel,rawEvent
10.0.0.1,10.0.0.2,443,80,TCP,ALLOW,LOW,33,Medium,Allowed connection
`;
      const result = await csvParser.parse(csvContent, {
        originalFileName: 'sample_b.csv',
        fileSize: csvContent.length,
        mimeType: 'text/csv',
        extension: '.csv',
      });

      expect(result.risk.riskScore).toBe(33);
      expect(result.risk.threatLevel).toBe(ThreatLevel.MEDIUM);
      expect(result.siem?.length).toBe(1);
      expect(result.siem?.[0].sourceIp).toBe('10.0.0.1');
      expect(result.siem?.[0].destIp).toBe('10.0.0.2');
    });
  });
});
