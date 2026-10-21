import { Injectable } from '@nestjs/common';
import { IFileParser, FileParserOptions } from '../interfaces/parser.interface';
import {
  AnalysisInput,
  AnalysisInputSiem,
  AnalysisInputIoc,
  AnalysisInputVulnerability,
  AnalysisInputAsset,
  AnalysisInputEndpoint,
  AnalysisInputSoar,
  AnalysisInputMitre,
  AnalysisInputBehavior,
  AnalysisInputSandbox,
  AnalysisInputYara,
  AnalysisInputIncident,
} from '../interfaces/analysis-input.interface';
import { AnalysisNormalizer } from '../normalizer/analysis.normalizer';
import { ALIAS_MAPS, findValueByAliases, classifyItemEntity, normalizeKey } from '../alias-registry';

@Injectable()
export class CsvParser implements IFileParser {
  constructor(private readonly normalizer: AnalysisNormalizer) {}

  canParse(extension: string, mimeType: string, content?: string): boolean {
    const ext = extension.toLowerCase();
    if (ext === '.csv' || mimeType.includes('csv') || mimeType.includes('excel')) {
      return true;
    }
    if (content) {
      const firstLine = content.split(/\r?\n/)[0] || '';
      if (firstLine.includes(',') || firstLine.includes(';') || firstLine.includes('\t')) {
        return true;
      }
    }
    return false;
  }

  private detectDelimiter(line: string): string {
    const commas = (line.match(/,/g) || []).length;
    const semicolons = (line.match(/;/g) || []).length;
    const tabs = (line.match(/\t/g) || []).length;
    const pipes = (line.match(/\|/g) || []).length;

    let max = commas;
    let delim = ',';
    if (semicolons > max) { max = semicolons; delim = ';'; }
    if (tabs > max) { max = tabs; delim = '\t'; }
    if (pipes > max) { max = pipes; delim = '|'; }
    return delim;
  }

  private parseCsvLines(content: string): string[][] {
    const rawLines = content.split(/\r?\n/).filter(line => line.trim().length > 0);
    if (rawLines.length === 0) return [];

    const delimiter = this.detectDelimiter(rawLines[0]);
    const lines: string[][] = [];

    for (const line of rawLines) {
      const row: string[] = [];
      let current = '';
      let inQuotes = false;

      for (let i = 0; i < line.length; i++) {
        const char = line[i];
        if (char === '"') {
          if (inQuotes && i + 1 < line.length && line[i + 1] === '"') {
            current += '"';
            i++; // Skip escaped double quote
          } else {
            inQuotes = !inQuotes;
          }
        } else if (char === delimiter && !inQuotes) {
          row.push(current.trim());
          current = '';
        } else {
          current += char;
        }
      }
      row.push(current.trim());
      lines.push(row);
    }
    return lines;
  }

  parse(content: string, options: FileParserOptions): AnalysisInput {
    const rows = this.parseCsvLines(content);
    if (rows.length === 0) {
      return this.normalizer.normalize({
        metadata: {
          fileName: options.originalFileName,
          originalFileName: options.originalFileName,
          fileSize: options.fileSize,
          fileType: 'CSV',
          mimeType: options.mimeType,
        },
        risk: {},
      });
    }

    const rawHeaders = rows[0];
    const headers = rawHeaders.map(h => normalizeKey(h));
    const dataRows = rows.slice(1);

    let riskScore: number | null = null;
    let threatLevel: string | null = null;
    let hostname: string | null = null;
    let username: string | null = null;
    let operatingSystem: string | null = null;
    let recommendation: string | null = null;
    let md5: string | null = null;
    let sha256: string | null = null;

    const siemEvents: AnalysisInputSiem[] = [];
    const iocs: AnalysisInputIoc[] = [];
    const vulnerabilities: AnalysisInputVulnerability[] = [];
    const assets: AnalysisInputAsset[] = [];
    const endpoints: AnalysisInputEndpoint[] = [];
    const soarExecutions: AnalysisInputSoar[] = [];
    const mitreTechniques: AnalysisInputMitre[] = [];
    const behaviorEvents: AnalysisInputBehavior[] = [];
    const sandboxResults: AnalysisInputSandbox[] = [];
    const yaraResults: AnalysisInputYara[] = [];
    const incidents: AnalysisInputIncident[] = [];
    const unmappedRows: any[] = [];

    dataRows.forEach((row, rowIndex) => {
      const rowObj: Record<string, string> = {};
      rawHeaders.forEach((rawHeader, index) => {
        if (index < row.length) {
          rowObj[rawHeader] = row[index];
          rowObj[normalizeKey(rawHeader)] = row[index];
        }
      });

      // Extract metadata / risk values from row using ALIAS_MAPS
      if (riskScore === null) {
        const val = findValueByAliases(rowObj, ALIAS_MAPS.risk.riskScore);
        if (val !== undefined && val !== null && val !== '') {
          const parsed = parseInt(val, 10);
          if (!isNaN(parsed)) riskScore = parsed;
        }
      }
      if (!threatLevel) threatLevel = findValueByAliases(rowObj, ALIAS_MAPS.risk.threatLevel) || null;
      if (!hostname) hostname = findValueByAliases(rowObj, ALIAS_MAPS.metadata.hostname) || null;
      if (!username) username = findValueByAliases(rowObj, ALIAS_MAPS.metadata.username) || null;
      if (!operatingSystem) operatingSystem = findValueByAliases(rowObj, ALIAS_MAPS.metadata.operatingSystem) || null;
      if (!recommendation) recommendation = findValueByAliases(rowObj, ALIAS_MAPS.risk.recommendation) || null;
      if (!md5) md5 = findValueByAliases(rowObj, ALIAS_MAPS.hashes.md5) || null;
      if (!sha256) sha256 = findValueByAliases(rowObj, ALIAS_MAPS.hashes.sha256) || null;

      // Classify row using classifyItemEntity
      const entityType = classifyItemEntity(rowObj);
      let matched = false;

      if (entityType === 'vulnerabilities') {
        matched = true;
        const cveId = findValueByAliases(rowObj, ALIAS_MAPS.vulnerabilities.cveId) || `CVE-CSV-${rowIndex + 1}`;
        const title = findValueByAliases(rowObj, ALIAS_MAPS.vulnerabilities.title) || cveId;
        const cvssVal = findValueByAliases(rowObj, ALIAS_MAPS.vulnerabilities.cvssScore);
        vulnerabilities.push({
          cveId,
          title,
          cvssScore: cvssVal ? parseFloat(cvssVal) : null,
          severity: findValueByAliases(rowObj, ALIAS_MAPS.vulnerabilities.severity) || threatLevel || null,
          description: findValueByAliases(rowObj, ALIAS_MAPS.vulnerabilities.description) || null,
          affectedAsset: findValueByAliases(rowObj, ALIAS_MAPS.vulnerabilities.affectedAsset) || null,
          packageName: findValueByAliases(rowObj, ALIAS_MAPS.vulnerabilities.packageName) || null,
          installedVersion: findValueByAliases(rowObj, ALIAS_MAPS.vulnerabilities.installedVersion) || null,
          fixedVersion: findValueByAliases(rowObj, ALIAS_MAPS.vulnerabilities.fixedVersion) || null,
          status: findValueByAliases(rowObj, ALIAS_MAPS.vulnerabilities.status) || 'OPEN',
          remediation: findValueByAliases(rowObj, ALIAS_MAPS.vulnerabilities.remediation) || null,
        });
      } else if (entityType === 'assets') {
        matched = true;
        const name = findValueByAliases(rowObj, ALIAS_MAPS.assets.assetName) || hostname || `Asset-${rowIndex + 1}`;
        assets.push({
          assetName: name,
          hostname: findValueByAliases(rowObj, ALIAS_MAPS.assets.hostname) || hostname || null,
          ipAddress: findValueByAliases(rowObj, ALIAS_MAPS.assets.ipAddress) || null,
          macAddress: findValueByAliases(rowObj, ALIAS_MAPS.assets.macAddress) || null,
          assetType: findValueByAliases(rowObj, ALIAS_MAPS.assets.assetType) || null,
          criticality: findValueByAliases(rowObj, ALIAS_MAPS.assets.criticality) || null,
          operatingSystem: findValueByAliases(rowObj, ALIAS_MAPS.assets.operatingSystem) || operatingSystem || null,
          owner: findValueByAliases(rowObj, ALIAS_MAPS.assets.owner) || username || null,
          status: findValueByAliases(rowObj, ALIAS_MAPS.assets.status) || 'Active',
          description: findValueByAliases(rowObj, ALIAS_MAPS.assets.description) || null,
        });
      } else if (entityType === 'endpoints') {
        matched = true;
        const host = findValueByAliases(rowObj, ALIAS_MAPS.endpoints.hostname) || hostname || `Endpoint-${rowIndex + 1}`;
        endpoints.push({
          hostname: host,
          ipAddress: findValueByAliases(rowObj, ALIAS_MAPS.endpoints.ipAddress) || null,
          osVersion: findValueByAliases(rowObj, ALIAS_MAPS.endpoints.osVersion) || operatingSystem || null,
          operatingSystem: findValueByAliases(rowObj, ALIAS_MAPS.endpoints.operatingSystem) || operatingSystem || null,
          user: findValueByAliases(rowObj, ALIAS_MAPS.endpoints.user) || username || null,
          agentStatus: findValueByAliases(rowObj, ALIAS_MAPS.endpoints.agentStatus) || 'ONLINE',
          status: findValueByAliases(rowObj, ALIAS_MAPS.endpoints.status) || 'ACTIVE',
          endpointType: findValueByAliases(rowObj, ALIAS_MAPS.endpoints.endpointType) || null,
          lastSeen: findValueByAliases(rowObj, ALIAS_MAPS.endpoints.lastSeen) ? new Date(findValueByAliases(rowObj, ALIAS_MAPS.endpoints.lastSeen)) : null,
        });
      } else if (entityType === 'soar') {
        matched = true;
        const actName = findValueByAliases(rowObj, ALIAS_MAPS.soar.actionName) || `Action-${rowIndex + 1}`;
        soarExecutions.push({
          actionName: actName,
          description: findValueByAliases(rowObj, ALIAS_MAPS.soar.description) || null,
          actionType: findValueByAliases(rowObj, ALIAS_MAPS.soar.actionType) || null,
          target: findValueByAliases(rowObj, ALIAS_MAPS.soar.target) || null,
          status: (findValueByAliases(rowObj, ALIAS_MAPS.soar.status) || 'RECOMMENDED') as any,
          triggeredBy: findValueByAliases(rowObj, ALIAS_MAPS.soar.triggeredBy) || 'Source',
          source: 'CSV',
          result: findValueByAliases(rowObj, ALIAS_MAPS.soar.result) || null,
          executionLog: findValueByAliases(rowObj, ALIAS_MAPS.soar.executionLog) || null,
        });
      } else if (entityType === 'mitre') {
        matched = true;
        mitreTechniques.push({
          tactic: findValueByAliases(rowObj, ALIAS_MAPS.mitre.tactic) || 'Execution',
          techniqueId: (findValueByAliases(rowObj, ALIAS_MAPS.mitre.techniqueId) || 'T1000').toUpperCase(),
          name: findValueByAliases(rowObj, ALIAS_MAPS.mitre.name) || 'Mitre Technique',
          description: findValueByAliases(rowObj, ALIAS_MAPS.mitre.description) || null,
        });
      } else if (entityType === 'yara') {
        matched = true;
        yaraResults.push({
          ruleName: findValueByAliases(rowObj, ALIAS_MAPS.yara.ruleName) || `YARA-Rule-${rowIndex + 1}`,
          namespace: findValueByAliases(rowObj, ALIAS_MAPS.yara.namespace) || null,
          description: findValueByAliases(rowObj, ALIAS_MAPS.yara.description) || null,
        });
      } else if (entityType === 'sandbox') {
        matched = true;
        const scoreVal = findValueByAliases(rowObj, ALIAS_MAPS.sandbox.score);
        sandboxResults.push({
          sandboxName: findValueByAliases(rowObj, ALIAS_MAPS.sandbox.sandboxName) || 'CSV Sandbox',
          verdict: findValueByAliases(rowObj, ALIAS_MAPS.sandbox.verdict) || 'UNKNOWN',
          score: scoreVal ? parseInt(scoreVal, 10) : null,
          details: findValueByAliases(rowObj, ALIAS_MAPS.sandbox.details) || null,
        });
      } else if (entityType === 'iocs') {
        matched = true;
        const iocVal = findValueByAliases(rowObj, ALIAS_MAPS.iocs.value);
        if (iocVal) {
          const confVal = findValueByAliases(rowObj, ALIAS_MAPS.iocs.confidence);
          iocs.push({
            type: (findValueByAliases(rowObj, ALIAS_MAPS.iocs.type) || 'INDICATOR').toUpperCase(),
            value: iocVal,
            category: findValueByAliases(rowObj, ALIAS_MAPS.iocs.category) || null,
            confidence: confVal ? parseInt(confVal, 10) : null,
            description: findValueByAliases(rowObj, ALIAS_MAPS.iocs.description) || null,
          });
        }
      } else if (entityType === 'siem') {
        matched = true;
        const srcPortVal = findValueByAliases(rowObj, ALIAS_MAPS.siem.sourcePort);
        const dstPortVal = findValueByAliases(rowObj, ALIAS_MAPS.siem.destPort);
        const tsVal = findValueByAliases(rowObj, ALIAS_MAPS.siem.timestamp);
        siemEvents.push({
          eventId: findValueByAliases(rowObj, ALIAS_MAPS.siem.eventId) || `CSV-ROW-${rowIndex + 1}`,
          sourceIp: findValueByAliases(rowObj, ALIAS_MAPS.siem.sourceIp) || null,
          destIp: findValueByAliases(rowObj, ALIAS_MAPS.siem.destIp) || null,
          sourcePort: srcPortVal ? parseInt(srcPortVal, 10) : null,
          destPort: dstPortVal ? parseInt(dstPortVal, 10) : null,
          protocol: findValueByAliases(rowObj, ALIAS_MAPS.siem.protocol) || null,
          action: findValueByAliases(rowObj, ALIAS_MAPS.siem.action) || null,
          severity: findValueByAliases(rowObj, ALIAS_MAPS.siem.severity) || null,
          rawEvent: findValueByAliases(rowObj, ALIAS_MAPS.siem.rawEvent) || row.join(', '),
          timestamp: tsVal ? new Date(tsVal) : new Date(),
        });
      } else if (entityType === 'incident') {
        matched = true;
        incidents.push({
          title: findValueByAliases(rowObj, ALIAS_MAPS.incidents.title) || `CSV Incident ${rowIndex + 1}`,
          severity: findValueByAliases(rowObj, ALIAS_MAPS.incidents.severity) || threatLevel || null,
          status: findValueByAliases(rowObj, ALIAS_MAPS.incidents.status) || 'OPEN',
          reason: findValueByAliases(rowObj, ALIAS_MAPS.incidents.reason) || 'Source explicit CSV incident record',
          assignedTo: findValueByAliases(rowObj, ALIAS_MAPS.incidents.assignedTo) || null,
        });
      }

      if (!matched) {
        unmappedRows.push(rowObj);
      }
    });

    const providedSections: string[] = [];
    if (yaraResults.length > 0 || headers.some(h => h.includes('yara') || h.includes('rulename'))) providedSections.push('yara');
    if (headers.some(h => h.includes('virustotal') || h.includes('vt'))) providedSections.push('virusTotal');
    if (iocs.length > 0 || headers.some(h => h.includes('ioc') || h.includes('indicator'))) providedSections.push('iocs');
    if (mitreTechniques.length > 0 || headers.some(h => h.includes('mitre') || h.includes('technique'))) providedSections.push('mitre');
    if (behaviorEvents.length > 0 || headers.some(h => h.includes('behavior'))) providedSections.push('behavior');
    if (sandboxResults.length > 0 || headers.some(h => h.includes('sandbox') || h.includes('verdict'))) providedSections.push('sandbox');
    if (siemEvents.length > 0 || headers.some(h => h.includes('siem') || h.includes('sourceip') || h.includes('rawevent'))) providedSections.push('siem');
    if (incidents.length > 0 || headers.some(h => h.includes('incident'))) providedSections.push('incident');
    if (soarExecutions.length > 0 || headers.some(h => h.includes('soar') || h.includes('playbook'))) providedSections.push('soar');
    if (assets.length > 0 || headers.some(h => h.includes('asset'))) providedSections.push('assets');
    if (endpoints.length > 0 || headers.some(h => h.includes('endpoint') || h.includes('agentstatus'))) providedSections.push('endpoints');
    if (vulnerabilities.length > 0 || headers.some(h => h.includes('cve') || h.includes('vulnerability') || h.includes('cvss'))) providedSections.push('vulnerabilities');

    const rawInput: Partial<AnalysisInput> = {
      metadata: {
        fileName: options.originalFileName,
        originalFileName: options.originalFileName,
        fileSize: options.fileSize,
        fileType: 'CSV',
        mimeType: options.mimeType,
        hostname,
        username,
        operatingSystem,
      },
      risk: {
        riskScore,
        threatLevel,
        recommendation,
      },
      hashes: (md5 || sha256) ? { md5, sha256 } : null,
      siem: siemEvents.length > 0 ? siemEvents : null,
      iocs: iocs.length > 0 ? iocs : null,
      vulnerabilities: vulnerabilities.length > 0 ? vulnerabilities : null,
      assets: assets.length > 0 ? assets : null,
      endpoints: endpoints.length > 0 ? endpoints : null,
      soar: soarExecutions.length > 0 ? soarExecutions : null,
      mitre: mitreTechniques.length > 0 ? mitreTechniques : null,
      behavior: behaviorEvents.length > 0 ? behaviorEvents : null,
      sandbox: sandboxResults.length > 0 ? sandboxResults : null,
      yara: yaraResults.length > 0 ? yaraResults : null,
      incident: incidents.length > 0 ? incidents : null,
      unrecognizedFields: unmappedRows.length > 0 ? { unmappedRows } : null,
      provenance: {
        parser: 'CsvParser',
        sourceType: 'CSV',
        totalRows: dataRows.length,
        unmappedRowCount: unmappedRows.length,
        providedSections,
      },
    };

    return this.normalizer.normalize(rawInput);
  }
}
