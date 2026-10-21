import { Injectable, BadRequestException } from '@nestjs/common';
import { IFileParser, FileParserOptions } from '../interfaces/parser.interface';
import { AnalysisInput } from '../interfaces/analysis-input.interface';
import { AnalysisNormalizer } from '../normalizer/analysis.normalizer';
import { ALIAS_MAPS, SECTION_ALIASES, findValueByAliases, classifyItemEntity, normalizeKey } from '../alias-registry';

@Injectable()
export class JsonParser implements IFileParser {
  constructor(private readonly normalizer: AnalysisNormalizer) {}

  canParse(extension: string, mimeType: string, content: string): boolean {
    const ext = extension.toLowerCase();
    if (ext === '.json' || ext === '.jsonl' || ext === '.ndjson' || mimeType.includes('json')) {
      return true;
    }
    const trimmed = content ? content.trim() : '';
    if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
      try {
        JSON.parse(trimmed);
        return true;
      } catch (e) {
        // Fall through to NDJSON check
      }
    }
    // Check if it's NDJSON: non-empty content where lines parse as JSON objects
    if (trimmed.length > 0) {
      const lines = trimmed.split(/\r?\n/).map(l => l.trim()).filter(l => l.length > 0);
      if (lines.length >= 1 && lines[0].startsWith('{') && lines[0].endsWith('}')) {
        try {
          const sample = lines.slice(0, Math.min(lines.length, 5));
          if (sample.every(line => {
            const parsed = JSON.parse(line);
            return typeof parsed === 'object' && parsed !== null;
          })) {
            return true;
          }
        } catch {
          // Not NDJSON
        }
      }
    }
    return false;
  }

  // Recursive deep search for scalar or section properties
  private getValueDeep(obj: any, aliases: string[], primitiveOnly = true, maxDepth = 5, currentDepth = 0): any {
    if (!obj || typeof obj !== 'object' || currentDepth > maxDepth) return undefined;

    // Direct check at current level
    const directVal = findValueByAliases(obj, aliases, primitiveOnly);
    if (directVal !== undefined && directVal !== null) {
      return directVal;
    }

    // Deep search child objects (skipping arrays for scalar lookup)
    for (const key of Object.keys(obj)) {
      const child = obj[key];
      if (child && typeof child === 'object' && !Array.isArray(child)) {
        const found = this.getValueDeep(child, aliases, primitiveOnly, maxDepth, currentDepth + 1);
        if (found !== undefined && found !== null) {
          return found;
        }
      }
    }

    return undefined;
  }

  // Find array or object section by section aliases
  private getSectionDeep(obj: any, sectionKey: string, maxDepth = 5, currentDepth = 0): any {
    if (!obj || typeof obj !== 'object' || currentDepth > maxDepth) return undefined;

    const aliases = SECTION_ALIASES[sectionKey] || [sectionKey];
    const normalizedAliases = new Set(aliases.map(normalizeKey));

    for (const key of Object.keys(obj)) {
      if (normalizedAliases.has(normalizeKey(key))) {
        return obj[key];
      }
    }

    for (const key of Object.keys(obj)) {
      const child = obj[key];
      if (child && typeof child === 'object' && !Array.isArray(child)) {
        const found = this.getSectionDeep(child, sectionKey, maxDepth, currentDepth + 1);
        if (found !== undefined) return found;
      }
    }

    return undefined;
  }

  parse(content: string, options: FileParserOptions): AnalysisInput {
    let parsedJson: any;
    let isNdjson = false;
    try {
      parsedJson = JSON.parse(content);
    } catch (e) {
      const trimmed = content ? content.trim() : '';
      const lines = trimmed.split(/\r?\n/).map(l => l.trim()).filter(l => l.length > 0);
      if (lines.length > 0) {
        try {
          const items = lines.map(line => JSON.parse(line));
          if (items.every(it => typeof it === 'object' && it !== null)) {
            parsedJson = items;
            isNdjson = true;
          } else {
            throw new BadRequestException(`Malformed JSON document: ${e.message}`);
          }
        } catch (ndErr) {
          throw new BadRequestException(`Malformed JSON document: ${e.message}`);
        }
      } else {
        throw new BadRequestException(`Malformed JSON document: ${e.message}`);
      }
    }

    const warnings: string[] = [];
    const unrecognizedFields: Record<string, any> = {};

    let rootObj: any = parsedJson;
    let itemsArray: any[] | null = null;

    if (Array.isArray(parsedJson)) {
      itemsArray = parsedJson;
      rootObj = {};
    } else if (typeof parsedJson === 'object' && parsedJson !== null) {
      const containerKeys = [
        'data', 'report', 'results', 'analysis', 'payload', 'item', 'items', 'content',
        'security_report', 'scan_results', 'threat_data',
        'events', 'logs', 'siem', 'siem_events', 'records', 'entries', 'telemetry', 'audit_logs', 'security_events'
      ];
      for (const cKey of containerKeys) {
        if (parsedJson[cKey] && typeof parsedJson[cKey] === 'object') {
          if (Array.isArray(parsedJson[cKey])) {
            itemsArray = parsedJson[cKey];
          }
          break;
        }
      }
    } else {
      throw new BadRequestException('JSON payload must be an object or array.');
    }

    // Scalar & Metadata extraction via central ALIAS_MAPS
    const hostname = this.getValueDeep(rootObj, ALIAS_MAPS.metadata.hostname, true);
    const username = this.getValueDeep(rootObj, ALIAS_MAPS.metadata.username, true);
    const operatingSystem = this.getValueDeep(rootObj, ALIAS_MAPS.metadata.operatingSystem, true);
    const analysisTime = this.getValueDeep(rootObj, ALIAS_MAPS.metadata.analysisTime, true);

    // Risk extraction
    const riskScore = this.getValueDeep(rootObj, ALIAS_MAPS.risk.riskScore, true);
    const threatLevel = this.getValueDeep(rootObj, ALIAS_MAPS.risk.threatLevel, true);
    const recommendation = this.getValueDeep(rootObj, ALIAS_MAPS.risk.recommendation, true);

    // Hashes extraction
    const md5 = this.getValueDeep(rootObj, ALIAS_MAPS.hashes.md5, true);
    const sha1 = this.getValueDeep(rootObj, ALIAS_MAPS.hashes.sha1, true);
    const sha256 = this.getValueDeep(rootObj, ALIAS_MAPS.hashes.sha256, true);
    const ssdeep = this.getValueDeep(rootObj, ALIAS_MAPS.hashes.ssdeep, true);

    // File Properties
    const entropy = this.getValueDeep(rootObj, ALIAS_MAPS.fileProperties.entropy, true);
    const digitalSignature = this.getValueDeep(rootObj, ALIAS_MAPS.fileProperties.digitalSignature, true);
    const isPacked = this.getValueDeep(rootObj, ALIAS_MAPS.fileProperties.isPacked, true);
    const packer = this.getValueDeep(rootObj, ALIAS_MAPS.fileProperties.packer, true);
    const imports = this.getValueDeep(rootObj, ALIAS_MAPS.fileProperties.imports, false);
    const suspiciousApis = this.getValueDeep(rootObj, ALIAS_MAPS.fileProperties.suspiciousApis, false);

    // Collection Sections
    let yara = this.getSectionDeep(rootObj, 'yara');
    let virusTotal = this.getSectionDeep(rootObj, 'virusTotal');
    let iocs = this.getSectionDeep(rootObj, 'iocs');
    let mitre = this.getSectionDeep(rootObj, 'mitre');
    let behavior = this.getSectionDeep(rootObj, 'behavior');
    let sandbox = this.getSectionDeep(rootObj, 'sandbox');
    let siem = this.getSectionDeep(rootObj, 'siem');
    let incident = this.getSectionDeep(rootObj, 'incident');
    let soar = this.getSectionDeep(rootObj, 'soar');
    let assets = this.getSectionDeep(rootObj, 'assets');
    let endpoints = this.getSectionDeep(rootObj, 'endpoints');
    let vulnerabilities = this.getSectionDeep(rootObj, 'vulnerabilities');

    if (siem && !Array.isArray(siem) && typeof siem === 'object') {
      siem = [siem];
    }

    // If root object is a standalone SIEM event (no top-level static report sections)
    if (!itemsArray && (!siem || (Array.isArray(siem) && siem.length === 0)) && !yara && !virusTotal && !mitre) {
      if (
        classifyItemEntity(rootObj) === 'siem' ||
        rootObj.src_ip || rootObj.source_ip || rootObj.sourceIp ||
        rootObj.dst_ip || rootObj.dest_ip || rootObj.destIp ||
        rootObj.eventId || rootObj.event_id ||
        (rootObj.rawEvent && (rootObj.timestamp || rootObj.action || rootObj.severity))
      ) {
        siem = [rootObj];
      }
    }

    // If itemsArray is already one of the explicitly extracted sections, do not re-categorize it as an unclassified items container
    if (
      itemsArray &&
      (itemsArray === siem ||
       itemsArray === yara ||
       itemsArray === mitre ||
       itemsArray === behavior ||
       itemsArray === sandbox ||
       itemsArray === incident ||
       itemsArray === soar ||
       itemsArray === assets ||
       itemsArray === endpoints ||
       itemsArray === vulnerabilities)
    ) {
      itemsArray = null;
    }

    // If root was an array or container of items, dynamically categorize items using classifyItemEntity
    if (itemsArray && Array.isArray(itemsArray)) {
      yara = yara || [];
      iocs = iocs || [];
      mitre = mitre || [];
      behavior = behavior || [];
      sandbox = sandbox || [];
      siem = siem || [];
      incident = incident || [];
      soar = soar || [];
      assets = assets || [];
      endpoints = endpoints || [];
      vulnerabilities = vulnerabilities || [];

      for (const item of [...itemsArray]) {
        if (!item) continue;

        if (typeof item === 'string') {
          siem.push({
            rawEvent: item,
            timestamp: new Date(),
          });
          continue;
        }

        if (typeof item !== 'object') continue;

        const category = classifyItemEntity(item);
        if (category === 'vulnerabilities') vulnerabilities.push(item);
        else if (category === 'yara') yara.push(item);
        else if (category === 'mitre') mitre.push(item);
        else if (category === 'sandbox') sandbox.push(item);
        else if (category === 'soar') soar.push(item);
        else if (category === 'behavior') behavior.push(item);
        else if (category === 'assets') assets.push(item);
        else if (category === 'endpoints') endpoints.push(item);
        else if (category === 'iocs') iocs.push(item);
        else if (category === 'siem') siem.push(item);
        else if (category === 'incident') incident.push(item);
        else {
          if (item.rawEvent || item.message || item.msg || item.log || item.event || item.src || item.src_ip || item.client_ip) {
            siem.push(item);
          } else {
            if (!unrecognizedFields.unparsedItems) unrecognizedFields.unparsedItems = [];
            unrecognizedFields.unparsedItems.push(item);
          }
        }
      }
    }

    // Normalize structured objects into arrays or canonical forms
    if (yara && typeof yara === 'object' && !Array.isArray(yara)) {
      if (Array.isArray(yara.matches)) yara = yara.matches;
      else if (Array.isArray(yara.rules)) yara = yara.rules;
      else if (Array.isArray(yara.results)) yara = yara.results;
      else if (Array.isArray(yara.signatures)) yara = yara.signatures;
      else if (Array.isArray(yara.items)) yara = yara.items;
      else if (yara.rule || yara.ruleName) yara = [yara];
    }

    if (mitre && typeof mitre === 'object' && !Array.isArray(mitre)) {
      if (Array.isArray(mitre.techniques)) mitre = mitre.techniques;
      else if (Array.isArray(mitre.technique_list)) mitre = mitre.technique_list;
      else if (Array.isArray(mitre.attack_techniques)) mitre = mitre.attack_techniques;
      else if (Array.isArray(mitre.items)) mitre = mitre.items;
      else if (mitre.id || mitre.techniqueId) mitre = [mitre];
    }

    if (sandbox && typeof sandbox === 'object' && !Array.isArray(sandbox)) {
      if (Array.isArray(sandbox.runs)) sandbox = sandbox.runs;
      else if (Array.isArray(sandbox.results)) sandbox = sandbox.results;
      else if (Array.isArray(sandbox.executions)) sandbox = sandbox.executions;
      else if (Array.isArray(sandbox.items)) sandbox = sandbox.items;
      else if (sandbox.verdict || sandbox.sandboxName || sandbox.sandbox_name) sandbox = [sandbox];
    }

    if (behavior && typeof behavior === 'object' && !Array.isArray(behavior)) {
      if (Array.isArray(behavior.events)) behavior = behavior.events;
      else if (Array.isArray(behavior.behavior_events)) behavior = behavior.behavior_events;
      else if (Array.isArray(behavior.items)) behavior = behavior.items;
      else {
        const items: any[] = [];
        for (const [k, v] of Object.entries(behavior)) {
          if (v !== null && v !== undefined && v !== '' && v !== false && v !== 'No' && v !== 'None' && v !== '0' && v !== 'na') {
            if (typeof v === 'object') {
              if (Array.isArray(v)) items.push(...v);
              else items.push(v);
            } else {
              items.push({
                eventType: 'BEHAVIOR',
                action: 'OBSERVED',
                target: String(v),
                details: `Source attribute: ${k}`,
              });
            }
          }
        }
        behavior = items.length > 0 ? items : null;
      }
    }

    if (iocs && typeof iocs === 'object' && !Array.isArray(iocs)) {
      const explicitIocs: any[] = [];
      if (Array.isArray(iocs.ips)) {
        for (const ip of iocs.ips) {
          explicitIocs.push({ type: 'IP', value: String(ip), category: 'Network / External IP' });
        }
      }
      if (Array.isArray(iocs.domains)) {
        for (const d of iocs.domains) {
          explicitIocs.push({ type: 'DOMAIN', value: String(d), category: 'Network / Domain Name' });
        }
      }
      if (Array.isArray(iocs.urls)) {
        for (const u of iocs.urls) {
          explicitIocs.push({ type: 'URL', value: String(u), category: 'Network / Web URL' });
        }
      }
      if (Array.isArray(iocs.emails)) {
        for (const em of iocs.emails) {
          explicitIocs.push({ type: 'EMAIL', value: String(em), category: 'Communication / Email' });
        }
      }
      if (iocs.hashes) {
        if (Array.isArray(iocs.hashes)) {
          for (const h of iocs.hashes) {
            explicitIocs.push({ type: 'HASH', value: String(h), category: 'Host / File Hash' });
          }
        } else if (typeof iocs.hashes === 'object') {
          for (const [algo, hashList] of Object.entries(iocs.hashes)) {
            if (Array.isArray(hashList)) {
              for (const h of hashList) {
                explicitIocs.push({ type: 'HASH', value: String(h), category: `Host / File Hash (${algo.toUpperCase()})` });
              }
            } else if (typeof hashList === 'string') {
              explicitIocs.push({ type: 'HASH', value: hashList, category: `Host / File Hash (${algo.toUpperCase()})` });
            }
          }
        }
      }
      iocs = explicitIocs.length > 0 ? explicitIocs : null;
    }

    // Track provided sections
    const providedSections: string[] = [];
    if (this.getSectionDeep(parsedJson, 'yara') !== undefined || (Array.isArray(yara) && yara.length > 0)) providedSections.push('yara');
    if (this.getSectionDeep(parsedJson, 'virusTotal') !== undefined || Boolean(virusTotal)) providedSections.push('virusTotal');
    if (this.getSectionDeep(parsedJson, 'iocs') !== undefined || (Array.isArray(iocs) && iocs.length > 0)) providedSections.push('iocs');
    if (this.getSectionDeep(parsedJson, 'mitre') !== undefined || (Array.isArray(mitre) && mitre.length > 0)) providedSections.push('mitre');
    if (this.getSectionDeep(parsedJson, 'behavior') !== undefined || (Array.isArray(behavior) && behavior.length > 0)) providedSections.push('behavior');
    if (this.getSectionDeep(parsedJson, 'sandbox') !== undefined || (Array.isArray(sandbox) && sandbox.length > 0)) providedSections.push('sandbox');
    if (this.getSectionDeep(parsedJson, 'siem') !== undefined || (Array.isArray(siem) && siem.length > 0)) providedSections.push('siem');
    if (this.getSectionDeep(parsedJson, 'incident') !== undefined || (Array.isArray(incident) && incident.length > 0)) providedSections.push('incident');
    if (this.getSectionDeep(parsedJson, 'soar') !== undefined || (Array.isArray(soar) && soar.length > 0)) providedSections.push('soar');
    if (this.getSectionDeep(parsedJson, 'assets') !== undefined || (Array.isArray(assets) && assets.length > 0)) providedSections.push('assets');
    if (this.getSectionDeep(parsedJson, 'endpoints') !== undefined || (Array.isArray(endpoints) && endpoints.length > 0)) providedSections.push('endpoints');
    if (this.getSectionDeep(parsedJson, 'vulnerabilities') !== undefined || (Array.isArray(vulnerabilities) && vulnerabilities.length > 0)) providedSections.push('vulnerabilities');

    // Collect unrecognized top-level keys and map line numbers for diagnostic warnings
    if (typeof parsedJson === 'object' && !Array.isArray(parsedJson)) {
      const knownKeys = new Set<string>();
      Object.values(ALIAS_MAPS).forEach(entityMap => {
        Object.values(entityMap).forEach(aliases => {
          aliases.forEach(a => knownKeys.add(normalizeKey(a)));
        });
      });
      Object.values(SECTION_ALIASES).forEach(aliases => {
        aliases.forEach(a => knownKeys.add(normalizeKey(a)));
      });
      ['reportmetadata', 'report_metadata', 'metadata', 'sample', 'file', 'data', 'report', 'results', 'analysis'].forEach(k => knownKeys.add(normalizeKey(k)));

      const sourceLines = content.split(/\r?\n/);
      const findKeyLine = (k: string): number => {
        const escaped = k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const reg = new RegExp(`["']${escaped}["']\\s*:`);
        for (let idx = 0; idx < sourceLines.length; idx++) {
          if (reg.test(sourceLines[idx])) return idx + 1;
        }
        return 1;
      };

      for (const k of Object.keys(parsedJson)) {
        if (!knownKeys.has(normalizeKey(k))) {
          unrecognizedFields[k] = parsedJson[k];
          const lineNum = findKeyLine(k);
          const val = parsedJson[k];

          if (typeof val === 'string') {
            const noteLines = val.split(/\r?\n/).filter((l: string) => l.trim().length > 0);
            if (noteLines.length > 1) {
              const total = noteLines.length;
              noteLines.forEach((nl, idx) => {
                warnings.push(`Line ${lineNum}: [${k}] (note ${idx + 1} of ${total}) "${nl.trim()}" could not be matched to a canonical entity schema (unstructured multi-line text).`);
              });
            } else {
              warnings.push(`Line ${lineNum}: Unrecognized field '${k}' with value "${val.trim()}" could not be matched to a canonical entity schema.`);
            }
          } else if (typeof val === 'object' && val !== null && !Array.isArray(val)) {
            const entries = Object.entries(val);
            if (entries.length === 0) {
              warnings.push(`Line ${lineNum}: Unrecognized section '${k}' could not be matched to a canonical entity schema.`);
            } else {
              for (const [subK, subV] of entries) {
                const subLine = findKeyLine(subK);
                if (typeof subV === 'string' && subV.includes('\n')) {
                  const subNoteLines = subV.split(/\r?\n/).filter((l: string) => l.trim().length > 0);
                  const total = subNoteLines.length;
                  subNoteLines.forEach((nl, idx) => {
                    warnings.push(`Line ${subLine}: [${k}.${subK}] (note ${idx + 1} of ${total}) "${nl.trim()}" could not be matched to a canonical entity schema (unstructured multi-line text).`);
                  });
                } else {
                  warnings.push(`Line ${subLine}: [${k}.${subK}] "${subK}": ${JSON.stringify(subV)} could not be matched to a canonical entity schema (unrecognized nested field).`);
                }
              }
            }
          } else if (Array.isArray(val)) {
            if (val.length === 0) {
              warnings.push(`Line ${lineNum}: Unrecognized field '${k}' (empty list) could not be matched to a canonical entity schema.`);
            } else {
              val.forEach((item, idx) => {
                warnings.push(`Line ${lineNum}: [${k}[${idx}]] ${JSON.stringify(item)} could not be matched to a canonical entity schema.`);
              });
            }
          } else {
            warnings.push(`Line ${lineNum}: Unrecognized field '${k}' with value ${JSON.stringify(val)} could not be matched to a canonical entity schema.`);
          }
        }
      }
    }

    const rawInput: Partial<AnalysisInput> = {
      metadata: {
        fileName: options.originalFileName,
        originalFileName: options.originalFileName,
        fileSize: options.fileSize,
        fileType: 'JSON',
        mimeType: options.mimeType,
        hostname: hostname !== undefined && hostname !== null ? String(hostname) : null,
        username: username !== undefined && username !== null ? String(username) : null,
        operatingSystem: operatingSystem !== undefined && operatingSystem !== null ? String(operatingSystem) : null,
        analysisTime: analysisTime ? new Date(analysisTime) : null,
      },
      risk: {
        riskScore: riskScore !== undefined ? riskScore : null,
        threatLevel: this.normalizer.normalizeThreatLevel(threatLevel),
        recommendation: recommendation !== undefined && recommendation !== null ? String(recommendation) : null,
      },
      hashes: (md5 || sha1 || sha256 || ssdeep) ? {
        md5: md5 ? String(md5) : null,
        sha1: sha1 ? String(sha1) : null,
        sha256: sha256 ? String(sha256) : null,
        ssdeep: ssdeep ? String(ssdeep) : null,
      } : null,
      fileProperties: (entropy !== undefined || digitalSignature !== undefined || isPacked !== undefined || packer || imports || suspiciousApis) ? {
        entropy: entropy !== undefined && entropy !== null ? Number(entropy) : null,
        digitalSignature: digitalSignature ? String(digitalSignature) : null,
        isPacked: typeof isPacked === 'boolean' ? isPacked : null,
        packer: packer ? String(packer) : null,
        imports: imports || null,
        suspiciousApis: suspiciousApis || null,
      } : null,
      yara: Array.isArray(yara) && yara.length > 0 ? yara : null,
      virusTotal: virusTotal || null,
      iocs: Array.isArray(iocs) && iocs.length > 0 ? iocs : null,
      mitre: Array.isArray(mitre) && mitre.length > 0 ? mitre : null,
      behavior: Array.isArray(behavior) && behavior.length > 0 ? behavior : null,
      sandbox: Array.isArray(sandbox) && sandbox.length > 0 ? sandbox : null,
      siem: Array.isArray(siem) && siem.length > 0 ? siem : null,
      incident: Array.isArray(incident) && incident.length > 0 ? incident : null,
      soar: Array.isArray(soar) && soar.length > 0 ? soar : null,
      assets: Array.isArray(assets) && assets.length > 0 ? assets : null,
      endpoints: Array.isArray(endpoints) && endpoints.length > 0 ? endpoints : null,
      vulnerabilities: Array.isArray(vulnerabilities) && vulnerabilities.length > 0 ? vulnerabilities : null,
      parsingStatus: warnings.length > 0 ? 'PARTIAL' : 'COMPLETED',
      parsingWarnings: warnings,
      unrecognizedFields: Object.keys(unrecognizedFields).length > 0 ? unrecognizedFields : null,
      provenance: {
        parser: 'JsonParser',
        sourceType: isNdjson ? 'NDJSON' : 'JSON',
        parsedAt: new Date().toISOString(),
        hasUnrecognizedFields: Object.keys(unrecognizedFields).length > 0,
        providedSections,
      },
    };

    return this.normalizer.normalize(rawInput);
  }
}
