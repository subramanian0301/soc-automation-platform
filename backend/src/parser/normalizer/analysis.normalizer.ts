import { Injectable, BadRequestException } from '@nestjs/common';
import { ThreatLevel, SoarStatus } from '@prisma/client';
import { AnalysisInput } from '../interfaces/analysis-input.interface';
import { ALIAS_MAPS, findValueByAliases } from '../alias-registry';

@Injectable()
export class AnalysisNormalizer {
  normalizeThreatLevel(value: any, riskScore?: number | null): ThreatLevel | null {
    if (value && typeof value === 'string') {
      const clean = value.trim().toUpperCase();
      if (clean === 'LOW') return ThreatLevel.LOW;
      if (clean === 'MEDIUM') return ThreatLevel.MEDIUM;
      if (clean === 'HIGH') return ThreatLevel.HIGH;
      if (clean === 'CRITICAL') return ThreatLevel.CRITICAL;
    }

    if (riskScore !== undefined && riskScore !== null) {
      if (riskScore >= 90) return ThreatLevel.CRITICAL;
      if (riskScore >= 70) return ThreatLevel.HIGH;
      if (riskScore >= 30) return ThreatLevel.MEDIUM;
      return ThreatLevel.LOW;
    }

    return null;
  }

  normalizeSoarStatus(value: any): SoarStatus | null {
    if (!value || typeof value !== 'string') return null;
    const clean = value.trim().toUpperCase();
    if (clean === 'COMPLETED') return SoarStatus.COMPLETED;
    if (clean === 'PENDING_APPROVAL') return SoarStatus.PENDING_APPROVAL;
    if (clean === 'RECOMMENDED') return SoarStatus.RECOMMENDED;
    if (clean === 'FAILED') return SoarStatus.FAILED;
    if (clean === 'PENDING') return SoarStatus.PENDING;
    if (clean === 'RUNNING') return SoarStatus.RUNNING;
    if (clean === 'SIMULATION' || clean === 'DRY_RUN') return SoarStatus.SIMULATION;
    return null;
  }

  normalizeRiskScore(value: any): number | null {
    if (value === null || value === undefined) return null;
    let num: number | null = null;
    if (typeof value === 'number' && !isNaN(value)) {
      num = value;
    } else if (typeof value === 'string') {
      const match = value.match(/(\d+)/);
      if (match) {
        num = parseInt(match[1], 10);
      }
    }

    if (num !== null && !isNaN(num)) {
      if (num < 0 || num > 100) {
        throw new BadRequestException(`Invalid risk score '${value}': risk score must be between 0 and 100.`);
      }
      return num; // Preserves exact source value without clamping or recalculation
    }

    return null;
  }

  normalizeNumber(value: any): number | null {
    if (value === null || value === undefined) return null;
    const num = Number(value);
    return isNaN(num) ? null : num;
  }

  normalizeDate(value: any): Date | null {
    if (!value) return null;
    if (value instanceof Date && !isNaN(value.getTime())) return value;
    if (typeof value === 'number') {
      const d = new Date(value > 1e11 ? value : value * 1000);
      return isNaN(d.getTime()) ? null : d;
    }
    if (typeof value === 'string') {
      const clean = value.trim();
      const d = new Date(clean);
      if (!isNaN(d.getTime())) return d;
      // Try CLF format: 11/Oct/2026:09:24:36 +0000
      const clfMatch = clean.match(/(\d{1,2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}:\d{2}:\d{2})(?:\s*([+-]\d{4}))?/);
      if (clfMatch) {
        const [, day, mon, yr, time, tz] = clfMatch;
        const parsed = new Date(`${day} ${mon} ${yr} ${time} ${tz || 'UTC'}`);
        if (!isNaN(parsed.getTime())) return parsed;
      }
    }
    return null;
  }

  normalize(raw: Partial<AnalysisInput>): AnalysisInput {
    const metadata = {
      fileName: raw.metadata?.fileName || 'uploaded_file',
      originalFileName: raw.metadata?.originalFileName || 'uploaded_file',
      fileSize: raw.metadata?.fileSize ?? 0,
      fileType: raw.metadata?.fileType ?? 'LOG',
      mimeType: raw.metadata?.mimeType || 'application/octet-stream',
      hostname: raw.metadata?.hostname ?? null,
      username: raw.metadata?.username ?? null,
      operatingSystem: raw.metadata?.operatingSystem ?? null,
      analysisTime: this.normalizeDate(raw.metadata?.analysisTime),
    };

    const normalizedScore = this.normalizeRiskScore(raw.risk?.riskScore);
    const risk = {
      riskScore: normalizedScore,
      threatLevel: this.normalizeThreatLevel(raw.risk?.threatLevel, normalizedScore),
      recommendation: raw.risk?.recommendation ?? null,
    };

    const hashes = raw.hashes
      ? {
          md5: raw.hashes.md5 ?? null,
          sha1: raw.hashes.sha1 ?? null,
          sha256: raw.hashes.sha256 ?? null,
          ssdeep: raw.hashes.ssdeep ?? null,
        }
      : null;

    let imports = raw.fileProperties?.imports;
    if (Array.isArray(imports)) {
      imports = imports.map((imp: any) => typeof imp === 'string' ? imp.replace(/^imports\s*:\s*/i, '').trim() : imp).filter((imp: any) => Boolean(imp));
    }

    const fileProperties = raw.fileProperties
      ? {
          entropy: this.normalizeNumber(raw.fileProperties.entropy),
          digitalSignature: raw.fileProperties.digitalSignature ?? null,
          isPacked: typeof raw.fileProperties.isPacked === 'boolean' ? raw.fileProperties.isPacked : null,
          packer: raw.fileProperties.packer ?? null,
          imports: imports ?? null,
          suspiciousApis: raw.fileProperties.suspiciousApis ?? null,
        }
      : null;

    const yara = (raw.yara && raw.yara.length > 0)
      ? raw.yara
          .filter(item => {
            const ruleName = findValueByAliases(item, ALIAS_MAPS.yara.ruleName) || item.ruleName || '';
            return !/^matched\s*strings?\s*:?$/i.test(ruleName.trim());
          })
          .map(item => ({
            ruleName: findValueByAliases(item, ALIAS_MAPS.yara.ruleName) || item.ruleName || 'YaraRule',
            namespace: findValueByAliases(item, ALIAS_MAPS.yara.namespace) ?? item.namespace ?? null,
            tags: findValueByAliases(item, ALIAS_MAPS.yara.tags) ?? item.tags ?? null,
            meta: findValueByAliases(item, ALIAS_MAPS.yara.meta) ?? item.meta ?? null,
            description: findValueByAliases(item, ALIAS_MAPS.yara.description) ?? item.description ?? null,
          }))
      : null;

    const virusTotal = raw.virusTotal
      ? {
          positives: findValueByAliases(raw.virusTotal, ALIAS_MAPS.virusTotal.positives) ?? raw.virusTotal.positives ?? 0,
          total: findValueByAliases(raw.virusTotal, ALIAS_MAPS.virusTotal.total) ?? raw.virusTotal.total ?? 0,
          permalink: findValueByAliases(raw.virusTotal, ALIAS_MAPS.virusTotal.permalink) ?? raw.virusTotal.permalink ?? null,
          scanDate: findValueByAliases(raw.virusTotal, ALIAS_MAPS.virusTotal.scanDate) ?? raw.virusTotal.scanDate ?? null,
          detections: findValueByAliases(raw.virusTotal, ALIAS_MAPS.virusTotal.detections) ?? raw.virusTotal.detections ?? null,
        }
      : null;

    const normalizeIocType = (rawType: string): string => {
      const upper = (rawType || '').toUpperCase().trim();
      if (upper === 'IP' || upper === 'IPV4' || upper === 'IPV6' || upper === 'IP_ADDRESS') return 'IP';
      if (upper === 'DOMAIN' || upper === 'DOMAIN_NAME' || upper === 'HOSTNAME' || upper === 'FQDN') return 'DOMAIN';
      if (upper === 'URL' || upper === 'URI' || upper === 'LINK') return 'URL';
      if (upper === 'EMAIL' || upper === 'EMAIL_ADDRESS' || upper === 'MAIL') return 'EMAIL';
      if (upper === 'HASH' || upper === 'MD5' || upper === 'SHA1' || upper === 'SHA256' || upper === 'SSDEEP') return 'HASH';
      return upper || 'INDICATOR';
    };

    const iocMap = new Map<string, any>();
    if (raw.iocs && raw.iocs.length > 0) {
      for (const item of raw.iocs) {
        const rawType = findValueByAliases(item, ALIAS_MAPS.iocs.type) || item.type || 'INDICATOR';
        const rawVal = findValueByAliases(item, ALIAS_MAPS.iocs.value) || item.value || '';
        const value = typeof rawVal === 'string' ? rawVal.trim() : String(rawVal).trim();
        if (!value) continue;

        const type = normalizeIocType(rawType);
        const dedupKey = `${type}:${value.toLowerCase()}`;
        const category = findValueByAliases(item, ALIAS_MAPS.iocs.category) ?? item.category ?? null;
        const confidence = this.normalizeNumber(findValueByAliases(item, ALIAS_MAPS.iocs.confidence) ?? item.confidence);
        const description = findValueByAliases(item, ALIAS_MAPS.iocs.description) ?? item.description ?? null;

        if (!iocMap.has(dedupKey)) {
          iocMap.set(dedupKey, {
            type,
            value,
            category,
            confidence,
            description,
          });
        } else {
          const existing = iocMap.get(dedupKey)!;
          if (!existing.category && category) existing.category = category;
          if (!existing.description && description) existing.description = description;
          if (confidence !== null && (existing.confidence === null || confidence > existing.confidence)) {
            existing.confidence = confidence;
          }
        }
      }
    }
    const iocs = iocMap.size > 0 ? Array.from(iocMap.values()) : null;

    const mitre = (raw.mitre && raw.mitre.length > 0)
      ? raw.mitre.map(item => {
          const techniqueId = findValueByAliases(item, ALIAS_MAPS.mitre.techniqueId) || item.techniqueId || '';
          return {
            tactic: findValueByAliases(item, ALIAS_MAPS.mitre.tactic) || item.tactic || 'Execution',
            techniqueId,
            name: findValueByAliases(item, ALIAS_MAPS.mitre.name) || item.name || techniqueId,
            description: findValueByAliases(item, ALIAS_MAPS.mitre.description) ?? item.description ?? null,
          };
        }).filter(item => item.techniqueId)
      : null;

    const isNegativeBehavior = (str: any): boolean => {
      if (str === null || str === undefined) return true;
      if (typeof str === 'boolean') return !str;
      const clean = String(str).trim().toLowerCase();
      if (!clean) return true;
      if (/^(none|no|false|0|nil|n\/a|na|not detected|none detected|clean|null|-|undefined)$/i.test(clean)) return true;
      if (/.*(detected|found|observed|modified|created|present|activity|persistence|dropped\s*files?)\s*[:=-]?\s*(none|no|false|0|nil|n\/a|na|null)$/i.test(clean)) return true;
      if (/^(created\s*process|registry\s*modified|persistence|dropped\s*files?)\s*[:=-]?\s*(none|no|false|0|nil|n\/a|na|null)$/i.test(clean)) return true;
      if (/^no\s+(malicious|suspicious|persistence|files?|processes?|registry|activity|behavior)/i.test(clean)) return true;
      if (/\b(not detected|none detected|no threats? detected|no suspicious activity|no persistence)\b/i.test(clean)) return true;
      return false;
    };

    const behaviorList = (raw.behavior && raw.behavior.length > 0)
      ? raw.behavior
          .filter(item => {
            if (!item || typeof item !== 'object') return false;
            const target = findValueByAliases(item, ALIAS_MAPS.behavior.target) ?? item.target;
            const action = findValueByAliases(item, ALIAS_MAPS.behavior.action) ?? item.action;
            if (isNegativeBehavior(target) && isNegativeBehavior(action)) return false;
            if (isNegativeBehavior(target)) return false;
            return true;
          })
          .map(item => {
            const rawType = findValueByAliases(item, ALIAS_MAPS.behavior.eventType) || item.eventType || item.type || 'BEHAVIOR';
            const rawAction = findValueByAliases(item, ALIAS_MAPS.behavior.action) || item.action || 'OBSERVED';
            const rawTarget = findValueByAliases(item, ALIAS_MAPS.behavior.target) || item.target || '';
            const rawDetails = findValueByAliases(item, ALIAS_MAPS.behavior.details) ?? item.details ?? null;
            const rawTime = findValueByAliases(item, ALIAS_MAPS.behavior.timestamp) ?? item.timestamp;

            const cleanDetails = (rawDetails !== null && rawDetails !== undefined && String(rawDetails).trim() !== '' && !isNegativeBehavior(rawDetails))
              ? String(rawDetails).trim()
              : null;

            return {
              eventType: String(rawType).toUpperCase(),
              action: String(rawAction).toUpperCase(),
              target: String(rawTarget).trim(),
              details: cleanDetails,
              timestamp: this.normalizeDate(rawTime),
            };
          })
          .filter(item => item.target && !isNegativeBehavior(item.target))
      : null;
    const behavior = behaviorList && behaviorList.length > 0 ? behaviorList : null;

    const sandbox = (raw.sandbox && raw.sandbox.length > 0)
      ? raw.sandbox.map(item => {
          const rawName = findValueByAliases(item, ALIAS_MAPS.sandbox.sandboxName) || item.sandboxName || item.sandbox_name || item.environment || item.env || item.run_id || 'Sandbox';
          const rawVerdict = findValueByAliases(item, ALIAS_MAPS.sandbox.verdict) || item.verdict || 'SUSPICIOUS';
          const rawScore = findValueByAliases(item, ALIAS_MAPS.sandbox.score) ?? item.score;
          const rawDetails = findValueByAliases(item, ALIAS_MAPS.sandbox.details) ?? item.details ?? (
            item.signatures || item.duration_seconds
              ? { signatures: item.signatures, duration_seconds: item.duration_seconds, run_id: item.run_id, environment: item.environment }
              : null
          );

          return {
            sandboxName: String(rawName).trim(),
            verdict: String(rawVerdict).trim().toUpperCase(),
            score: this.normalizeNumber(rawScore),
            details: rawDetails ?? null,
          };
        })
      : null;

    const normalizeSiemSeverity = (val: any): string | null => {
      if (val === null || val === undefined) return null;
      if (typeof val === 'number') {
        if (val === 1) return 'CRITICAL';
        if (val === 2) return 'HIGH';
        if (val === 3) return 'MEDIUM';
        if (val === 4) return 'LOW';
        if (val === 5) return 'INFO';
      }
      const clean = String(val).trim().toUpperCase();
      if (['CRITICAL', 'CRIT', 'FATAL', 'EMERG', 'EMERGENCY', 'ALERT', 'SEV1', '1'].includes(clean)) return 'CRITICAL';
      if (['HIGH', 'ERR', 'ERROR', 'SEV2', '2'].includes(clean)) return 'HIGH';
      if (['MEDIUM', 'WARN', 'WARNING', 'MED', 'SEV3', '3'].includes(clean)) return 'MEDIUM';
      if (['LOW', 'NOTICE', 'VERBOSE', 'SEV4', '4'].includes(clean)) return 'LOW';
      if (['INFO', 'INFORMATIONAL', 'DEBUG', 'TRACE', 'SEV5', '5'].includes(clean)) return 'INFO';
      return clean;
    };

    const siemMap = new Map<string, any>();
    if (raw.siem && raw.siem.length > 0) {
      for (const item of raw.siem) {
        const rawEvent = (typeof item === 'string' ? item : (findValueByAliases(item, ALIAS_MAPS.siem.rawEvent) || item.rawEvent || JSON.stringify(item))).trim();
        let timestamp = this.normalizeDate(findValueByAliases(item, ALIAS_MAPS.siem.timestamp) ?? item.timestamp);
        let eventId = findValueByAliases(item, ALIAS_MAPS.siem.eventId) ?? item.eventId ?? null;
        let sourceIp = findValueByAliases(item, ALIAS_MAPS.siem.sourceIp) ?? item.sourceIp ?? null;
        let destIp = findValueByAliases(item, ALIAS_MAPS.siem.destIp) ?? item.destIp ?? null;
        let sourcePort = this.normalizeNumber(findValueByAliases(item, ALIAS_MAPS.siem.sourcePort) ?? item.sourcePort);
        let destPort = this.normalizeNumber(findValueByAliases(item, ALIAS_MAPS.siem.destPort) ?? item.destPort);
        let protocol = findValueByAliases(item, ALIAS_MAPS.siem.protocol) ?? item.protocol ?? null;
        let action = findValueByAliases(item, ALIAS_MAPS.siem.action) ?? item.action ?? null;
        let rawSeverity = findValueByAliases(item, ALIAS_MAPS.siem.severity) ?? item.severity;
        let severity = normalizeSiemSeverity(rawSeverity);

        if (typeof item === 'string' || (!sourceIp && !destIp && !action)) {
          if (!sourceIp) {
            const sMatch = rawEvent.match(/\b(?:SRC|src|source_ip|client_ip|from)[=:\s]+([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b/i);
            if (sMatch) sourceIp = sMatch[1];
          }
          if (!destIp) {
            const dMatch = rawEvent.match(/\b(?:DST|dst|dest_ip|to)[=:\s]+([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b/i);
            if (dMatch) destIp = dMatch[1];
          }
          if (!protocol) {
            const pMatch = rawEvent.match(/\b(?:PROTO|proto)[=:\s]+([A-Za-z0-9]+)\b/i) || rawEvent.match(/\b(TCP|UDP|ICMP)\b/i);
            if (pMatch) protocol = pMatch[1].toUpperCase();
          }
          if (!action) {
            if (/failed\s+password|authentication\s+failed|logon\s+failed|failed\s+to\s+log\s*on|denied|audit\s+failure/i.test(rawEvent)) action = 'AUTH_FAILED';
            else if (/accepted|successful|success|successfully\s+logged\s*on|audit\s+success/i.test(rawEvent)) action = 'AUTH_SUCCESS';
            else if (/\b(BLOCKED|BLOCK)\b/i.test(rawEvent)) action = 'BLOCKED';
            else if (/\b(ALLOWED|ALLOW)\b/i.test(rawEvent)) action = 'ALLOWED';
            else if (/\b(DROPPED|DROP)\b/i.test(rawEvent)) action = 'DROPPED';
          }
          if (!severity) {
            if (/crit|fatal|emerg|alert/i.test(rawEvent)) severity = 'CRITICAL';
            else if (/err|error|high|failed|denied/i.test(rawEvent)) severity = 'HIGH';
            else if (/warn|warning|medium|blocked|dropped/i.test(rawEvent)) severity = 'MEDIUM';
            else if (/notice|low/i.test(rawEvent)) severity = 'LOW';
            else severity = 'INFO';
          }
        }

        if (!timestamp) timestamp = new Date();

        // Deduplication key: prefer eventId if present, else normalized timestamp + rawEvent
        const dedupKey = eventId
          ? `id:${eventId}:${rawEvent.trim()}`
          : `ts:${timestamp.toISOString()}:${rawEvent.trim()}`;


        if (!siemMap.has(dedupKey)) {
          siemMap.set(dedupKey, {
            eventId,
            sourceIp,
            destIp,
            sourcePort,
            destPort,
            protocol,
            action,
            severity,
            rawEvent,
            timestamp,
          });
        } else {
          // Merge non-null fields into existing entry
          const existing = siemMap.get(dedupKey)!;
          if (!existing.sourceIp && sourceIp) existing.sourceIp = sourceIp;
          if (!existing.destIp && destIp) existing.destIp = destIp;
          if (existing.sourcePort === null && sourcePort !== null) existing.sourcePort = sourcePort;
          if (existing.destPort === null && destPort !== null) existing.destPort = destPort;
          if (!existing.protocol && protocol) existing.protocol = protocol;
          if (!existing.action && action) existing.action = action;
          if (!existing.severity && severity) existing.severity = severity;
        }
      }
    }
    const siem = siemMap.size > 0 ? Array.from(siemMap.values()) : null;

    const incident = (raw.incident && raw.incident.length > 0)
      ? raw.incident.map(item => ({
          title: findValueByAliases(item, ALIAS_MAPS.incidents.title) || item.title || 'Security Incident',
          severity: this.normalizeThreatLevel(findValueByAliases(item, ALIAS_MAPS.incidents.severity) ?? item.severity),
          status: findValueByAliases(item, ALIAS_MAPS.incidents.status) || item.status || 'OPEN',
          reason: findValueByAliases(item, ALIAS_MAPS.incidents.reason) || item.reason || 'Source explicit incident record',
          assignedTo: findValueByAliases(item, ALIAS_MAPS.incidents.assignedTo) ?? item.assignedTo ?? null,
        }))
      : null;

    const soar = (raw.soar && raw.soar.length > 0)
      ? raw.soar
          .map(item => {
            const rawStatus = findValueByAliases(item, ALIAS_MAPS.soar.status) ?? item.status;
            const normalizedStatus = this.normalizeSoarStatus(rawStatus) || SoarStatus.RECOMMENDED;
            return {
              actionName: findValueByAliases(item, ALIAS_MAPS.soar.actionName) || item.actionName || 'Playbook Action',
              description: findValueByAliases(item, ALIAS_MAPS.soar.description) ?? item.description ?? null,
              actionType: findValueByAliases(item, ALIAS_MAPS.soar.actionType) ?? item.actionType ?? null,
              target: findValueByAliases(item, ALIAS_MAPS.soar.target) ?? item.target ?? null,
              status: normalizedStatus,
              triggeredBy: findValueByAliases(item, ALIAS_MAPS.soar.triggeredBy) ?? item.triggeredBy ?? 'Source',
              source: findValueByAliases(item, ALIAS_MAPS.soar.source) ?? item.source ?? 'Source',
              result: findValueByAliases(item, ALIAS_MAPS.soar.result) ?? item.result ?? null,
              executionLog: findValueByAliases(item, ALIAS_MAPS.soar.executionLog) ?? item.executionLog ?? null,
              executedAt: this.normalizeDate(findValueByAliases(item, ALIAS_MAPS.soar.executedAt) ?? item.executedAt),
              completedAt: this.normalizeDate(findValueByAliases(item, ALIAS_MAPS.soar.completedAt) ?? item.completedAt),
            };
          })
          .filter(Boolean) as any
      : null;

    const assets = (raw.assets && raw.assets.length > 0)
      ? raw.assets.map(item => ({
          assetName: findValueByAliases(item, ALIAS_MAPS.assets.assetName) || item.assetName || item.hostname || item.ipAddress || 'Asset',
          hostname: findValueByAliases(item, ALIAS_MAPS.assets.hostname) ?? item.hostname ?? null,
          ipAddress: findValueByAliases(item, ALIAS_MAPS.assets.ipAddress) ?? item.ipAddress ?? null,
          macAddress: findValueByAliases(item, ALIAS_MAPS.assets.macAddress) ?? item.macAddress ?? null,
          assetType: findValueByAliases(item, ALIAS_MAPS.assets.assetType) ?? item.assetType ?? null,
          criticality: findValueByAliases(item, ALIAS_MAPS.assets.criticality) ?? item.criticality ?? null,
          operatingSystem: findValueByAliases(item, ALIAS_MAPS.assets.operatingSystem) ?? item.operatingSystem ?? null,
          owner: findValueByAliases(item, ALIAS_MAPS.assets.owner) ?? item.owner ?? item.user ?? null,
          status: findValueByAliases(item, ALIAS_MAPS.assets.status) ?? item.status ?? null,
          source: findValueByAliases(item, ALIAS_MAPS.assets.source) ?? item.source ?? 'Source file',
          description: findValueByAliases(item, ALIAS_MAPS.assets.description) ?? item.description ?? null,
          evidence: findValueByAliases(item, ALIAS_MAPS.assets.evidence) ?? item.evidence ?? null,
        }))
      : null;

    const endpoints = (raw.endpoints && raw.endpoints.length > 0)
      ? raw.endpoints.map(item => ({
          hostname: findValueByAliases(item, ALIAS_MAPS.endpoints.hostname) || item.hostname || item.ipAddress || 'Endpoint',
          ipAddress: findValueByAliases(item, ALIAS_MAPS.endpoints.ipAddress) ?? item.ipAddress ?? null,
          osVersion: findValueByAliases(item, ALIAS_MAPS.endpoints.osVersion) ?? item.osVersion ?? item.operatingSystem ?? null,
          operatingSystem: findValueByAliases(item, ALIAS_MAPS.endpoints.operatingSystem) ?? item.operatingSystem ?? item.osVersion ?? null,
          user: findValueByAliases(item, ALIAS_MAPS.endpoints.user) ?? item.user ?? null,
          agentStatus: findValueByAliases(item, ALIAS_MAPS.endpoints.agentStatus) ?? item.agentStatus ?? item.status ?? null,
          status: findValueByAliases(item, ALIAS_MAPS.endpoints.status) ?? item.status ?? item.agentStatus ?? null,
          endpointType: findValueByAliases(item, ALIAS_MAPS.endpoints.endpointType) ?? item.endpointType ?? null,
          source: findValueByAliases(item, ALIAS_MAPS.endpoints.source) ?? item.source ?? 'Source file',
          evidence: findValueByAliases(item, ALIAS_MAPS.endpoints.evidence) ?? item.evidence ?? null,
          lastSeen: this.normalizeDate(findValueByAliases(item, ALIAS_MAPS.endpoints.lastSeen) ?? item.lastSeen),
        }))
      : null;

    const vulnerabilities = (raw.vulnerabilities && raw.vulnerabilities.length > 0)
      ? raw.vulnerabilities.map(item => {
          const cveId = findValueByAliases(item, ALIAS_MAPS.vulnerabilities.cveId) || item.cveId || 'CVE-UNKNOWN';
          return {
            cveId,
            title: findValueByAliases(item, ALIAS_MAPS.vulnerabilities.title) || item.title || item.name || cveId,
            cvssScore: this.normalizeNumber(findValueByAliases(item, ALIAS_MAPS.vulnerabilities.cvssScore) ?? item.cvssScore),
            severity: this.normalizeThreatLevel(findValueByAliases(item, ALIAS_MAPS.vulnerabilities.severity) ?? item.severity),
            description: findValueByAliases(item, ALIAS_MAPS.vulnerabilities.description) ?? item.description ?? null,
            affectedAsset: findValueByAliases(item, ALIAS_MAPS.vulnerabilities.affectedAsset) ?? item.affectedAsset ?? null,
            packageName: findValueByAliases(item, ALIAS_MAPS.vulnerabilities.packageName) ?? item.packageName ?? null,
            installedVersion: findValueByAliases(item, ALIAS_MAPS.vulnerabilities.installedVersion) ?? item.installedVersion ?? null,
            fixedVersion: findValueByAliases(item, ALIAS_MAPS.vulnerabilities.fixedVersion) ?? item.fixedVersion ?? null,
            status: findValueByAliases(item, ALIAS_MAPS.vulnerabilities.status) ?? item.status ?? null,
            remediation: findValueByAliases(item, ALIAS_MAPS.vulnerabilities.remediation) ?? item.remediation ?? null,
            source: item.source ?? 'Source file',
            evidence: item.evidence ?? null,
          };
        })
      : null;

    return {
      metadata,
      risk,
      hashes,
      fileProperties,
      yara,
      virusTotal,
      iocs,
      mitre,
      behavior,
      sandbox,
      siem,
      incident,
      soar: (soar && soar.length > 0) ? soar : null,
      assets,
      endpoints,
      vulnerabilities,
      parsingStatus: raw.parsingStatus || (raw.parsingWarnings && raw.parsingWarnings.length > 0 ? 'PARTIAL' : 'COMPLETED'),
      parsingWarnings: raw.parsingWarnings || [],
      unrecognizedFields: raw.unrecognizedFields || null,
      provenance: {
        ...(raw.provenance || {
          sourceFields: Object.keys(raw).filter(k => !['parsingStatus', 'parsingWarnings', 'unrecognizedFields', 'provenance'].includes(k)),
          extractedAt: new Date().toISOString(),
        }),
        providedSections: raw.provenance?.providedSections || (
          [
            yara ? 'yara' : null,
            virusTotal ? 'virusTotal' : null,
            iocs ? 'iocs' : null,
            mitre ? 'mitre' : null,
            behavior ? 'behavior' : null,
            sandbox ? 'sandbox' : null,
            siem ? 'siem' : null,
            incident ? 'incident' : null,
            soar ? 'soar' : null,
            assets ? 'assets' : null,
            endpoints ? 'endpoints' : null,
            vulnerabilities ? 'vulnerabilities' : null,
          ].filter(Boolean) as string[]
        ),
      },
    };
  }
}
