import { Injectable } from '@nestjs/common';
import { IFileParser, FileParserOptions } from '../interfaces/parser.interface';
import {
  AnalysisInput,
  AnalysisInputHashes,
  AnalysisInputYara,
  AnalysisInputVirusTotal,
  AnalysisInputIoc,
  AnalysisInputMitre,
  AnalysisInputBehavior,
  AnalysisInputSiem,
  AnalysisInputIncident,
  AnalysisInputSoar,
  AnalysisInputAsset,
  AnalysisInputEndpoint,
  AnalysisInputVulnerability,
  AnalysisInputSandbox,
} from '../interfaces/analysis-input.interface';
import { AnalysisNormalizer } from '../normalizer/analysis.normalizer';
import { ALIAS_MAPS, SECTION_ALIASES, normalizeKey, findValueByAliases } from '../alias-registry';
import { IocExtractor } from '../extractors/ioc.extractor';

@Injectable()
export class TextLogParser implements IFileParser {
  constructor(private readonly normalizer: AnalysisNormalizer) {}

  canParse(extension: string, mimeType: string): boolean {
    const ext = extension.toLowerCase();
    return ext === '.log' || ext === '.txt' || mimeType.includes('text') || mimeType.includes('log') || true;
  }

  private parseSyslogDate(monthStr: string, dayStr: string, timeStr: string, defaultYear = 2026): Date {
    const monthMap: Record<string, number> = {
      jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5,
      jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11,
    };
    const m = monthMap[monthStr.toLowerCase()];
    if (m !== undefined) {
      const day = parseInt(dayStr, 10);
      const [hh, mm, ss] = timeStr.split(':').map(n => parseInt(n, 10));
      const d = new Date(Date.UTC(defaultYear, m, day, hh || 0, mm || 0, ss || 0));
      if (!isNaN(d.getTime())) return d;
    }
    return new Date();
  }

  private parseClfDate(clfDateStr: string): Date | null {
    const match = clfDateStr.match(/(\d{1,2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?/);
    if (match) {
      const [, day, mon, yr, hr, min, sec, tz] = match;
      const d = new Date(`${day} ${mon} ${yr} ${hr}:${min}:${sec} ${tz || '+0000'}`);
      if (!isNaN(d.getTime())) return d;
    }
    return null;
  }

  public extractAnyTimestamp(text: string, defaultYear = 2026): Date | null {
    if (!text) return null;

    // 1. Syslog RFC 3164: Oct 11 09:14:02 or [Oct 11 09:14:02]
    const syslogMatch = text.match(/\b([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\b/);
    if (syslogMatch) {
      const monthMap: Record<string, number> = {
        jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5,
        jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11,
      };
      const m = monthMap[syslogMatch[1].toLowerCase()];
      if (m !== undefined) {
        const day = parseInt(syslogMatch[2], 10);
        const [hh, mm, ss] = syslogMatch[3].split(':').map(n => parseInt(n, 10));
        const d = new Date(Date.UTC(defaultYear, m, day, hh || 0, mm || 0, ss || 0));
        if (!isNaN(d.getTime())) return d;
      }
    }

    // 2. ISO 8601 / Dash date: 2026-10-11T09:14:02 or 2026-10-11 09:14:02
    const isoMatch = text.match(/\b(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b/);
    if (isoMatch) {
      const d = new Date(isoMatch[1]);
      if (!isNaN(d.getTime())) return d;
    }

    // 3. Slashes date: 2026/10/11 09:14:02 or 2026/10/11:09:14:02
    const slashIsoMatch = text.match(/\b(\d{4})\/(\d{2})\/(\d{2})[T\s:](\d{2}):(\d{2}):(\d{2})\b/);
    if (slashIsoMatch) {
      const [, y, m, d, hh, mm, ss] = slashIsoMatch;
      const date = new Date(Date.UTC(parseInt(y, 10), parseInt(m, 10) - 1, parseInt(d, 10), parseInt(hh, 10), parseInt(mm, 10), parseInt(ss, 10)));
      if (!isNaN(date.getTime())) return date;
    }

    // 4. Common Log Format: [11/Oct/2026:09:24:36 +0000] or 11/Oct/2026:09:24:36
    const clfMatch = text.match(/\[?(\d{1,2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2}(?:\s*[+-]\d{4})?)\]?/);
    if (clfMatch) {
      const d = this.parseClfDate(clfMatch[1]);
      if (d) return d;
    }

    // 5. Apache Error bracket date: [Sun Oct 11 09:14:02.123456 2026]
    const apacheMatch = text.match(/\[(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(\d{4})\]/i);
    if (apacheMatch) {
      const [, mon, day, time, yr] = apacheMatch;
      const d = new Date(`${day} ${mon} ${yr} ${time.split('.')[0]} UTC`);
      if (!isNaN(d.getTime())) return d;
    }

    // 6. Snort / Suricata: 10/11/2026-09:14:02.123456
    const snortMatch = text.match(/\b(\d{1,2})\/(\d{1,2})\/(\d{4})-(\d{2}:\d{2}:\d{2})\b/);
    if (snortMatch) {
      const [, m, day, yr, time] = snortMatch;
      const d = new Date(`${yr}-${m.padStart(2, '0')}-${day.padStart(2, '0')}T${time}Z`);
      if (!isNaN(d.getTime())) return d;
    }

    // 7. US/Euro date: 11/10/2026 09:14:02 or 10/11/2026 09:14:02 or 11-10-2026 09:14:02
    const usEuroMatch = text.match(/\b(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{4})[\sT](\d{2}:\d{2}:\d{2})\b/);
    if (usEuroMatch) {
      const [, part1, part2, yr, time] = usEuroMatch;
      const p1 = parseInt(part1, 10);
      const p2 = parseInt(part2, 10);
      const m = p1 > 12 ? p2 : p1;
      const day = p1 > 12 ? p1 : p2;
      const d = new Date(`${yr}-${String(m).padStart(2, '0')}-${String(day).padStart(2, '0')}T${time}Z`);
      if (!isNaN(d.getTime())) return d;
    }

    // 8. Unix audit epoch: audit(1791710344.000:811) or time=1791710344 or rt=1791710344
    const epochMatch = text.match(/\b(?:audit\(|time=|timestamp=|rt=|devtime=)(\d{10})(?:\.\d+)?/i);
    if (epochMatch) {
      const sec = parseInt(epochMatch[1], 10);
      const d = new Date(sec * 1000);
      if (!isNaN(d.getTime())) return d;
    }

    return null;
  }

  public extractSeverity(explicitSeverity: string | null, line: string): string {
    if (explicitSeverity) {
      const clean = explicitSeverity.trim().toUpperCase();
      if (['CRITICAL', 'CRIT', 'FATAL', 'EMERG', 'EMERGENCY', 'ALERT', 'SEV1', '1'].includes(clean)) return 'CRITICAL';
      if (['ERROR', 'ERR', 'HIGH', 'SEV2', '2'].includes(clean)) return 'HIGH';
      if (['WARN', 'WARNING', 'MEDIUM', 'MED', 'SEV3', '3'].includes(clean)) return 'MEDIUM';
      if (['NOTICE', 'LOW', 'SEV4', '4'].includes(clean)) return 'LOW';
      if (['INFO', 'INFORMATIONAL', 'DEBUG', 'TRACE', 'VERBOSE', '5'].includes(clean)) return 'INFO';
    }

    const upper = line.toUpperCase();
    if (/\b(?:CRITICAL|CRIT|FATAL|EMERG|EMERGENCY|ALERT|SEV1)\b/.test(upper)) return 'CRITICAL';
    if (/\b(?:ERROR|ERR|HIGH|SEV2)\b/.test(upper)) return 'HIGH';
    if (/\b(?:WARN|WARNING|MEDIUM|MED|SEV3)\b/.test(upper)) return 'MEDIUM';
    if (/\b(?:NOTICE|LOW|SEV4)\b/.test(upper)) return 'LOW';
    if (/\b(?:INFO|INFORMATIONAL|DEBUG|TRACE)\b/.test(upper)) return 'INFO';

    // Heuristics based on security keywords
    if (/failed\s+password|authorization\s+denied|authentication\s+failed|logon\s+failed|login\s+failed|failed\s+to\s+log\s*on|\b4625\b|audit\s+failure|access\s+denied|brute\s*force|trojan|meterpreter|reverse\s+https/i.test(line)) return 'HIGH';
    if (/blocked|dropped|rejected|deny|denied|invalid\s+user|access\s+forbidden|scan\s+potential/i.test(line)) return 'MEDIUM';
    if (/accepted\s+publickey|session\s+opened|session\s+closed|success|successful\s+logon/i.test(line)) return 'INFO';

    // HTTP status codes in line
    if (/\s5\d{2}\s/.test(line)) return 'HIGH';
    if (/\s(401|403)\s/.test(line)) return 'HIGH';
    if (/\s(400|404|429)\s/.test(line)) return 'MEDIUM';
    if (/\s2\d{2}\s/.test(line)) return 'INFO';

    return 'INFO';
  }

  public parseSiemLogLine(line: string, defaultYear = 2026): AnalysisInputSiem | null {
    if (!line || line.trim().length === 0) return null;
    const cleanLine = line.trim();

    // 0. Embedded JSON check
    if (cleanLine.startsWith('{') && cleanLine.endsWith('}')) {
      try {
        const item = JSON.parse(cleanLine);
        if (typeof item === 'object' && item !== null) {
          const rawEvent = findValueByAliases(item, ALIAS_MAPS.siem.rawEvent) ||
            item.rawEvent || item.message || item.msg || item.log || cleanLine;
          const tsVal = findValueByAliases(item, ALIAS_MAPS.siem.timestamp) || item.timestamp || item.time || item.date;
          const timestamp = this.normalizer.normalizeDate(tsVal) || this.extractAnyTimestamp(cleanLine, defaultYear) || new Date();
          const eventId = findValueByAliases(item, ALIAS_MAPS.siem.eventId) || item.eventId || item.id || item.event_id || null;
          const sourceIp = findValueByAliases(item, ALIAS_MAPS.siem.sourceIp) || item.sourceIp || item.src_ip || item.src || null;
          const destIp = findValueByAliases(item, ALIAS_MAPS.siem.destIp) || item.destIp || item.dst_ip || item.dst || null;
          const sPortVal = findValueByAliases(item, ALIAS_MAPS.siem.sourcePort) || item.sourcePort || item.sport || item.src_port;
          const dPortVal = findValueByAliases(item, ALIAS_MAPS.siem.destPort) || item.destPort || item.dport || item.dst_port;
          const protocol = findValueByAliases(item, ALIAS_MAPS.siem.protocol) || item.protocol || item.proto || null;
          const action = findValueByAliases(item, ALIAS_MAPS.siem.action) || item.action || item.status || null;
          const rawSev = findValueByAliases(item, ALIAS_MAPS.siem.severity) || item.severity || item.level || null;

          return {
            eventId: eventId ? String(eventId) : null,
            sourceIp: sourceIp ? String(sourceIp) : null,
            destIp: destIp ? String(destIp) : null,
            sourcePort: sPortVal ? parseInt(String(sPortVal), 10) : null,
            destPort: dPortVal ? parseInt(String(dPortVal), 10) : null,
            protocol: protocol ? String(protocol).toUpperCase() : null,
            action: action ? String(action).toUpperCase() : null,
            severity: this.extractSeverity(rawSev, cleanLine),
            rawEvent: typeof rawEvent === 'string' ? rawEvent : JSON.stringify(rawEvent),
            timestamp,
          };
        }
      } catch {
        // Not JSON, continue with line-based parsing
      }
    }

    // 0b. CEF line
    if (/^CEF:\d+/i.test(cleanLine)) {
      const parts = cleanLine.split('|');
      if (parts.length >= 7) {
        const eventId = parts[4] || null;
        const name = parts[5] || null;
        const cefSevNum = parseInt(parts[6], 10);
        let severity = 'MEDIUM';
        if (!isNaN(cefSevNum)) {
          if (cefSevNum >= 9) severity = 'CRITICAL';
          else if (cefSevNum >= 7) severity = 'HIGH';
          else if (cefSevNum >= 4) severity = 'MEDIUM';
          else if (cefSevNum >= 1) severity = 'LOW';
          else severity = 'INFO';
        }
        const ext = parts.slice(7).join('|');
        const sIp = ext.match(/\b(?:src|source|suser|client_ip)=([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b/i)?.[1] || null;
        const dIp = ext.match(/\b(?:dst|destination|server_ip)=([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b/i)?.[1] || null;
        const sPort = ext.match(/\bspt=([0-9]{1,5})\b/i)?.[1];
        const dPort = ext.match(/\bdpt=([0-9]{1,5})\b/i)?.[1];
        const proto = ext.match(/\bproto=([A-Za-z0-9]+)\b/i)?.[1];
        const act = ext.match(/\bact(?:ion)?=([^\s]+)/i)?.[1] || name || null;
        const rtMatch = ext.match(/\b(?:rt|start|end)=([^\s]+)/i);
        let ts = new Date();
        if (rtMatch) {
          const parsed = this.extractAnyTimestamp(rtMatch[1], defaultYear);
          if (parsed) ts = parsed;
        } else {
          const anyTs = this.extractAnyTimestamp(cleanLine, defaultYear);
          if (anyTs) ts = anyTs;
        }
        return {
          eventId,
          sourceIp: sIp,
          destIp: dIp,
          sourcePort: sPort ? parseInt(sPort, 10) : null,
          destPort: dPort ? parseInt(dPort, 10) : null,
          protocol: proto ? proto.toUpperCase() : null,
          action: act ? act.toUpperCase() : null,
          severity,
          rawEvent: cleanLine,
          timestamp: ts,
        };
      }
    }

    // 1. Syslog PRI header check: <134> or <34>1 ...
    let strippedLine = cleanLine;
    let priSeverity: string | null = null;
    const priMatch = cleanLine.match(/^<(\d{1,3})>(?:1\s+)?(.*)$/);
    if (priMatch) {
      const pri = parseInt(priMatch[1], 10);
      const priLevel = pri & 7;
      if (priLevel <= 2) priSeverity = 'CRITICAL';
      else if (priLevel === 3) priSeverity = 'HIGH';
      else if (priLevel === 4) priSeverity = 'MEDIUM';
      else if (priLevel <= 6) priSeverity = 'INFO';
      else priSeverity = 'INFO';
      strippedLine = priMatch[2];
    }

    // 2. Timestamp extraction
    const timestamp = this.extractAnyTimestamp(strippedLine, defaultYear) || new Date();

    // 3. Severity extraction
    const severity = this.extractSeverity(priSeverity, strippedLine);

    // 4. IP, Port, and Protocol extraction
    let sourceIp: string | null = null;
    let destIp: string | null = null;
    let sourcePort: number | null = null;
    let destPort: number | null = null;
    let protocol: string | null = null;

    // Arrow notation check: IP:Port -> IP:Port or IP -> IP
    const arrowMatch = strippedLine.match(/([0-9]{1,3}(?:\.[0-9]{1,3}){3})(?::(\d+))?\s*(?:->|=>)\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})(?::(\d+))?/);
    if (arrowMatch) {
      sourceIp = arrowMatch[1];
      if (arrowMatch[2]) sourcePort = parseInt(arrowMatch[2], 10);
      destIp = arrowMatch[3];
      if (arrowMatch[4]) destPort = parseInt(arrowMatch[4], 10);
    }

    // Source IP
    if (!sourceIp) {
      const srcKv = strippedLine.match(/\b(?:SRC|src|source_ip|sourceIp|client_ip|clientip|client|source|remote_ip|c_ip|c-ip|addr|ip)[=:\s]+([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b/i);
      const srcWord = strippedLine.match(/\b(?:from|client)\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b/i);
      const srcNetAddr = strippedLine.match(/Source\s+Network\s+Address:\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})/i);
      const apacheClient = strippedLine.match(/\[client\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})/i);
      const ciscoSrc = strippedLine.match(/src\s+[A-Za-z0-9_-]+:([0-9]{1,3}(?:\.[0-9]{1,3}){3})/i);
      const leadingIp = strippedLine.match(/^([0-9]{1,3}(?:\.[0-9]{1,3}){3})\s+/);
      const embeddedClfIp = strippedLine.match(/(?:\[\d+\]|:\s*)\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})\s+-/);

      if (srcKv) sourceIp = srcKv[1];
      else if (srcWord) sourceIp = srcWord[1];
      else if (srcNetAddr) sourceIp = srcNetAddr[1];
      else if (apacheClient) sourceIp = apacheClient[1];
      else if (ciscoSrc) sourceIp = ciscoSrc[1];
      else if (embeddedClfIp) sourceIp = embeddedClfIp[1];
      else if (leadingIp) sourceIp = leadingIp[1];
    }

    // Destination IP
    if (!destIp) {
      const dstKv = strippedLine.match(/\b(?:DST|dst|destination_ip|destIp|dest|destination|server_ip|serverip|server|target_ip|targetip|target|s_ip|s-ip)[=:\s]+([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b/i);
      const dstWord = strippedLine.match(/\b(?:to|destination)\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b/i);
      const dstNetAddr = strippedLine.match(/Destination\s+Network\s+Address:\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})/i);
      const ciscoDst = strippedLine.match(/dst\s+[A-Za-z0-9_-]+:([0-9]{1,3}(?:\.[0-9]{1,3}){3})/i);

      if (dstKv) destIp = dstKv[1];
      else if (dstWord) destIp = dstWord[1];
      else if (dstNetAddr) destIp = dstNetAddr[1];
      else if (ciscoDst) destIp = ciscoDst[1];
    }

    // Fallback IP extraction: if line contains an IP that hasn't been mapped
    if (!sourceIp) {
      const allIps = strippedLine.match(/\b([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b/g);
      if (allIps && allIps.length > 0) {
        // Pick first IP as source IP if not 0.0.0.0
        const validIp = allIps.find(ip => ip !== '0.0.0.0' && ip !== '255.255.255.255');
        if (validIp) sourceIp = validIp;
      }
    }

    // Source Port
    if (!sourcePort) {
      const sptMatch = strippedLine.match(/\b(?:SPT|spt|sport|source_port)[=:\s]+([0-9]{1,5})\b/i) ||
        strippedLine.match(/Source\s+Port:\s*([0-9]{1,5})\b/i) ||
        strippedLine.match(/\bport\s+([0-9]{1,5})\b/i);
      if (sptMatch) sourcePort = parseInt(sptMatch[1], 10);
      else if (sourceIp) {
        const portWithIp = strippedLine.match(new RegExp(`${sourceIp.replace(/\./g, '\\.')}[:\\/]([0-9]{1,5})\\b`));
        if (portWithIp) sourcePort = parseInt(portWithIp[1], 10);
      }
    }

    // Dest Port
    if (!destPort) {
      const dptMatch = strippedLine.match(/\b(?:DPT|dpt|dport|dest_port)[=:\s]+([0-9]{1,5})\b/i) ||
        strippedLine.match(/Destination\s+Port:\s*([0-9]{1,5})\b/i);
      if (dptMatch) destPort = parseInt(dptMatch[1], 10);
      else if (destIp) {
        const portWithIp = strippedLine.match(new RegExp(`${destIp.replace(/\./g, '\\.')}[:\\/]([0-9]{1,5})\\b`));
        if (portWithIp) destPort = parseInt(portWithIp[1], 10);
      }
    }

    // Protocol
    const protoMatch = strippedLine.match(/\b(?:PROTO|proto|protocol|transport)[=:\s]+([A-Za-z0-9]+)\b/i) ||
      strippedLine.match(/\b(TCP|UDP|ICMP|ssh2|HTTP\/[0-9.]+|HTTPS|TLS|DNS)\b/i);
    if (protoMatch) protocol = protoMatch[1].toUpperCase();

    // 5. Action extraction
    let action: string | null = null;
    if (/failed\s+password|authentication\s+failed|auth\s+failed|logon\s+failed|login\s+failed|failed\s+to\s+log\s*on|audit\s+failure|password\s+check\s+failed|Unknown user name or bad password/i.test(strippedLine)) action = 'AUTH_FAILED';
    else if (/accepted\s+publickey|accepted\s+password|successful\s+logon|successful\s+login|successfully\s+logged\s*on|account\s+was\s+successfully\s+logged\s+on|audit\s+success/i.test(strippedLine)) action = 'AUTH_SUCCESS';
    else if (/session\s+opened/i.test(strippedLine)) action = 'SESSION_OPENED';
    else if (/session\s+closed/i.test(strippedLine)) action = 'SESSION_CLOSED';
    else if (/authorization\s+denied|permission\s+denied|client\s+denied/i.test(strippedLine)) action = 'ACCESS_DENIED';
    else if (/access\s+forbidden|forbidden\s+by\s+rule/i.test(strippedLine)) action = 'ACCESS_FORBIDDEN';
    else if (/connection\s+refused|connection\s+rejected|connect\s+failed/i.test(strippedLine)) action = 'CONNECTION_REFUSED';
    else if (/limit_req\s+exceeded|rate\s+limit\s+exceeded/i.test(strippedLine)) action = 'RATE_LIMIT_EXCEEDED';
    else if (/new\s+user:/i.test(strippedLine)) action = 'USER_CREATED';
    else if (/add\s+['"][^'"]+['"]\s+to\s+group/i.test(strippedLine)) action = 'USER_MODIFIED';
    else if (/Deactivated|stop/i.test(strippedLine)) action = 'SERVICE_STOPPED';
    else if (/Started/i.test(strippedLine)) action = 'SERVICE_STARTED';
    else if (/COMMAND=([^\s;]+)/i.test(strippedLine)) {
      const cmd = strippedLine.match(/COMMAND=([^\s;]+)/i);
      action = cmd ? `CMD: ${cmd[1]}` : 'CMD_EXEC';
    } else if (/\b(BLOCK|BLOCKED)\b/i.test(strippedLine)) action = 'BLOCKED';
    else if (/\b(ALLOW|ALLOWED)\b/i.test(strippedLine)) action = 'ALLOWED';
    else if (/\b(DROP|DROPPED)\b/i.test(strippedLine)) action = 'DROPPED';
    else if (/\b(DENY|DENIED)\b/i.test(strippedLine)) action = 'DENIED';
    else if (/\b(REJECT|REJECTED)\b/i.test(strippedLine)) action = 'REJECTED';
    else if (/\b(SYN)\b/i.test(strippedLine)) action = 'SYN';
    else {
      const actMatch = strippedLine.match(/\b(?:action|act|status|result)[=:\s]+([A-Za-z0-9_\-]+)\b/i);
      if (actMatch) action = actMatch[1].toUpperCase();
      else {
        const httpMatch = strippedLine.match(/"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([^\s"]+)/i);
        if (httpMatch) action = `${httpMatch[1].toUpperCase()} ${httpMatch[2]}`;
      }
    }

    // 6. Event ID extraction
    let eventId: string | null = null;
    const eventIdMatch = strippedLine.match(/\b(?:event_?id|eventId)=([A-Za-z0-9_-]+)\b/i) ||
      strippedLine.match(/\b(?:Event\s*ID|EventCode|Event)[:\s]+(\d+)\b/i) ||
      strippedLine.match(/\[1:(\d+):\d+\]/) || // Snort/Suricata SID
      strippedLine.match(/(%ASA-\d+-\d+)/) || // Cisco ASA
      strippedLine.match(/\b(?:Microsoft-Windows-[A-Za-z0-9_-]+|Security-Auditing|Security)\s+(\d{3,5})\b/i) || // Windows Event ID
      strippedLine.match(/\b(?:[A-Za-z0-9_-]+)\[(\d+)\]/i); // Service PID like sshd[1842], app[2420], filterlog[1234]
    if (eventIdMatch) eventId = eventIdMatch[1];

    return {
      eventId,
      sourceIp,
      destIp,
      sourcePort,
      destPort,
      protocol,
      action,
      severity,
      rawEvent: cleanLine,
      timestamp,
    };
  }

  parse(content: string, options: FileParserOptions): AnalysisInput {
    const lines = content.split(/\r?\n/).map(l => l.trim()).filter(l => l.length > 0);

    let riskScore: number | null = null;
    let threatLevel: string | null = null;
    let hostname: string | null = null;
    let username: string | null = null;
    let operatingSystem: string | null = null;
    let recommendation: string | null = null;
    let analysisTime: Date | null = null;
    const sandboxMetrics: Record<string, any> = {};
    let sandboxVerdict: string | null = null;
    let sandboxScore: number | null = null;
    let sandboxName = 'Automated Sandbox';

    const hashes: AnalysisInputHashes = {};
    const fileProperties: any = {};
    const yaraResults: AnalysisInputYara[] = [];
    let virusTotal: AnalysisInputVirusTotal | null = null;
    const iocs: AnalysisInputIoc[] = [];
    const mitreTechniques: AnalysisInputMitre[] = [];
    const behaviorEvents: AnalysisInputBehavior[] = [];
    const sandboxResults: AnalysisInputSandbox[] = [];
    const siemEvents: AnalysisInputSiem[] = [];
    const incidents: AnalysisInputIncident[] = [];
    const soarExecutions: AnalysisInputSoar[] = [];
    const assets: AnalysisInputAsset[] = [];
    const endpoints: AnalysisInputEndpoint[] = [];
    const vulnerabilities: AnalysisInputVulnerability[] = [];
    const unparsedLines: { lineNum: number; content: string }[] = [];
    const providedSectionsSet = new Set<string>();

    const ipRegex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/;
    const cveRegex = /\b(CVE-\d{4}-\d{4,7})\b/i;
    let inferredYear = 2026;
    const isoDateMatch = content.match(/\b(20[2-3]\d)-\d{2}-\d{2}\b/);
    const clfDateMatch = content.match(/\/[A-Za-z]{3}\/(20[2-3]\d):/);
    if (isoDateMatch) {
      inferredYear = parseInt(isoDateMatch[1], 10);
    } else if (clfDateMatch) {
      inferredYear = parseInt(clfDateMatch[1], 10);
    }

    let currentSection = '';

    const isDivider = (l: string) => /^={3,}$/.test(l) || /^-{3,}$/.test(l) || /^#{3,}$/.test(l);
    const isDrivePath = (l: string) => /^[A-Za-z]:[\\/]/.test(l.trim());
    const isBulletLine = (l: string) => /^[-*•]|\d+[\.\)]/.test(l.trim());
    const isSectionHeaderLine = (l: string) => /^(?:\[([^\]]+)\]|={3,}\s*(.*?)\s*={3,}|#{1,3}\s*(.*))$/.test(l.trim());
    const isKeyValueLine = (l: string) => !isDrivePath(l) && !isBulletLine(l) && /^([^:=->\t]+?)\s*(?:=>|->|:=|[:=->\t])\s*(.*)$/.test(l.trim());

    const isNegativeFinding = (v: string): boolean => {
      if (!v) return true;
      const clean = v.trim().toLowerCase();
      if (/^(none|no|false|0|nil|n\/a|na|not detected|none detected|clean|null|-)$/i.test(clean)) return true;
      if (/^no\s+(malicious|suspicious|persistence|files?|processes?|registry|activity|behavior)/i.test(clean)) return true;
      if (/^(created\s*process|registry\s*modified|persistence|dropped\s*files?)\s*:\s*(none|no|false|0|nil|n\/a)$/i.test(clean)) return true;
      return false;
    };

    const getNextNonEmptyLine = (idx: number): { line: string; index: number } | null => {
      for (let j = idx + 1; j < lines.length; j++) {
        const l = lines[j].trim();
        if (l.length > 0) {
          return { line: l, index: j };
        }
      }
      return null;
    };

    const equalsAnyAlias = (normK: string, aliases: string[]) => {
      return aliases.some(a => normK === normalizeKey(a));
    };

    let currentIncidentObj: Partial<AnalysisInputIncident> | null = null;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // 1. Block Section Header check: Divider -> Title -> Divider
      if (isDivider(line)) {
        if (i + 2 < lines.length && isDivider(lines[i + 2])) {
          const title = lines[i + 1].trim();
          if (title.length > 0) {
            currentSection = normalizeKey(title);
            for (const [secKey, aliases] of Object.entries(SECTION_ALIASES)) {
              if (aliases.some(a => currentSection.includes(normalizeKey(a)))) {
                providedSectionsSet.add(secKey);
              }
            }
            i += 2; // Advance past title and closing divider line
            continue;
          }
        }
        // Standalone divider line
        continue;
      }

      // 2. Inline Section Header check: [YARA], === YARA RESULTS ===, # YARA
      const sectionMatch = line.match(/^(?:\[([^\]]+)\]|={3,}\s*(.*?)\s*={3,}|#{1,3}\s*(.*))$/);
      if (sectionMatch) {
        const rawSec = sectionMatch[1] ?? sectionMatch[2] ?? sectionMatch[3] ?? '';
        const secText = typeof rawSec === 'string' ? rawSec.trim() : '';
        if (secText.length > 0) {
          currentSection = normalizeKey(secText);
          for (const [secKey, aliases] of Object.entries(SECTION_ALIASES)) {
            if (aliases.some(a => currentSection.includes(normalizeKey(a)))) {
              providedSectionsSet.add(secKey);
            }
          }
          continue;
        }
      }

      let matched = false;

      // Key-Value separator: :, =, =>, ->, or tab (ignore drive paths like C:\...)
      const isDrive = isDrivePath(line);
      const kvMatch = !isDrive ? line.match(/^([^:=->\t]+?)\s*(?:=>|->|:=|[:=->\t])\s*(.*)$/) : null;
      let rawKey = '';
      let val = '';

      if (kvMatch) {
        rawKey = kvMatch[1].trim();
        val = kvMatch[2].trim();

        const normKeyCheck = normalizeKey(rawKey);

        // Multi-line value check: if val is empty, look ahead to see if the value is on the next line
        if (val.length === 0) {
          if (
            normKeyCheck !== 'recommendation' &&
            normKeyCheck !== 'recommendations' &&
            normKeyCheck !== 'matchedstrings' &&
            normKeyCheck !== 'imports'
          ) {
            const nextObj = getNextNonEmptyLine(i);
            if (nextObj) {
              const nextL = nextObj.line;
              const nextIsDrive = isDrivePath(nextL);
              const nextKv = !nextIsDrive ? nextL.match(/^([^:=->\t]+?)\s*(?:=>|->|:=|[:=->\t])\s*(.*)$/) : null;
              if (!isDivider(nextL) && !isSectionHeaderLine(nextL) && (!nextKv || nextIsDrive)) {
                val = nextL;
                i = nextObj.index; // Advance i to line of value
              }
            }
          }
        }
      } else {
        // Multi-line Key-Value pair check without colon on the key line
        const normLine = normalizeKey(line);
        const nextObj = getNextNonEmptyLine(i);
        if (nextObj) {
          const nextL = nextObj.line;
          const nextIsDrive = isDrivePath(nextL);
          const nextKv = !nextIsDrive ? nextL.match(/^([^:=->\t]+?)\s*(?:=>|->|:=|[:=->\t])\s*(.*)$/) : null;
          if (!isDivider(nextL) && !isSectionHeaderLine(nextL) && (!nextKv || nextIsDrive)) {
            const isKnownKey =
              equalsAnyAlias(normLine, ALIAS_MAPS.risk.riskScore) ||
              equalsAnyAlias(normLine, ALIAS_MAPS.risk.threatLevel) ||
              equalsAnyAlias(normLine, ALIAS_MAPS.metadata.hostname) ||
              equalsAnyAlias(normLine, ALIAS_MAPS.metadata.username) ||
              equalsAnyAlias(normLine, ALIAS_MAPS.metadata.operatingSystem) ||
              equalsAnyAlias(normLine, ALIAS_MAPS.metadata.analysisTime) ||
              equalsAnyAlias(normLine, ALIAS_MAPS.yara.ruleName) ||
              equalsAnyAlias(normLine, ALIAS_MAPS.virusTotal.positives) ||
              equalsAnyAlias(normLine, ALIAS_MAPS.iocs.value) ||
              equalsAnyAlias(normLine, ALIAS_MAPS.behavior.target) ||
              equalsAnyAlias(normLine, ALIAS_MAPS.incidents.title) ||
              equalsAnyAlias(normLine, ALIAS_MAPS.soar.actionName) ||
              currentSection.includes('behavior') ||
              normLine === 'matchedrule' || normLine === 'detectionratio' || normLine === 'remoteip' ||
              normLine === 'commandcontroldomain' || normLine === 'malwaredistributiondomain' ||
              normLine === 'url' || normLine === 'emailioc' || normLine === 'processespawned' ||
              normLine === 'createdprocess' || normLine === 'registrymodified' ||
              normLine === 'persistence' || normLine === 'droppedfile' || normLine === 'droppedfiles' || normLine === 'scheduledtask' ||
              normLine === 'incidentid' || normLine === 'playbook' || normLine === 'executed' ||
              normLine === 'completed' || normLine === 'classification' || normLine === 'threatfamily' ||
              normLine === 'matchedstrings' || normLine === 'severity';

            if (isKnownKey) {
              rawKey = line;
              val = nextL;
              i = nextObj.index; // Advance i to line of value
            }
          }
        }
      }

      const normK = normalizeKey(rawKey);

      if (
        normK.length > 0 &&
        (val.length > 0 ||
          normK === 'recommendation' ||
          normK === 'recommendations' ||
          normK === 'matchedstrings' ||
          normK === 'imports' ||
          equalsAnyAlias(normK, ALIAS_MAPS.risk.recommendation))
      ) {
        if (equalsAnyAlias(normK, ALIAS_MAPS.risk.riskScore) || (normK === 'risk' && /\d/.test(val))) {
          const scoreMatch = val.match(/(\d+)/);
          if (scoreMatch) riskScore = parseInt(scoreMatch[1], 10);
          matched = true;
        } else if (equalsAnyAlias(normK, ALIAS_MAPS.risk.threatLevel) || (normK === 'risk' && !/\d/.test(val))) {
          threatLevel = val;
          matched = true;
        } else if (equalsAnyAlias(normK, ALIAS_MAPS.metadata.hostname)) {
          hostname = val;
          matched = true;
        } else if (equalsAnyAlias(normK, ALIAS_MAPS.metadata.username)) {
          username = val;
          matched = true;
        } else if (equalsAnyAlias(normK, ALIAS_MAPS.metadata.operatingSystem)) {
          operatingSystem = val;
          matched = true;
        } else if (equalsAnyAlias(normK, ALIAS_MAPS.metadata.analysisTime)) {
          const parsed = this.extractAnyTimestamp(val, inferredYear) || new Date(val);
          if (!isNaN(parsed.getTime())) {
            analysisTime = parsed;
            matched = true;
          }
        } else if (equalsAnyAlias(normK, ALIAS_MAPS.risk.recommendation) || normK === 'recommendation' || normK === 'recommendations') {
          const recBullets: string[] = [];
          if (val.length > 0 && !val.startsWith(':')) {
            recBullets.push(val);
          }
          while (i + 1 < lines.length) {
            const nextL = lines[i + 1].trim();
            if (isDivider(nextL) || isSectionHeaderLine(nextL)) break;
            if (isBulletLine(nextL)) {
              recBullets.push(nextL);
              i++;
            } else if (recBullets.length === 0 && !isKeyValueLine(nextL)) {
              recBullets.push(nextL);
              i++;
            } else {
              break;
            }
          }
          if (recBullets.length > 0) {
            const fullRec = recBullets.join('\n');
            recommendation = recommendation ? `${recommendation}\n${fullRec}` : fullRec;
          }
          matched = true;
        } else if (normK === 'md5' || normK === 'md5hash' || normK === 'filemd5') {
          hashes.md5 = val;
          matched = true;
        } else if (normK === 'sha1' || normK === 'sha1hash' || normK === 'filesha1') {
          hashes.sha1 = val;
          matched = true;
        } else if (normK === 'sha256' || normK === 'sha256hash' || normK === 'filesha256') {
          hashes.sha256 = val;
          matched = true;
        } else if (normK === 'ssdeep') {
          hashes.ssdeep = val;
          matched = true;
        } else if (normK === 'entropy' || normK === 'fileentropy') {
          const num = parseFloat(val);
          if (!isNaN(num)) fileProperties.entropy = num;
          matched = true;
        } else if (normK.includes('digitalsignature') || normK.includes('signature')) {
          fileProperties.digitalSignature = val;
          matched = true;
        } else if (normK === 'compiletime' || normK === 'compilationdate') {
          fileProperties.compileTime = val;
          matched = true;
        } else if (normK === 'packed' || normK === 'ispacked') {
          fileProperties.isPacked = /yes|true|1/i.test(val);
          const packerMatch = val.match(/\(([^)]+)\)/);
          if (packerMatch) fileProperties.packer = packerMatch[1];
          matched = true;
        } else if (normK === 'packer' || normK === 'packername') {
          fileProperties.packer = val;
          matched = true;
        } else if (normK === 'imports' || equalsAnyAlias(normK, ALIAS_MAPS.fileProperties.imports)) {
          if (!fileProperties.imports) fileProperties.imports = [];
          const cleanDll = val.replace(/^imports\s*:\s*/i, '').trim();
          if (cleanDll.length > 0 && !fileProperties.imports.includes(cleanDll)) {
            fileProperties.imports.push(cleanDll);
          }
          while (i + 1 < lines.length) {
            const nextL = lines[i + 1].trim();
            if (isDivider(nextL) || isSectionHeaderLine(nextL)) break;
            if (nextL.toLowerCase().endsWith('.dll') && !nextL.includes(':')) {
              const cleanNext = nextL.replace(/^imports\s*:\s*/i, '').trim();
              if (!fileProperties.imports.includes(cleanNext)) {
                fileProperties.imports.push(cleanNext);
              }
              i++;
            } else {
              break;
            }
          }
          matched = true;
        } else if (equalsAnyAlias(normK, ALIAS_MAPS.yara.ruleName) || (normK.includes('yara') && !currentSection.includes('yara')) || normK === 'matchedrule') {
          yaraResults.push({ ruleName: val });
          providedSectionsSet.add('yara');
          matched = true;
        } else if (normK === 'matchedstrings') {
          matched = true;
          if (val.length > 0) {
            if (yaraResults.length > 0) {
              const currentRule = yaraResults[yaraResults.length - 1];
              currentRule.tags = Array.isArray(currentRule.tags) ? [...(currentRule.tags as string[]), val] : [val];
            }
          }
          while (i + 1 < lines.length) {
            const nextL = lines[i + 1].trim();
            if (isDivider(nextL) || isSectionHeaderLine(nextL)) break;
            if (nextL.startsWith('$')) {
              if (yaraResults.length > 0) {
                const currentRule = yaraResults[yaraResults.length - 1];
                currentRule.tags = Array.isArray(currentRule.tags) ? [...(currentRule.tags as string[]), nextL] : [nextL];
              }
              i++;
            } else {
              break;
            }
          }
        } else if (normK === 'severity' && currentSection.includes('yara')) {
          if (yaraResults.length > 0) {
            yaraResults[yaraResults.length - 1].description = `Severity: ${val}`;
          }
          matched = true;
        } else if (equalsAnyAlias(normK, ALIAS_MAPS.virusTotal.positives) || normK.includes('virustotal') || normK === 'vt' || normK.includes('detectionratio')) {
          const vtMatch = val.match(/(\d+)\s*\/\s*(\d+)/);
          if (vtMatch) {
            virusTotal = {
              positives: parseInt(vtMatch[1], 10),
              total: parseInt(vtMatch[2], 10),
            };
          }
          providedSectionsSet.add('virusTotal');
          matched = true;
        } else if (normK.includes('ipaddress') || normK === 'ip' || normK === 'remoteip') {
          iocs.push({ type: 'IP', value: val });
          providedSectionsSet.add('iocs');
          matched = true;
        } else if (normK === 'domain' || normK.includes('domain') || normK.includes('commandcontroldomain') || normK.includes('malwaredistributiondomain')) {
          iocs.push({ type: 'DOMAIN', value: val });
          providedSectionsSet.add('iocs');
          matched = true;
        } else if (normK === 'url') {
          iocs.push({ type: 'URL', value: val });
          providedSectionsSet.add('iocs');
          matched = true;
        } else if (normK === 'email' || normK.includes('email')) {
          iocs.push({ type: 'EMAIL', value: val });
          providedSectionsSet.add('iocs');
          matched = true;
        } else if (normK.includes('ioc') || normK.includes('indicator')) {
          const parts = val.split(/[-–:]/).map(p => p.trim());
          if (parts.length >= 2) {
            iocs.push({ type: parts[0].toUpperCase(), value: parts[1] });
          } else {
            const ip = val.match(ipRegex);
            if (ip) iocs.push({ type: 'IP', value: ip[0] });
            else iocs.push({ type: 'INDICATOR', value: val });
          }
          providedSectionsSet.add('iocs');
          matched = true;
        } else if (equalsAnyAlias(normK, ALIAS_MAPS.mitre.techniqueId) || normK.includes('mitre') || normK.includes('technique')) {
          const mitreMatch = val.match(/(T\d{4}(?:\.\d{3})?)\s*[-–]?\s*(.*)/i);
          if (mitreMatch) {
            mitreTechniques.push({
              tactic: 'Execution',
              techniqueId: mitreMatch[1].toUpperCase(),
              name: mitreMatch[2] || mitreMatch[1],
            });
            providedSectionsSet.add('mitre');
          }
          matched = true;
        } else if (
          equalsAnyAlias(normK, ALIAS_MAPS.behavior.target) ||
          normK.includes('processespawned') ||
          normK.includes('createdprocess') ||
          normK.includes('processcreated') ||
          normK.includes('persistence') ||
          normK.includes('droppedfile') ||
          normK.includes('droppedfiles') ||
          normK.includes('registrymodified') ||
          normK.includes('scheduledtask') ||
          currentSection.includes('behavior')
        ) {
          providedSectionsSet.add('behavior');
          matched = true;
          if (!isNegativeFinding(val)) {
            let eventType = 'BEHAVIOR';
            let action = 'OBSERVED';
            let target = val;

            if (normK.includes('process')) {
              eventType = 'PROCESS';
              action = 'PROCESS_CREATE';
            } else if (normK.includes('registry')) {
              eventType = 'REGISTRY';
              action = 'REGISTRY_MODIFIED';
            } else if (normK.includes('persistence')) {
              eventType = 'PERSISTENCE';
              action = 'PERSISTENCE_DETECTED';
              if (/^(yes|true|1)$/i.test(val)) {
                target = 'Persistence Mechanism';
              }
            } else if (normK.includes('dropped') || normK.includes('file')) {
              eventType = 'FILE';
              action = 'FILE_DROP';
            } else if (normK.includes('task')) {
              eventType = 'SCHEDULED_TASK';
              action = 'TASK_CREATED';
            }

            behaviorEvents.push({
              eventType,
              action,
              target,
            });
          }
        } else if (currentSection.includes('sandbox')) {
          providedSectionsSet.add('sandbox');
          matched = true;
          if (normK === 'processescreated' || normK === 'createdprocesses') {
            sandboxMetrics.processesCreated = parseInt(val, 10);
          } else if (normK === 'filescreated' || normK === 'createdfiles') {
            sandboxMetrics.filesCreated = parseInt(val, 10);
          } else if (normK === 'registrykeys' || normK === 'registrykeysmodified') {
            sandboxMetrics.registryKeys = parseInt(val, 10);
          } else if (normK === 'networkrequests' || normK === 'networkconnections') {
            sandboxMetrics.networkRequests = parseInt(val, 10);
          } else if (normK === 'verdict' || equalsAnyAlias(normK, ALIAS_MAPS.sandbox.verdict)) {
            sandboxVerdict = val;
          } else if (normK === 'score' || equalsAnyAlias(normK, ALIAS_MAPS.sandbox.score)) {
            const s = parseInt(val, 10);
            if (!isNaN(s)) sandboxScore = s;
          } else if (normK === 'sandboxname' || equalsAnyAlias(normK, ALIAS_MAPS.sandbox.sandboxName)) {
            sandboxName = val;
          } else {
            const num = Number(val);
            sandboxMetrics[rawKey] = isNaN(num) ? val : num;
          }
        } else if (normK.includes('playbook')) {
          soarExecutions.push({
            actionName: val,
            status: 'RECOMMENDED' as any,
          });
          providedSectionsSet.add('soar');
          matched = true;
        } else if (normK.includes('executed') || normK.includes('completed')) {
          if (soarExecutions.length > 0) {
            soarExecutions[soarExecutions.length - 1].status = 'COMPLETED' as any;
          } else {
            soarExecutions.push({
              actionName: val,
              status: 'COMPLETED' as any,
            });
          }
          providedSectionsSet.add('soar');
          matched = true;
        } else if (normK === 'incidentid' || normK === 'incident_id') {
          if (!currentIncidentObj) currentIncidentObj = {};
          currentIncidentObj.reason = `Incident ID: ${val}`;
          providedSectionsSet.add('incident');
          matched = true;
        } else if (normK === 'title' && currentSection.includes('incident')) {
          if (!currentIncidentObj) currentIncidentObj = {};
          currentIncidentObj.title = val;
          providedSectionsSet.add('incident');
          matched = true;
        } else if (normK === 'severity' && currentSection.includes('incident')) {
          if (!currentIncidentObj) currentIncidentObj = {};
          currentIncidentObj.severity = this.normalizer.normalizeThreatLevel(val);
          providedSectionsSet.add('incident');
          matched = true;
        } else if (normK === 'status' && currentSection.includes('incident')) {
          if (!currentIncidentObj) currentIncidentObj = {};
          currentIncidentObj.status = val;
          providedSectionsSet.add('incident');
          matched = true;
        } else if (normK === 'assignedto' && currentSection.includes('incident')) {
          if (!currentIncidentObj) currentIncidentObj = {};
          currentIncidentObj.assignedTo = val;
          providedSectionsSet.add('incident');
          matched = true;
        }
      }

      // Standalone pattern matchers
      if (!matched) {
        if (!hashes.md5) {
          const match = line.match(/\bMD5:\s*([a-fA-F0-9]{32})\b/i);
          if (match) { hashes.md5 = match[1]; matched = true; }
        }
        if (!hashes.sha256) {
          const match = line.match(/\bSHA256:\s*([a-fA-F0-9]{64})\b/i);
          if (match) { hashes.sha256 = match[1]; matched = true; }
        }
        const mitreMatch = line.match(/^(T\d{4}(?:\.\d{3})?)\s+([-–\w\s]+)$/i);
        if (mitreMatch) {
          mitreTechniques.push({
            tactic: 'Execution',
            techniqueId: mitreMatch[1].toUpperCase(),
            name: mitreMatch[2].trim(),
          });
          providedSectionsSet.add('mitre');
          matched = true;
        }
      }

      // Contextual Section Parsing
      if (!matched && currentSection) {
        if (currentSection.includes('yara') || currentSection.includes('rules')) {
          if (line.startsWith('$')) {
            if (yaraResults.length > 0) {
              const currentRule = yaraResults[yaraResults.length - 1];
              currentRule.tags = Array.isArray(currentRule.tags) ? [...(currentRule.tags as string[]), line] : [line];
            }
            matched = true;
          } else if (
            isNegativeFinding(line) ||
            /^matched\s*(strings?|rules?)|severity|rulename/i.test(line) ||
            line.includes(':')
          ) {
            matched = true;
          } else if (line !== 'Matched Rule' && line !== 'Severity' && line !== 'Matched Strings') {
            if (yaraResults.length === 0 || yaraResults[yaraResults.length - 1].ruleName !== line) {
              yaraResults.push({ ruleName: line });
              providedSectionsSet.add('yara');
            }
            matched = true;
          }
        } else if (currentSection.includes('vulnerabil') || currentSection.includes('cve')) {
          const cveMatch = line.match(cveRegex);
          if (cveMatch || /cve|vulnerab|flaw|exploit|patch|security|kernel|rce|overflow|injection/i.test(line)) {
            vulnerabilities.push({
              cveId: cveMatch ? cveMatch[1].toUpperCase() : 'CVE-LOG',
              title: line,
            });
            providedSectionsSet.add('vulnerabilities');
            matched = true;
          }
        } else if (currentSection.includes('asset')) {
          assets.push({ assetName: line });
          providedSectionsSet.add('assets');
          matched = true;
        } else if (currentSection.includes('endpoint')) {
          endpoints.push({ hostname: line });
          providedSectionsSet.add('endpoints');
          matched = true;
        } else if (currentSection.includes('mitre') || currentSection.includes('attack')) {
          const mitreMatch = line.match(/(T\d{4}(?:\.\d{3})?)\s*[-–]?\s*(.*)/i);
          if (mitreMatch) {
            mitreTechniques.push({
              tactic: 'Execution',
              techniqueId: mitreMatch[1].toUpperCase(),
              name: mitreMatch[2] || mitreMatch[1],
            });
            providedSectionsSet.add('mitre');
            matched = true;
          } else if (isNegativeFinding(line)) {
            matched = true;
          }
        } else if (currentSection.includes('behavior')) {
          if (isNegativeFinding(line)) {
            matched = true;
          } else if (!line.includes(':') && line !== 'Processes Spawned' && line !== 'Persistence' && line !== 'Dropped File' && line !== 'Scheduled Task') {
            behaviorEvents.push({
              eventType: 'BEHAVIOR',
              action: 'OBSERVED',
              target: line,
            });
            providedSectionsSet.add('behavior');
            matched = true;
          }
        } else if (currentSection.includes('sandbox')) {
          if (isNegativeFinding(line)) {
            matched = true;
            if (!sandboxVerdict) sandboxVerdict = 'Clean';
          }
        } else if (currentSection.includes('soar')) {
          if (line !== 'Playbook' && line !== 'Executed' && line !== 'Completed' && line !== 'Pending Approval') {
            const status = line.toLowerCase().includes('recommend') || line.toLowerCase().includes('pending') ? 'RECOMMENDED' : 'COMPLETED';
            soarExecutions.push({
              actionName: line,
              status: status as any,
            });
            providedSectionsSet.add('soar');
            matched = true;
          }
        } else if (currentSection.includes('static')) {
          if (line.toLowerCase().endsWith('.dll')) {
            if (!fileProperties.imports) fileProperties.imports = [];
            const cleanDll = line.replace(/^imports\s*:\s*/i, '').trim();
            if (!fileProperties.imports.includes(cleanDll)) {
              fileProperties.imports.push(cleanDll);
            }
            matched = true;
          } else if (['CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory', 'WinExec', 'URLDownloadToFileA', 'InternetOpenUrlA'].includes(line)) {
            if (!fileProperties.suspiciousApis) fileProperties.suspiciousApis = [];
            fileProperties.suspiciousApis.push(line);
            matched = true;
          } else if (line === 'Imports' || line === 'Suspicious APIs' || isNegativeFinding(line)) {
            matched = true;
          }
        } else if (currentSection.includes('risk')) {
          if (line.toLowerCase().includes('recommend') || line.endsWith('.')) {
            recommendation = recommendation ? `${recommendation} ${line}` : line;
            matched = true;
          }
        } else if (currentSection.includes('siem') || currentSection.includes('log') || currentSection.includes('event')) {
          const parsedSiem = this.parseSiemLogLine(line, inferredYear);
          if (parsedSiem) {
            siemEvents.push(parsedSiem);
            providedSectionsSet.add('siem');
            matched = true;
          }
        }
      }

      // Comments (# or //) are ignorable documentation lines
      if (!matched && (/^(?:#|\/\/)/.test(line))) {
        matched = true;
      }

      // Syslog / SIEM log line structural detection
      const isJsonLine = line.startsWith('{') && line.endsWith('}');
      const isSyslogTimestamp = /^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}/i.test(line);
      const isIsoTimestamp = /^\d{4}[-/]\d{2}[-/]\d{2}[T\s]\d{2}:\d{2}:\d{2}/.test(line);
      const isUsEuroTimestamp = /^\d{1,2}[/-]\d{1,2}[/-]\d{4}[\sT]\d{2}:\d{2}:\d{2}/.test(line);
      const isClfLine = /^[0-9]{1,3}(?:\.[0-9]{1,3}){3}\s+-\s+.*\[\d{1,2}\/[A-Za-z]{3}\/\d{4}:/.test(line);
      const isBracketedDate = /^\[(?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+)?[A-Za-z0-9\/\-:,\.\s+]+\]/i.test(line) && this.extractAnyTimestamp(line, inferredYear) !== null;
      const isPriSyslog = /^<\d{1,3}>/.test(line);
      const isCef = /^(?:CEF|LEEF):\d+/i.test(line);
      const isCisco = /^%[A-Za-z0-9_-]+-\d+-[A-Za-z0-9_]+:/.test(line);
      const isSnort = /^(?:\[\*\*\]|\d{1,2}\/\d{1,2}(?:-\d{2}:\d{2}:\d{2})|\d{1,2}\/\d{1,2}\/\d{4}-\d{2}:\d{2}:\d{2})/.test(line);
      const isWindowsEvent = /\b(?:EventID|Event\s+ID:?\s*\d+|EventCode=\d+|Microsoft-Windows-[A-Za-z0-9_-]+)\b/i.test(line);
      const isKnownServiceLine = /\b(?:sshd|sudo|kernel|systemd|useradd|usermod|CRON|nginx|app\[\d+\]|audit|iptables|named|postfix|httpd|ftpd|suricata|snort|firewalld|dockerd|containerd)\b/i.test(line);
      const isKeyValueLog = /\b(?:SRC|DST|src_ip|dst_ip|suser|duser|proto|action|status|event_id)=/i.test(line);
      const hasSecurityAction = /\b(?:ALLOW|ALLOWED|DENY|DENIED|BLOCK|BLOCKED|DROP|DROPPED|REJECT|REJECTED|ACCEPT|ACCEPTED|PERMIT|PERMITTED|FAILED\s+PASSWORD|AUTHENTICATION\s+FAILED|AUDIT\s+FAILURE|LOGON\s+FAILED)\b/i.test(line);
      const hasAnyExtractedDate = this.extractAnyTimestamp(line, inferredYear) !== null;

      if (!matched && (
        isJsonLine ||
        isSyslogTimestamp ||
        isIsoTimestamp ||
        isUsEuroTimestamp ||
        isClfLine ||
        isBracketedDate ||
        isPriSyslog ||
        isCef ||
        isCisco ||
        isSnort ||
        isWindowsEvent ||
        isKnownServiceLine ||
        isKeyValueLog ||
        hasSecurityAction ||
        (hasAnyExtractedDate && (line.includes(':') || line.includes(' ')))
      )) {
        const parsedSiem = this.parseSiemLogLine(line, inferredYear);
        if (parsedSiem) {
          siemEvents.push(parsedSiem);
          providedSectionsSet.add('siem');
          matched = true;
        }
      }

      // Structural headers & report titles
      if (!matched) {
        if (
          /^SOC PLATFORM/i.test(line) ||
          /^END OF REPORT/i.test(line) ||
          /^END OF LOG/i.test(line) ||
          /^ANALYSIS LOG/i.test(line) ||
          line === 'Matched Rule' ||
          line === 'Severity' ||
          line === 'Matched Strings' ||
          /^matched\s*strings?\s*:?$/i.test(line) ||
          line === 'Classification' ||
          line === 'Threat Family' ||
          line === 'Title' ||
          line === 'Status' ||
          line === 'Assigned To' ||
          line === 'Playbook' ||
          line === 'Executed' ||
          line === 'Completed' ||
          isNegativeFinding(line)
        ) {
          matched = true;
        } else {
          unparsedLines.push({ lineNum: i + 1, content: line });
        }
      }
    }

    if (currentIncidentObj && (currentIncidentObj.title || currentIncidentObj.reason)) {
      incidents.push({
        title: currentIncidentObj.title || 'Security Incident',
        severity: this.normalizer.normalizeThreatLevel(currentIncidentObj.severity || threatLevel),
        status: currentIncidentObj.status || 'OPEN',
        reason: currentIncidentObj.reason || 'Source explicit incident record',
        assignedTo: currentIncidentObj.assignedTo || null,
      });
      providedSectionsSet.add('incident');
    }

    // Materialize Sandbox Results if metrics or section was provided
    if (providedSectionsSet.has('sandbox') || Object.keys(sandboxMetrics).length > 0) {
      providedSectionsSet.add('sandbox');
      if (sandboxResults.length === 0) {
        const verdict = (
          sandboxVerdict ||
          (riskScore !== null && riskScore <= 20 ? 'CLEAN' : (riskScore !== null && riskScore >= 70 ? 'MALICIOUS' : 'SUSPICIOUS'))
        ).toUpperCase();

        sandboxResults.push({
          sandboxName: sandboxName || 'Automated Sandbox',
          verdict,
          score: sandboxScore ?? riskScore,
          details: Object.keys(sandboxMetrics).length > 0 ? sandboxMetrics : null,
        });
      }
    }

    // Extract IOCs from log content using validated extraction and combine with any explicit key-value IOCs
    const extractedIocs = IocExtractor.extractIocsFromText(content);
    const combinedIocs = [...iocs, ...extractedIocs];

    if (yaraResults.length > 0) providedSectionsSet.add('yara');
    if (Boolean(virusTotal)) providedSectionsSet.add('virusTotal');
    if (combinedIocs.length > 0) providedSectionsSet.add('iocs');
    if (mitreTechniques.length > 0) providedSectionsSet.add('mitre');
    if (behaviorEvents.length > 0) providedSectionsSet.add('behavior');
    if (sandboxResults.length > 0) providedSectionsSet.add('sandbox');
    if (siemEvents.length > 0) providedSectionsSet.add('siem');
    if (incidents.length > 0) providedSectionsSet.add('incident');
    if (soarExecutions.length > 0) providedSectionsSet.add('soar');
    if (assets.length > 0) providedSectionsSet.add('assets');
    if (endpoints.length > 0) providedSectionsSet.add('endpoints');
    if (vulnerabilities.length > 0) providedSectionsSet.add('vulnerabilities');

    const warnings: string[] = [];
    if (unparsedLines.length > 0) {
      warnings.push(`${unparsedLines.length} line(s) in source document could not be matched to a canonical entity schema.`);
      for (const item of unparsedLines) {
        warnings.push(`Line ${item.lineNum}: "${item.content}" could not be matched to a canonical entity schema.`);
      }
    }

    const rawInput: Partial<AnalysisInput> = {
      metadata: {
        fileName: options.originalFileName,
        originalFileName: options.originalFileName,
        fileSize: options.fileSize,
        fileType: options.extension.replace('.', '').toUpperCase() || 'LOG',
        mimeType: options.mimeType,
        hostname,
        username,
        operatingSystem,
        analysisTime,
      },
      risk: {
        riskScore,
        threatLevel: this.normalizer.normalizeThreatLevel(threatLevel, riskScore),
        recommendation,
      },
      hashes: (hashes.md5 || hashes.sha1 || hashes.sha256 || hashes.ssdeep) ? hashes : null,
      fileProperties: (fileProperties.entropy !== undefined || fileProperties.digitalSignature || fileProperties.compileTime || fileProperties.isPacked !== undefined || fileProperties.packer || fileProperties.imports || fileProperties.suspiciousApis) ? fileProperties : null,
      yara: yaraResults.length > 0 ? yaraResults : null,
      virusTotal,
      iocs: combinedIocs.length > 0 ? combinedIocs : null,
      mitre: mitreTechniques.length > 0 ? mitreTechniques : null,
      behavior: behaviorEvents.length > 0 ? behaviorEvents : null,
      sandbox: sandboxResults.length > 0 ? sandboxResults : null,
      siem: siemEvents.length > 0 ? siemEvents : null,
      incident: incidents.length > 0 ? incidents : null,
      soar: soarExecutions.length > 0 ? soarExecutions : null,
      assets: assets.length > 0 ? assets : null,
      endpoints: endpoints.length > 0 ? endpoints : null,
      vulnerabilities: vulnerabilities.length > 0 ? vulnerabilities : null,
      parsingStatus: warnings.length > 0 ? 'PARTIAL' : 'COMPLETED',
      parsingWarnings: warnings,
      unrecognizedFields: unparsedLines.length > 0 ? { unparsedLines: unparsedLines.map(u => u.content), unparsedLineDetails: unparsedLines } : null,
      provenance: {
        parser: 'TextLogParser',
        sourceType: options.extension.toUpperCase().replace('.', '') || 'LOG',
        totalLines: lines.length,
        unparsedLineCount: unparsedLines.length,
        providedSections: Array.from(providedSectionsSet),
      },
    };

    return this.normalizer.normalize(rawInput);
  }
}
