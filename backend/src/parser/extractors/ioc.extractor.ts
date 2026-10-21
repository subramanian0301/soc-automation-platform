import * as net from 'net';
import { AnalysisInputIoc } from '../interfaces/analysis-input.interface';

// TLDs and extensions that indicate file paths or code, NOT domain names
const BLACKLISTED_DOMAIN_TLDS = new Set([
  'sh', 'bash', 'zsh', 'exe', 'dll', 'so', 'bin', 'py', 'pyc', 'js', 'mjs', 'ts', 'tsx',
  'php', 'php3', 'php4', 'php5', 'phtml', 'html', 'htm', 'css', 'scss', 'json', 'csv',
  'log', 'txt', 'xml', 'yaml', 'yml', 'env', 'conf', 'config', 'cfg', 'ini', 'service',
  'socket', 'target', 'rules', 'lock', 'bak', 'old', 'tmp', 'tar', 'gz', 'zip', '7z',
  'iso', 'deb', 'rpm', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico', 'pdf', 'doc', 'docx',
  'bat', 'cmd', 'ps1', 'psm1', 'vbs', 'awk', 'sed', 'systemd', 'mount',
  // Common English words / person-name parts that appear as pseudo-TLDs in usernames
  // e.g., john.doe, jane.smith, first.last
  'doe', 'smith', 'jones', 'brown', 'davis', 'miller', 'wilson', 'moore', 'taylor',
  'anderson', 'thomas', 'jackson', 'white', 'harris', 'martin', 'thompson', 'garcia',
  'martinez', 'robinson', 'clark', 'rodriguez', 'lewis', 'lee', 'walker', 'hall',
  'young', 'allen', 'king', 'wright', 'scott', 'green', 'baker', 'adams', 'nelson',
  'carter', 'mitchell', 'perez', 'roberts', 'turner', 'phillips', 'campbell', 'parker',
  // Common YARA/security rule meta-TLDs
  'signed', 'binary', 'clean', 'malicious', 'suspicious', 'benign', 'agent',
  'trojan', 'downloader', 'ransomware', 'backdoor', 'exploit', 'rootkit',
  'adware', 'spyware', 'worm', 'virus', 'dropper', 'loader', 'packer',
  'payload', 'scanner', 'stealer', 'miner', 'rat', 'apt', 'gen',
]);

// Common valid TLDs (or generic ASCII 2-63 chars)
const VALID_TLD_REGEX = /^[a-zA-Z]{2,63}$/;

// Lines whose key indicates they are not network indicator sources
// (matched against the normalized key portion before the colon/equals)
const NON_NETWORK_LINE_KEYS = /^(?:user(?:name)?|usr|host(?:name)?|machine|computer|os|operating\s*system|rule\s*name|matched\s*rule|yara\s*rule|packer|compile\s*time|compile\s*date|digital\s*signature|severity|threat\s*family|classification|assigned\s*to|file\s*name|file\s*type|file\s*size|mime\s*type|recommendation|analyst\s*note|notes?|comment|description|status|title|priority|author|vendor|product|version|os\s*version|agent\s*version)\s*[:=]/i;

// Lines that are clearly YARA matched-string indicators (start with $)
const YARA_STRING_INDICATOR = /^\$/;

export class IocExtractor {
  /**
   * Evaluates whether an IPv4 string is valid and not a false positive
   */
  static isValidIpv4(ip: string, surroundingContext?: string): boolean {
    if (!net.isIPv4(ip)) return false;

    // Reject all-zeroes or broadcast
    if (ip === '0.0.0.0' || ip === '255.255.255.255') return false;

    // Check octets range and no leading zeroes (e.g. 01.02.03.04)
    const octets = ip.split('.');
    if (octets.length !== 4) return false;
    for (const oct of octets) {
      if (oct.length > 1 && oct.startsWith('0')) return false;
      const num = parseInt(oct, 10);
      if (isNaN(num) || num < 0 || num > 255) return false;
    }

    // False positive check: User-Agent version string or software/agent versions (e.g. Chrome/129.0.0.0, agent_version: "4.2.1.88")
    if (surroundingContext) {
      if (
        /(?:chrome|safari|firefox|curl|webkit|version|agent_version|ver|build|release|v)[\\/\\s:\"'=_]*$/i.test(surroundingContext) ||
        /\b(?:chrome|safari|firefox|curl|webkit)\/[\d.]+$/i.test(surroundingContext) ||
        /agent_version/i.test(surroundingContext)
      ) {
        return false;
      }
      if (ip.endsWith('.0.0') && /chrome|safari|mozilla|webkit/i.test(surroundingContext)) {
        return false;
      }
    }

    return true;
  }

  /**
   * Categorizes IPv4 as Internal or External
   */
  static isPrivateIpv4(ip: string): boolean {
    const parts = ip.split('.').map((p) => parseInt(p, 10));
    // 10.0.0.0/8
    if (parts[0] === 10) return true;
    // 172.16.0.0/12
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    // 192.168.0.0/16
    if (parts[0] === 192 && parts[1] === 168) return true;
    // 127.0.0.0/8 (Loopback)
    if (parts[0] === 127) return true;
    return false;
  }

  /**
   * Validates URLs and strips trailing punctuation
   */
  static sanitizeAndValidateUrl(rawUrl: string): string | null {
    if (!rawUrl || typeof rawUrl !== 'string') return null;
    let clean = rawUrl.trim();
    // Strip trailing punctuation often found at end of log sentences
    clean = clean.replace(/[.,;:)'\"!?]+$/, '');

    try {
      const parsed = new URL(clean);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:' && parsed.protocol !== 'ftp:') {
        return null;
      }
      if (!parsed.hostname || parsed.hostname.length === 0) {
        return null;
      }
      return clean;
    } catch {
      return null;
    }
  }

  /**
   * Validates a Domain / FQDN candidate
   */
  static isValidDomain(domain: string): boolean {
    if (!domain || typeof domain !== 'string') return false;
    const clean = domain.trim().toLowerCase();

    // Must not be an IP address
    if (net.isIPv4(clean) || net.isIPv6(clean)) return false;

    // Must have at least one dot
    if (!clean.includes('.')) return false;

    // Total length must be <= 253
    if (clean.length < 4 || clean.length > 253) return false;

    const parts = clean.split('.');
    if (parts.length < 2) return false;

    const tld = parts[parts.length - 1];
    if (BLACKLISTED_DOMAIN_TLDS.has(tld)) {
      return false; // Not a domain, it's a file extension or common name word
    }

    if (!VALID_TLD_REGEX.test(tld)) {
      return false;
    }

    for (const part of parts) {
      if (part.length === 0 || part.length > 63) return false;
      if (!/^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(part)) return false;
    }

    // At least one letter must be in the domain name
    if (!/[a-zA-Z]/.test(clean)) return false;

    return true;
  }

  /**
   * Validates an Email address candidate
   */
  static isValidEmail(email: string): boolean {
    if (!email || typeof email !== 'string') return false;
    const clean = email.trim();
    if (clean.length < 5 || clean.length > 254) return false;
    const emailRegex = /^[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,63})$/;
    const match = clean.match(emailRegex);
    if (!match) return false;
    const domain = match[1];
    return this.isValidDomain(domain);
  }

  /**
   * Validates a Hash candidate (MD5, SHA1, SHA256)
   */
  static validateHash(hash: string): { isValid: boolean; type?: string } {
    if (!hash || typeof hash !== 'string') return { isValid: false };
    const clean = hash.trim();

    // Check hex character composition
    if (!/^[a-fA-F0-9]+$/.test(clean)) return { isValid: false };

    // Reject all zeroes or all Fs
    if (/^0+$/.test(clean) || /^f+$/i.test(clean)) return { isValid: false };

    if (clean.length === 32) return { isValid: true, type: 'MD5' };
    if (clean.length === 40) return { isValid: true, type: 'SHA1' };
    if (clean.length === 64) return { isValid: true, type: 'SHA256' };

    return { isValid: false };
  }

  /**
   * Determines if a log line should be skipped for domain/generic IOC extraction
   * because its key indicates non-network metadata (username, hostname-as-label,
   * YARA rule names, filenames, etc.)
   */
  static isNonNetworkMetadataLine(line: string): boolean {
    // Lines whose key clearly indicates they contain non-network text
    if (NON_NETWORK_LINE_KEYS.test(line)) return true;

    // YARA matched string indicators (e.g., $cert_valid, $mz_header)
    if (YARA_STRING_INDICATOR.test(line.trim())) return true;

    return false;
  }

  /**
   * Extracts the longest possible FQDN at each position in a string.
   * The built-in domain regex only captures two-label domains; this helper
   * tries to extend rightward to get armmf.adobe.com instead of armmf.adobe.
   */
  static extractLongestDomainAt(text: string, matchStart: number, twoPartDomain: string): string {
    // Try to extend the match rightward by adding more labels
    const afterMatch = text.substring(matchStart + twoPartDomain.length);
    const extendMatch = afterMatch.match(/^(\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+/);
    if (extendMatch) {
      return twoPartDomain + extendMatch[0];
    }
    return twoPartDomain;
  }

  /**
   * Extracts all unique, validated IOCs from raw text or log lines
   */
  static extractIocsFromText(content: string): AnalysisInputIoc[] {
    if (!content || typeof content !== 'string') return [];

    const lines = content.split(/\r?\n/).map((l) => l.trim()).filter((l) => l.length > 0);
    const iocMap = new Map<string, AnalysisInputIoc>();

    const addIoc = (ioc: AnalysisInputIoc) => {
      const key = `${ioc.type.toUpperCase()}:${ioc.value.trim().toLowerCase()}`;
      if (!iocMap.has(key)) {
        iocMap.set(key, ioc);
      } else {
        // Retain highest confidence
        const existing = iocMap.get(key)!;
        if ((ioc.confidence || 0) > (existing.confidence || 0)) {
          iocMap.set(key, ioc);
        }
      }
    };

    for (const line of lines) {
      // 1. URLs
      const urlMatches = line.match(/(?:https?|ftp):\/\/[^\s"'<>()[\]{}]+/gi);
      if (urlMatches) {
        for (const rawUrl of urlMatches) {
          const validUrl = this.sanitizeAndValidateUrl(rawUrl);
          if (validUrl) {
            const isPayload = /payload|update|\.sh|\.exe|\.bin|\.bat/i.test(validUrl);
            addIoc({
              type: 'URL',
              value: validUrl,
              category: isPayload ? 'Network / Payload URL' : 'Network / Web URL',
              confidence: isPayload ? 95 : 85,
              description: `Extracted URL indicator observed in telemetry`,
            });

            // Extract Host from URL (IP or Domain)
            try {
              const parsed = new URL(validUrl);
              if (parsed.hostname) {
                if (net.isIPv4(parsed.hostname) || net.isIPv6(parsed.hostname)) {
                  if (this.isValidIpv4(parsed.hostname)) {
                    addIoc({
                      type: 'IP',
                      value: parsed.hostname,
                      category: this.isPrivateIpv4(parsed.hostname) ? 'Network / Internal IP' : 'Network / External IP',
                      confidence: isPayload ? 95 : 90,
                      description: `IP address extracted from URL ${validUrl}`,
                    });
                  }
                } else if (this.isValidDomain(parsed.hostname)) {
                  addIoc({
                    type: 'DOMAIN',
                    value: parsed.hostname.toLowerCase(),
                    category: 'Network / Domain Name',
                    confidence: 85,
                    description: `Domain name extracted from URL ${validUrl}`,
                  });
                } else if (/^[a-zA-Z0-9-]{3,63}$/.test(parsed.hostname) && !/^\d+$/.test(parsed.hostname)) {
                  addIoc({
                    type: 'DOMAIN',
                    value: parsed.hostname.toLowerCase(),
                    category: 'Network / Hostname',
                    confidence: 80,
                    description: `Internal/target hostname extracted from URL`,
                  });
                }
              }
            } catch {
              // Ignore URL parse error
            }
          }
        }
      }

      // 2. IP Addresses (IPv4)
      const ipRegex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g;
      let ipMatch: RegExpExecArray | null;
      while ((ipMatch = ipRegex.exec(line)) !== null) {
        const candidateIp = ipMatch[0];
        const matchIndex = ipMatch.index;
        const surroundingContext = line.substring(Math.max(0, matchIndex - 30), matchIndex);

        // Check if preceded by / (e.g. Chrome/129.0.0.0 or path/1.2.3.4)
        const charBefore = matchIndex > 0 ? line[matchIndex - 1] : ' ';
        if (charBefore === '/' || charBefore === '\\') {
          continue; // Part of User-Agent or file path
        }

        if (/agent_version|version|release|build/i.test(surroundingContext) || /"agent_version"\s*:\s*"/i.test(line)) {
          continue; // Skip agent or software version numbers
        }

        if (this.isValidIpv4(candidateIp, surroundingContext)) {
          const isPrivate = this.isPrivateIpv4(candidateIp);
          const isFailedAuth = /failed|invalid|drop|deny|block/i.test(line);
          addIoc({
            type: 'IP',
            value: candidateIp,
            category: isPrivate ? 'Network / Internal IP' : 'Network / External IP',
            confidence: isFailedAuth ? 95 : (isPrivate ? 85 : 90),
            description: isPrivate
              ? `Internal network address identified in log events`
              : isFailedAuth
                ? `External source address observed in security authentication failures or firewall drops`
                : `External IP address observed in network/system activity`,
          });
        }
      }

      // 3. IPv6 Addresses
      const ipv6Regex = /(?:^|[\s=:,([\<])([a-fA-F0-9]{1,4}(?::[a-fA-F0-9]{1,4}){7}|(?:[a-fA-F0-9]{1,4}:){1,7}:|(?:[a-fA-F0-9]{1,4}:){1,6}:[a-fA-F0-9]{1,4})(?:$|[\s/:,;)\]>])/g;
      let ipv6Match: RegExpExecArray | null;
      while ((ipv6Match = ipv6Regex.exec(line)) !== null) {
        const candidateIpv6 = ipv6Match[1];
        if (net.isIPv6(candidateIpv6) && candidateIpv6 !== '::1') {
          addIoc({
            type: 'IP',
            value: candidateIpv6,
            category: 'Network / IPv6 Address',
            confidence: 85,
            description: `IPv6 address observed in telemetry`,
          });
        }
      }

      // 4. Domains (standalone in text, e.g. domain=example.com, cdn-updates.top)
      // Skip lines that are clearly non-network metadata (username, YARA rule, filename, etc.)
      if (!this.isNonNetworkMetadataLine(line)) {
        // Use greedy domain regex that captures multi-label FQDNs
        // Pattern: matches the leftmost full FQDN greedily (e.g., armmf.adobe.com not just armmf.adobe)
        const domainRegex = /\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+)\b/g;
        let domainMatch: RegExpExecArray | null;
        const processedDomainRanges: Array<[number, number]> = [];

        while ((domainMatch = domainRegex.exec(line)) !== null) {
          const candidateDomain = domainMatch[1];
          const matchStart = domainMatch.index;
          const matchEnd = matchStart + candidateDomain.length;

          // Skip if this range overlaps a previously processed longer match
          const overlaps = processedDomainRanges.some(([s, e]) => matchStart >= s && matchStart < e);
          if (overlaps) continue;

          // Avoid words in user agents like AppleWebKit/537.36
          const charBefore = matchStart > 0 ? line[matchStart - 1] : ' ';
          if (charBefore === '/' || charBefore === '@') {
            continue; // Part of User-Agent version or email
          }

          if (this.isValidDomain(candidateDomain)) {
            processedDomainRanges.push([matchStart, matchEnd]);
            addIoc({
              type: 'DOMAIN',
              value: candidateDomain.toLowerCase(),
              category: 'Network / Domain Name',
              confidence: 85,
              description: `Domain name identified in log records`,
            });
          }
        }
      }

      // 5. Emails
      const emailRegex = /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,63}\b/g;
      let emailMatch: RegExpExecArray | null;
      while ((emailMatch = emailRegex.exec(line)) !== null) {
        const candidateEmail = emailMatch[0];
        if (this.isValidEmail(candidateEmail)) {
          addIoc({
            type: 'EMAIL',
            value: candidateEmail.toLowerCase(),
            category: 'Communication / Email',
            confidence: 85,
            description: `Email address observed in telemetry`,
          });
        }
      }

      // 6. Hashes (MD5, SHA1, SHA256)
      // Skip top-level file metadata hash lines (e.g. "MD5: ...", "SHA256: ...) which represent the analyzed file itself
      if (!/^\s*(?:MD5|SHA1|SHA256|SHA-1|SHA-256|SSDEEP)\s*[:=]/i.test(line)) {
        const hashRegex = /\b([a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b/g;
        let hashMatch: RegExpExecArray | null;
        while ((hashMatch = hashRegex.exec(line)) !== null) {
        const candidateHash = hashMatch[1];
        // Ensure not part of UUID (check surrounding hyphens)
        const charBefore = hashMatch.index > 0 ? line[hashMatch.index - 1] : ' ';
        const charAfter = hashMatch.index + candidateHash.length < line.length ? line[hashMatch.index + candidateHash.length] : ' ';
        if (charBefore === '-' || charAfter === '-') {
          continue; // UUID component
        }

        const validHash = this.validateHash(candidateHash);
        if (validHash.isValid) {
          addIoc({
            type: 'HASH',
            value: candidateHash.toLowerCase(),
            category: `Host / File Hash (${validHash.type})`,
            confidence: 90,
            description: `${validHash.type} cryptographic hash observed in security records`,
          });
        }
      }
    }
  }

  return Array.from(iocMap.values());
}
}
