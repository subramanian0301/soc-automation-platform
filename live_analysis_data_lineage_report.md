# Live Analysis Data-Lineage Investigation & Resolution Report

**Project**: SOC Security Platform (`d:\soc 2.0`)  
**Target Analysis ID**: `analysis_318529bd4c544091`  
**File Name**: `high_risk_sample.log`  
**Upload Timestamp**: `2026-10-09T14:07:23.000Z`  
**Database**: MySQL (`soc_platform`) via Prisma ORM  

---

## 1. Executive Summary

A comprehensive data-lineage investigation was conducted on live analysis `analysis_318529bd4c544091` (`high_risk_sample.log`). The initial investigation revealed systemic data suppression across multiple dashboard modules:
- **Risk Score** and **Threat Level** rendered as `Not Available`.
- **YARA Rules**, **VirusTotal Intelligence**, **IOC Summary**, **Behavior Events**, **Sandbox Results**, and **SIEM Summary** rendered as `Parsing Incomplete`, despite valid security indicators being present in the raw uploaded log file.

By executing an end-to-end data lineage trace across all six pipeline stages (Stage A: Raw File → Stage B: Parser → Stage C: Normalizer → Stage D: DB Persistence → Stage E: REST API → Stage F: Frontend Selectors), four primary root causes were identified and fixed at the shared architectural layer without altering test fixtures or hardcoding logic.

All fixes were verified through:
1. **Backend Unit & Integration Test Suite**: 16/16 Test Suites Passed (184/184 tests passed).
2. **Frontend Production Build**: Clean compilation with Next.js (`npm run build`).
3. **Live REST API Endpoint Verification**: Verified `GET /api/v1/analysis/analysis_318529bd4c544091` live responses.
4. **Browser UI State Verification**: Verified 100% UI module state alignment with API data.

---

## 2. Pipeline Evidence Tracing (Stages A through F)

### Stage A: Raw Uploaded Log File (`high_risk_sample.log`)
- **Inspection**: The uploaded log file contained distinct text blocks delimited by double equals divider lines (`===================\n=== SECTION TITLE ===\n===================`), key-value metadata pairs, YARA rule blocks, VT detection ratios (`54/70`), network indicators (IPs, C2 domains), process execution trees, and SIEM event streams.
- **Evidence**:
  ```text
  =========================================
  === SUMMARY ANALYSIS REPORT ===
  =========================================
  Target File: high_risk_sample.exe
  Risk Score: 98
  Threat Level: CRITICAL
  ...
  =========================================
  === YARA RULES ===
  =========================================
  Matched Rule: APT_MALWARE_GENERIC
  ...
  =========================================
  === VIRUSTOTAL SIMULATED ===
  =========================================
  Detection Ratio: 54/70
  ```

### Stage B: Text Log Parser (`backend/src/parser/parsers/text-log.parser.ts`)
- **Bug Identified**: The block header line detection matched any line with `===` or `---` dividers and immediately toggled `expectingSectionTitle = true`. Consequently, when the actual section title line was enclosed by top and bottom dividers, the bottom divider (or the very first key-value content line) was consumed as the section title, wiping out the initial data key (`Risk Score`, `Matched Rule`, `Detection Ratio`).
- **Section Alias Gaps**: Normalized section headers like `virustotalsimulated`, `networkindicators`, `behavioranalysis` were missing from `SECTION_ALIASES` in `alias-registry.ts`.
- **Key Alias Gaps**: Key normalizations such as `riskscore`, `threatlevel`, `detectionratio`, `matchedrule`, and `nodehost` failed lookup in exact match dictionaries.

### Stage C: Log Data Normalizer (`backend/src/parser/normalizer.service.ts`)
- **Bug Identified**: Because Stage B dropped the initial keys, the normalizer received empty structures (`{}`) for risk metrics and empty arrays (`[]`) for YARA, VT, IOCs, Behavior, and SIEM modules.
- **Fallback Logic**: When `riskScore` was unparsed, `threatLevel` derived as `null` or `UNKNOWN`.

### Stage D: Database Persistence (`prisma.analysis.update`)
- **Bug Identified**: The persisted MySQL database record for `analysis_318529bd4c544091` held:
  - `riskScore`: `null`
  - `threatLevel`: `null`
  - `yaraRules`: `[]`
  - `virusTotal`: `null`
  - `iocs`: `[]`
  - `behaviorEvents`: `[]`
  - `sandboxResults`: `null`
  - `siemSummary`: `null`

### Stage E: REST API Layer (`GET /api/v1/analysis/:id`)
- **Bug Identified**: The API accurately served the database state, returning `riskScore: null`, `threatLevel: null`, `parsingStatus: "PARTIAL"`, and empty arrays/nulls for structured fields.

### Stage F: Frontend State Selectors (`frontend/lib/moduleState.ts`)
- **Bug Identified**: `getModuleState(...)` evaluated global `parsingStatus === "PARTIAL"` *before* checking section explicit presence (`isExplicitlyProvided`). As a result:
  - Modules with 0 items (such as optional absent sections like `sandboxResults`) were forcibly overridden to `PARSING_INCOMPLETE` instead of `NOT_PROVIDED` or `CONFIRMED_EMPTY`.

---

## 3. Complete Field-Level Loss & Mismatch Matrix

| Module / Field | Initial UI State | Database State | Parser / Normalizer Root Cause | Shared-Layer Fix Applied | Final UI State | Final API / DB State |
|---|---|---|---|---|---|---|
| **Risk Score** | Not Available | `null` | Header divider matcher wiped out `Risk Score: 98` key-value line | Refactored divider block header parser & added `riskscore` key alias | `98 / 100` | `98` |
| **Threat Level** | Not Available | `null` | Normalizer received null risk score and missed `CRITICAL` string | Added `threatlevel` key alias & normalized threat derivation | `CRITICAL` | `"CRITICAL"` |
| **YARA Rules** | Parsing Incomplete | `[]` | Double header divider skipped `Matched Rule: ...` line | Parser extracts rule blocks, names, tags, & meta | `Available` (1 Rule) | `[{ ruleName: "APT_MALWARE_GENERIC", ... }]` |
| **VirusTotal** | Parsing Incomplete | `null` | Section title `VIRUSTOTAL SIMULATED` unmapped | Added `virustotalsimulated` section alias & `54/70` ratio matcher | `Available` (54/70) | `{ detectionRatio: "54/70", positives: 54, total: 70 }` |
| **IOC Summary** | Parsing Incomplete | `[]` | Multi-line key-value parsing failed for network indicators | Parsed IP, Domain, and File Hash lists into structured IOCs | `Available` (4 IOCs) | `[{ type: "IP", value: "192.168.1.105" }, ...]` (4 IOCs) |
| **MITRE ATT&CK**| `Available` (5 items) | 5 items | Unaffected (parsed cleanly) | Preserved schema contract | `Available` (5 items) | 5 Technique objects |
| **Behavior Events**| Parsing Incomplete | `[]` | Section title `BEHAVIOR ANALYSIS` unmapped | Added `behavioranalysis` section alias & process event parser | `Available` (3 Events)| `[{ eventType: "PROCESS_CREATE", ... }]` (3 Events) |
| **Sandbox Results**| Parsing Incomplete | `null` | Optional section absent in log file; selector forced `PARSING_INCOMPLETE` | Updated `moduleState.ts` to check `isExplicitlyProvided` first | `Not Provided` | `null` |
| **SIEM Summary** | Parsing Incomplete | `null` | Header divider skipped SIEM lines; selector forced incomplete state | Extracted SIEM logs in `TextLogParser` & fixed state selector | `Available` (3 Logs) | `[{ eventId: "4624", ... }]` (3 Logs) |

---

## 4. Code Modifications

### 1. `backend/src/parser/parsers/text-log.parser.ts`
- Replaced primitive single-line divider toggling with a triple-line block header matcher (`Divider -> Title Line -> Divider`).
- Added robust key-value extraction supporting multi-word keys and colon-separated values (`Risk Score: 98`).
- Implemented dedicated extractors for YARA rules, VirusTotal ratios (`54/70`), network IOCs, process behavior events, and SIEM logs.

### 2. `backend/src/parser/alias-registry.ts`
- Expanded `SECTION_ALIASES` to include `virustotalsimulated`, `networkindicators`, `behavioranalysis`, `siemevents`, and `yara`.
- Expanded `ALIAS_MAPS` for key normalization:
  - `metadata.hostname`: Added `'nodehost'`, `'node_host'`.
  - `risk.riskScore`: Added `'riskscore'`, `'risk_score'`, `'score'`.
  - `risk.threatLevel`: Added `'threatlevel'`, `'threat_level'`.
  - `virusTotal.positives`: Added `'detectionratio'`, `'detection_ratio'`.

### 3. `frontend/lib/moduleState.ts`
- Refactored `getModuleState` logic:
  1. Checks if section data was explicitly provided (`isExplicitlyProvided`).
  2. If absent and not provided, returns `NOT_PROVIDED`.
  3. If provided but empty, returns `CONFIRMED_EMPTY`.
  4. Only returns `PARSING_INCOMPLETE` if section parsing explicitly threw errors or experienced partial chunk truncations.

---

## 5. Empirical Verification Results

### A. Backend Jest Test Suite
Executed `npm run test` across all backend suites:
```text
Test Suites: 16 passed, 16 total
Tests:       184 passed, 184 total
Snapshots:   0 total
Time:        24.331 s
```
All 16 suites (including `parser.spec.ts`, `phase2-e2e.spec.ts`, `phase5-dashboard.spec.ts`, `unseen-e2e-validation.spec.ts`, `data-consistency-audit.spec.ts`, and `phase10-final-integration.spec.ts`) passed cleanly.

### B. Frontend Production Build
Executed `npm run build` in `frontend/`:
```text
✓ Compiled successfully
  Linting and checking validity of types ...
✓ Generating static pages (4/4)
```

### C. Live REST API Verification (`node scripts/verify-phase2-live.js`)
Targeting live analysis `analysis_318529bd4c544091`:
- `GET /api/v1/analysis/analysis_318529bd4c544091`:
  - `riskScore`: `98`
  - `threatLevel`: `"CRITICAL"`
  - `yaraRules`: 1 rule (`APT_MALWARE_GENERIC`)
  - `virusTotal`: `{ positives: 54, total: 70, detectionRatio: "54/70" }`
  - `iocs`: 4 items
  - `behaviorEvents`: 3 items
  - `siemSummary`: 3 logs
  - `sandboxResults`: `null`

### D. Browser UI Alignment
Verification via Headless Browser on `http://localhost:3000`:
- **Overview Card**: Risk Score `98 / 100`, Threat Level badge `CRITICAL`.
- **YARA Card**: State `Available`, rendering rule `APT_MALWARE_GENERIC`.
- **VirusTotal Card**: State `Available`, rendering `54 / 70`.
- **IOC Card**: State `Available`, rendering 4 items (IPs, Domain, Hashes).
- **Behavior Card**: State `Available`, rendering 3 process events.
- **Sandbox Card**: State `Not Provided` (gray badge), accurately indicating absence in raw log without reporting parsing failure.
- **SIEM Card**: State `Available`, rendering 3 event logs.

---

## 6. Remaining Limitations & Edge Cases

1. **Non-Standard Vendor Log Formats**: Custom proprietary text logs without colons (`:`) or standard section headers will rely on fuzzy key matching. If un-aliased keys are used, the system will fall back to `NOT_PROVIDED` or `CONFIRMED_EMPTY` without crashing or falsely flagging `PARSING_INCOMPLETE`.
2. **Binary File Artifacts**: For binary samples without text headers, parsing relies on secondary modules (PE parser / ELF parser). Text log section alias rules do not interfere with binary parsers.

---
*Report generated automatically following end-to-end data lineage investigation and verification.*
