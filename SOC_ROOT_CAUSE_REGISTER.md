# SOC Security Platform — Master Root Cause Register

**Project Location:** `D:\soc 2.0`  
**Date:** October 10, 2026  
**Document Status:** Production Baseline & Stabilization Register  

---

## Overview

This Root Cause Register documents all identified defects, runtime errors, data integrity failures, and architectural weaknesses across the SOC Security Platform. Each entry details the reproduction steps, root cause analysis, affected components, resolution applied, and regression test verification.

---

## Defect Summary Table

| Defect ID | Defect Title | Severity | Affected Component | Status | Verification Test |
|---|---|---|---|---|---|
| **DEFECT-01** | `Cannot read properties of undefined (reading 'toUpperCase')` in Normalizer | **Critical** | `AnalysisNormalizer` | **Repaired & Verified** | `parser.spec.ts` |
| **DEFECT-02** | Silent Destruction of Unmapped Telemetry & Missing Provenance | **High** | `AnalysisNormalizer`, `JsonParser`, `TextLogParser` | **Repaired & Verified** | `data-consistency-audit.spec.ts` |
| **DEFECT-03** | Derived Threat Level Overwriting Explicit Source Threat Level | **High** | `AnalysisNormalizer` | **Repaired & Verified** | `phase3-realdata.spec.ts` |
| **DEFECT-04** | Cross-Analysis Data Leakage & Stale React Query Caching | **High** | `AnalysisContext`, `Dashboard.tsx`, `SiemView.tsx` | **Repaired & Verified** | `phase4-analysis-state.spec.ts` |
| **DEFECT-05** | Loss of Explicit Zero Risk Scores (`riskScore = 0`) | **Medium** | `AnalysisNormalizer`, `CsvParser`, `JsonParser` | **Repaired & Verified** | `verify-phase2-live.js` |
| **DEFECT-06** | Single-Record Inserter Without Atomic Audit Logging | **Medium** | `AnalysisService` | **Repaired & Verified** | `phase7a-incidents-cases.spec.ts` |
| **DEFECT-07** | Path Traversal & Unsanitized File Names in File Storage | **High** | `UploadService` | **Repaired & Verified** | `phase2-e2e.spec.ts` |
| **DEFECT-08** | Ambiguous Empty States vs Clean Source Verification | **Medium** | `moduleState.ts`, All Module Views | **Repaired & Verified** | `phase5-dashboard.spec.ts` |
| **DEFECT-09** | Missing JWT Authentication Guards & Identity Verification | **High** | `AppModule`, `JwtAuthGuard`, `AuthModule`, `api.ts` | **Repaired & Verified** | `phase7-auth.spec.ts` |

---

## Detailed Root Cause Analysis Entries

### DEFECT-01: `Cannot read properties of undefined (reading 'toUpperCase')`
- **Severity:** Critical
- **Affected File:** [backend/src/parser/normalizer/analysis.normalizer.ts](file:///d:/soc%202.0/backend/src/parser/normalizer/analysis.normalizer.ts#L8-L25)
- **Reproduction Steps:**
  1. Upload a security log file containing `threatLevel: undefined` or a numeric risk score without an explicit threat level string.
  2. The parser passes `undefined` to `normalizeThreatLevel()`.
  3. Attempting to execute `value.toUpperCase()` on `undefined` throws an unhandled `TypeError`.
- **Root Cause:** Missing nullish check before calling string methods on optional threat level fields.
- **Fix Applied:**
  ```typescript
  normalizeThreatLevel(value: any, riskScore?: number | null): ThreatLevel | null {
    if (value && typeof value === 'string') {
      const clean = value.trim().toUpperCase();
      if (clean === 'LOW') return ThreatLevel.LOW;
      if (clean === 'MEDIUM') return ThreatLevel.MEDIUM;
      if (clean === 'HIGH') return ThreatLevel.HIGH;
      if (clean === 'CRITICAL') return ThreatLevel.CRITICAL;
    }
    // Fallback derivation based on validated riskScore
    if (riskScore !== undefined && riskScore !== null) {
      if (riskScore >= 90) return ThreatLevel.CRITICAL;
      if (riskScore >= 70) return ThreatLevel.HIGH;
      if (riskScore >= 30) return ThreatLevel.MEDIUM;
      return ThreatLevel.LOW;
    }
    return null;
  }
  ```
- **Regression Test:** Verified in `parser.spec.ts` and `verify-phase2-live.js` (Fixture B).

---

### DEFECT-02: Silent Destruction of Unmapped Telemetry & Missing Provenance
- **Severity:** High
- **Affected Files:**
  - [backend/src/parser/normalizer/analysis.normalizer.ts](file:///d:/soc%202.0/backend/src/parser/normalizer/analysis.normalizer.ts#L298-L322)
  - [backend/src/parser/parsers/json.parser.ts](file:///d:/soc%202.0/backend/src/parser/parsers/json.parser.ts#L198-L214)
  - [backend/src/parser/parsers/text-log.parser.ts](file:///d:/soc%202.0/backend/src/parser/parsers/text-log.parser.ts#L479-L483)
  - [database/prisma/schema.prisma](file:///d:/soc%202.0/database/prisma/schema.prisma#L58-L61)
- **Reproduction Steps:**
  1. Upload a JSON document containing custom telemetry fields (e.g. `compliance_pass: true`) or a text log with diagnostic lines.
  2. Inspect the database record and API response.
  3. Unmapped fields were previously silently discarded.
- **Root Cause:** Schema lacked dedicated JSON columns for unmapped source telemetry and line parsing warnings.
- **Fix Applied:** Added `unrecognizedFields` (Json) and `parsingWarnings` (Json) columns to `Analysis` model in Prisma. Parsers collect unmapped top-level keys and unparsed log lines, storing them under `unrecognizedFields` while flagging `parsingStatus` as `PARTIAL`.
- **Regression Test:** Verified in `data-consistency-audit.spec.ts` and `verify-phase2-live.js` (Fixture C).

---

### DEFECT-03: Derived Threat Level Overwriting Explicit Source Threat Level
- **Severity:** High
- **Affected File:** [backend/src/parser/normalizer/analysis.normalizer.ts](file:///d:/soc%202.0/backend/src/parser/normalizer/analysis.normalizer.ts#L8-L25)
- **Reproduction Steps:**
  1. Upload a file specifying `threatLevel: "LOW"` and `riskScore: 95`.
  2. Pre-fix normalizer recalculated `threatLevel` based on `riskScore >= 90`, overwriting the source-provided `"LOW"` with `"CRITICAL"`.
- **Root Cause:** Normalizer prioritized score thresholds over source truthfulness.
- **Fix Applied:** Updated `normalizeThreatLevel` to check and validate string inputs first. Derived threat levels are calculated only when the source document omits an explicit threat level.
- **Regression Test:** Verified in `phase3-realdata.spec.ts`.

---

### DEFECT-04: Cross-Analysis Data Leakage & Stale React Query Caching
- **Severity:** High
- **Affected Files:**
  - [frontend/context/AnalysisContext.tsx](file:///d:/soc%202.0/frontend/context/AnalysisContext.tsx)
  - [frontend/components/Dashboard.tsx](file:///d:/soc%202.0/frontend/components/Dashboard.tsx#L72)
  - [frontend/lib/api.ts](file:///d:/soc%202.0/frontend/lib/api.ts)
- **Reproduction Steps:**
  1. Select Analysis A containing 5 YARA rules.
  2. Switch to Analysis B containing 0 YARA rules.
  3. UI previously retained Analysis A's YARA rules due to global React Query cache keys lacking `analysisId`.
- **Root Cause:** React Query hooks used static keys (e.g., `['yara']`) rather than analysis-scoped keys (`['analysis', currentAnalysisId, 'yara']`).
- **Fix Applied:** Scoped all frontend query keys by `currentAnalysisId`. When `currentAnalysisId` changes or is cleared, React Query refetches or invalidates module views cleanly.
- **Regression Test:** Verified in `phase4-analysis-state.spec.ts` and live script `verify-phase2-live.js` (Step 7).

---

### DEFECT-05: Loss of Explicit Zero Risk Scores (`riskScore = 0`)
- **Severity:** Medium
- **Affected Files:**
  - [backend/src/parser/normalizer/analysis.normalizer.ts](file:///d:/soc%202.0/backend/src/parser/normalizer/analysis.normalizer.ts#L40-L60)
  - [backend/src/parser/parsers/csv.parser.ts](file:///d:/soc%202.0/backend/src/parser/parsers/csv.parser.ts#L137-L143)
- **Reproduction Steps:**
  1. Upload a log or JSON with `riskScore: 0`.
  2. Pre-fix falsy check `if (riskScore)` evaluated `0` as `false` and replaced it with `null`.
- **Root Cause:** Imperfect falsy checks (`if (!val)`) treated numeric `0` identically to `null` / `undefined`.
- **Fix Applied:** Updated normalizers to check `if (value !== undefined && value !== null)` explicitly. Validated score range `[0, 100]` throwing `BadRequestException` (400) for scores outside range (e.g. `150`).
- **Regression Test:** Verified in `verify-phase2-live.js` (Fixture A & Step 5).

---

### DEFECT-06: Single-Record Inserter Without Atomic Audit Logging
- **Severity:** Medium
- **Affected File:** [backend/src/analysis/analysis.service.ts](file:///d:/soc%202.0/backend/src/analysis/analysis.service.ts#L72-L287)
- **Reproduction Steps:**
  1. Perform file upload resulting in partial child record insert failure.
  2. Orphaned `Analysis` parent records remained in MySQL.
- **Root Cause:** Absence of database transaction wrappers on upload ingestion.
- **Fix Applied:** Wrapped `processUpload` database operations in `this.prisma.$transaction(async (tx) => { ... })`, guaranteeing atomic all-or-nothing database persistence.
- **Regression Test:** Verified in `phase2-e2e.spec.ts` and `phase10-final-integration.spec.ts`.

---

### DEFECT-07: Path Traversal & Unsanitized File Names in File Storage
- **Severity:** High
- **Affected File:** [backend/src/upload/upload.service.ts](file:///d:/soc%202.0/backend/src/upload/upload.service.ts#L45-L47)
- **Reproduction Steps:**
  1. Upload a file named `../../etc/passwd.log`.
  2. Direct string concatenation could write outside the designated upload directory.
- **Root Cause:** Lack of path sanitization on `file.originalname`.
- **Fix Applied:**
  ```typescript
  const rawName = path.basename(file.originalname);
  const sanitizedOriginalName = rawName.replace(/[^a-zA-Z0-9._-]/g, '_');
  ```
- **Regression Test:** Verified in `phase2-e2e.spec.ts`.

---

### DEFECT-08: Ambiguous Empty States vs Clean Source Verification
- **Severity:** Medium
- **Affected Files:**
  - [frontend/lib/moduleState.ts](file:///d:/soc%202.0/frontend/lib/moduleState.ts#L20-L100)
  - Module views in `frontend/components/*.tsx`
- **Reproduction Steps:**
  1. Upload a file that explicitly provided a YARA section with 0 matches.
  2. Pre-fix UI displayed a generic `"No data available"` banner, making analysts question if parsing failed.
- **Root Cause:** Lack of state machine logic consuming source provenance (`providedSections`).
- **Fix Applied:** Created `getModuleState()` in `moduleState.ts`. The UI now displays explicit, truthful badges:
  - `AVAILABLE`: `${count} items`
  - `CONFIRMED_EMPTY`: `0 items (Clean)`
  - `NOT_PROVIDED`: `Not Provided`
  - `PARSING_INCOMPLETE`: `Parsing Incomplete`
- **Regression Test:** Verified in `phase5-dashboard.spec.ts`.

---

### DEFECT-09: Missing JWT Authentication Guards & Identity Verification
- **Severity:** High
- **Affected Files:**
  - [backend/src/app.module.ts](file:///d:/soc%202.0/backend/src/app.module.ts)
  - [backend/src/auth/jwt-auth.guard.ts](file:///d:/soc%202.0/backend/src/auth/jwt-auth.guard.ts)
  - [backend/src/auth/auth.module.ts](file:///d:/soc%202.0/backend/src/auth/auth.module.ts)
  - [backend/src/auth/auth.service.ts](file:///d:/soc%202.0/backend/src/auth/auth.service.ts)
  - [backend/src/auth/auth.controller.ts](file:///d:/soc%202.0/backend/src/auth/auth.controller.ts)
  - [frontend/lib/api.ts](file:///d:/soc%202.0/frontend/lib/api.ts)
- **Reproduction Steps:**
  1. Make an unauthenticated HTTP request to `/api/v1/analyses`, `/api/v1/analyses/upload`, `/api/v1/analytics/enterprise`, or `/api/v1/analyses/:id/reports/*` without an `Authorization` header.
  2. The pre-fix backend allowed access to all routes without verifying user credentials or token signatures.
- **Root Cause:** Absence of NestJS authentication module, JWT service, and global guard.
- **Fix Applied:**
  1. Created `AuthModule`, `AuthService`, `AuthController`, `JwtAuthGuard`, and `@Public()` decorator in `backend/src/auth/`.
  2. Applied `JwtAuthGuard` globally in `AppModule` using `APP_GUARD`.
  3. Enforced `Authorization: Bearer <jwt_token>` verification for all sensitive routes. Marked `/api/v1/health` and demo authentication routes (`/api/v1/auth/login`, `/api/v1/auth/demo-token`) with `@Public()`.
  4. Added query parameter token support (`?token=<jwt>`) in `JwtAuthGuard` for direct browser report export downloads (PDF & CSV).
  5. Updated `frontend/lib/api.ts` with `authFetch` wrapper to attach `Authorization` headers, obtain demo tokens automatically, and clear tokens on 401/403 responses without infinite loops.
  6. Documented database tenant ownership limitation: The Prisma schema (`database/prisma/schema.prisma`) lacks a `userId` column on `Analysis`, so while JWT verifies token authenticity, identity, role, and expiration, resource-level tenant isolation is documented as constrained by the database schema.
- **Regression Test:** Verified in `backend/test/phase7-auth.spec.ts` (9/9 tests pass) and `scripts/verify-release-readiness.js` (Check 8 passes).

