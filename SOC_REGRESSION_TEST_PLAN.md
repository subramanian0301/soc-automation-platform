# SOC Security Platform — Master Regression Test Plan

**Project Location:** `D:\soc 2.0`  
**Date:** October 10, 2026  
**Document Status:** Production Regression Test Specification  

---

## Overview

This document specifies the repeatable regression test plan for the SOC Security Platform. It defines automated unit/integration suites, live end-to-end API scripts, production build checks, and test data requirements to prevent regressions during future development.

---

## Test Execution Commands & Environment Matrix

| Test Suite | Location | Command | Expected Duration | Primary Objective |
|---|---|---|---|---|
| **Backend Automated Tests** | `backend/` | `npm test` | ~23 seconds | Run all 16 Jest test suites (184 tests) |
| **Live API E2E Script** | `d:\soc 2.0\` | `node scripts/verify-phase2-live.js` | ~4 seconds | Verify live backend API endpoints & database persistence |
| **Frontend Production Build** | `frontend/` | `npm run build` | ~15 seconds | Verify Next.js compilation, type checking, and page generation |
| **Prisma Schema Validation** | `backend/` | `npm run prisma:validate` | ~2 seconds | Validate Prisma ORM schema against MySQL |

---

## Repeatable Test Case Specifications

### TC-01: Multi-Format File Ingestion (.json, .csv, .log, .txt)
- **Objective:** Verify that JSON, CSV, and text log files parse cleanly into canonical `AnalysisInput` records.
- **Test Data Requirements:**
  - `test_samples/high_risk_sample.json`
  - `test_samples/low_risk_sample.log`
- **Execution Command:** `npm test -- test/parser.spec.ts`
- **Expected Results:**
  - JSON objects and heterogenous arrays are parsed cleanly.
  - CSV headers match canonical field aliases in `ALIAS_MAPS`.
  - Log section headers (`=== SECTION ===`, `[SECTION]`) break content into correct entity collections.

---

### TC-02: Cryptographic Hash Calculation & Preservation
- **Objective:** Verify that calculated MD5, SHA1, and SHA256 hashes are computed directly from raw uploaded file bytes and stored in `FileMetadata`, without overwriting source-reported hashes.
- **Execution Command:** `node scripts/verify-phase2-live.js` (Step 2 & 3)
- **Expected Results:**
  - `calculatedMd5`, `calculatedSha1`, and `calculatedSha256` in `FileMetadata` match byte calculations.
  - Source-reported hashes in `Hash` model remain untouched.

---

### TC-03: Explicit Zero Risk Score Preservation & Boundary Validation
- **Objective:** Verify `riskScore: 0` is preserved as integer `0` and invalid risk scores (`> 100` or `< 0`) are rejected.
- **Execution Command:** `node scripts/verify-phase2-live.js` (Step 2 & 5)
- **Expected Results:**
  - `riskScore: 0` returns `riskScore = 0` (not `null`).
  - `riskScore: 150` returns `400 Bad Request`.

---

### TC-04: Unparsed Diagnostic Line Capture & Partial Parsing Status
- **Objective:** Verify unmapped telemetry fields or log lines are retained in `unrecognizedFields` and trigger `parsingStatus = "PARTIAL"`.
- **Execution Command:** `node scripts/verify-phase2-live.js` (Step 4)
- **Expected Results:**
  - `parsingStatus` is `"PARTIAL"`.
  - `unrecognizedFields.unparsedLines` contains unmapped diagnostic text.

---

### TC-05: Analysis ID Data Isolation
- **Objective:** Verify that switching between active analyses isolates sub-resource queries and prevents cross-analysis data leaks.
- **Execution Command:** `npm test -- test/phase4-analysis-state.spec.ts`
- **Expected Results:**
  - Querying `/analyses/:id/yara` returns only YARA rules belonging to `:id`.
  - Switching to an analysis with 0 YARA rules returns 0 items without leaking rules from previous selections.

---

### TC-06: Analyst Item Creation & Transactional Persistence
- **Objective:** Verify analyst manual additions (incidents, cases, assets, endpoints, vulnerabilities) persist to MySQL and create `AuditLog` entries.
- **Execution Command:** `npm test -- test/phase7a-incidents-cases.spec.ts`
- **Expected Results:**
  - POST `/analyses/:id/incidents` creates an `Incident` record.
  - An associated `AuditLog` entry is written atomically.

---

### TC-07: SOAR Response Playbooks & Simulation Mode
- **Objective:** Verify analyst SOAR execution defaults to safe dry-run / simulation mode.
- **Execution Command:** `npm test -- test/phase7b-soar.spec.ts`
- **Expected Results:**
  - `SoarExecution` record is created with `status = "SIMULATION"`.
  - `result` contains `"Dry Run Completed (Simulation Mode)"`.

---

### TC-08: PDF & CSV Report Export Generation
- **Objective:** Verify PDF report generation via `pdfkit` and CSV data export endpoints.
- **Execution Command:** `npm test -- test/phase9-reports-analytics.spec.ts`
- **Expected Results:**
  - GET `/analyses/:id/reports/executive/export?format=pdf` returns `Content-Type: application/pdf` buffer.
  - GET `/analyses/:id/reports/executive/export?format=csv` returns `Content-Type: text/csv` string.

---

### TC-09: File Upload Path Traversal Prevention
- **Objective:** Verify malicious filenames (e.g. `../../etc/passwd.log`) are sanitized.
- **Execution Command:** `npm test -- test/phase2-e2e.spec.ts`
- **Expected Results:**
  - Filename is sanitized to `______etc_passwd.log`.
  - File is written strictly inside `d:\soc 2.0\uploads\`.

---

### TC-10: Complete System E2E & Production Build Validation
- **Objective:** Verify full end-to-end integration and Next.js frontend compilation.
- **Execution Commands:**
  1. `cd backend && npm test`
  2. `cd frontend && npm run build`
- **Expected Results:**
  - All 16 backend test suites pass (184/184 tests).
  - Next.js production build succeeds with 0 errors.
