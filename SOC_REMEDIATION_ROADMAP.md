# SOC Security Platform — Prioritized Stabilization & Remediation Roadmap

**Project Location:** `D:\soc 2.0`  
**Date:** October 10, 2026  
**Document Status:** Production Stabilization & Phase-by-Phase Roadmap  

---

## Roadmap Overview & Strategy

This remediation plan establishes a prioritized, evidence-backed strategy for maintaining long-term stability, preventing regression, and expanding enterprise capabilities across the SOC Security Platform codebase. 

Tasks are ordered strictly by dependency and risk level. Shared root causes (parsing engine, transactional database boundaries, global state scoping) take precedence over UI-level adjustments.

---

## Phase 1 — Critical Startup, Data Security & Access Control

### Task 1.1: NestJS Authentication & Access Control Guard
- **Priority:** High / Security
- **Status:** **Completed & Verified**
- **Root Cause:** API endpoints previously lacked JWT authentication guards, allowing unauthenticated network access to read analyses or post analyst notes.
- **Affected Files:**
  - [backend/src/app.module.ts](file:///d:/soc%202.0/backend/src/app.module.ts)
  - [backend/src/auth/jwt-auth.guard.ts](file:///d:/soc%202.0/backend/src/auth/jwt-auth.guard.ts)
  - [backend/src/auth/auth.module.ts](file:///d:/soc%202.0/backend/src/auth/auth.module.ts)
  - [backend/src/auth/auth.service.ts](file:///d:/soc%202.0/backend/src/auth/auth.service.ts)
  - [backend/src/auth/auth.controller.ts](file:///d:/soc%202.0/backend/src/auth/auth.controller.ts)
  - [frontend/lib/api.ts](file:///d:/soc%202.0/frontend/lib/api.ts)
- **Implementation Accomplished:**
  1. Built NestJS JWT authentication module (`AuthModule`, `AuthService`, `AuthController`).
  2. Applied `JwtAuthGuard` globally in `AppModule` using `APP_GUARD`. Protected all sensitive routes with Bearer token validation while keeping public health check (`/api/v1/health`) and demo authentication endpoints decorated with `@Public()`.
  3. Added query string token parameter (`?token=<jwt>`) in `JwtAuthGuard` for secure direct browser report export downloads (PDF & CSV).
  4. Updated `frontend/lib/api.ts` with `authFetch` wrapper to attach `Authorization: Bearer <token>` headers, auto-fetch demo tokens, and handle 401/403 errors gracefully.
  5. Documented database tenant ownership limitation: The Prisma schema (`database/prisma/schema.prisma`) lacks a per-user `userId` column on `Analysis`, so while JWT verifies token authenticity, identity, role, and expiration, resource-level tenant isolation is documented as constrained by the database schema.
- **Verification Evidence:** `phase7-auth.spec.ts` (9/9 tests pass) and `verify-release-readiness.js` (Check 8 passes).

### Task 1.2: Strict Environment Variable Validation & Startup Diagnostics
- **Priority:** High / Reliability
- **Root Cause:** Environment variables (`DATABASE_URL`, `PORT`, `FRONTEND_URL`) could fail silently if improperly formatted in `.env`.
- **Affected Files:**
  - `backend/src/app.module.ts`
  - `backend/src/main.ts`
- **Implementation Approach:**
  1. Add `class-validator` schema validation to `@nestjs/config` ConfigModule.
  2. Implement database pre-flight ping in `main.ts` before starting NestJS HTTP listener.
- **Dependencies:** None.
- **Acceptance Criteria:** Server produces clear error logs and halts startup gracefully if `DATABASE_URL` is missing or unreachable.
- **Regression Tests:** Test startup error handling with missing environment variables.

---

## Phase 2 — Backend, Database & Transaction Boundaries

### Task 2.1: Transactional Integrity for Analyst Mutations
- **Priority:** Medium / Data Integrity
- **Root Cause:** Analyst actions (creating incidents, cases, SOAR playbooks, assets, endpoints, vulnerabilities) currently perform direct single-record inserts without explicit audit logging in the same database transaction.
- **Affected Files:**
  - `backend/src/analysis/analysis.service.ts`
- **Implementation Approach:**
  1. Wrap analyst mutation methods (`createAnalystIncident`, `createAnalystCase`, `createAnalystSoarAction`, `createAnalystAsset`, `createAnalystEndpoint`, `createAnalystVulnerability`) in Prisma `$transaction`.
  2. Atomically create the requested record and insert a corresponding `AuditLog` entry (e.g. `action: "ANALYST_CREATED_INCIDENT"`).
- **Dependencies:** Task 1.1 (for analyst username binding).
- **Acceptance Criteria:** Creating any analyst item atomically writes an audit log record in MySQL.
- **Regression Tests:** `phase7a-incidents-cases.spec.ts`, `phase7b-soar.spec.ts`.

---

## Phase 3 — Upload and Parsing Correctness

### Task 3.1: Streaming Parser for Large File Ingestion (> 50MB)
- **Priority:** Medium / Performance
- **Root Cause:** `UploadService` and `ParserService` load the entire file into buffer memory (`file.buffer.toString('utf-8')`). For massive log files, memory usage spikes.
- **Affected Files:**
  - `backend/src/upload/upload.service.ts`
  - `backend/src/parser/parser.service.ts`
  - `backend/src/parser/parsers/text-log.parser.ts`
  - `backend/src/parser/parsers/csv.parser.ts`
- **Implementation Approach:**
  1. Implement node `readline` / stream-based parsing option for text `.log` and `.csv` files exceeding 10MB.
  2. Process line-by-line regex extractions in chunks.
- **Dependencies:** None.
- **Acceptance Criteria:** Memory overhead remains under 100MB during parsing of 50MB log inputs.
- **Regression Tests:** Test memory benchmark with 50MB sample log.

---

## Phase 4 — Frontend Data Flow & Analysis Isolation

### Task 4.1: URL Query Parameter State Synchronization (`?analysisId=xyz`)
- **Priority:** Low / UX
- **Root Cause:** `currentAnalysisId` is stored in React memory context (`AnalysisContext.tsx`). Reloading the page or sharing a deep link resets the selected analysis to `null`.
- **Affected Files:**
  - `frontend/context/AnalysisContext.tsx`
  - `frontend/app/page.tsx`
  - `frontend/components/Navbar.tsx`
- **Implementation Approach:**
  1. Sync `currentAnalysisId` with Next.js router query parameter `?analysisId=...`.
  2. On page load, read `analysisId` from URL query parameter and initialize `AnalysisContext`.
- **Dependencies:** None.
- **Acceptance Criteria:** Refreshing browser page preserves active analysis selection.
- **Regression Tests:** Verify state hydration from URL query string.

---

## Phase 5 — Continuous QA & Automated Regression Strategy

### Task 5.1: Automated CI/CD Regression Pipeline
- **Priority:** High / Maintenance
- **Implementation Approach:**
  1. Add GitHub Actions workflow `.github/workflows/ci.yml`.
  2. Automated steps:
     - Start MySQL service container (`mysql:8.0`).
     - Run `prisma migrate dev` on database schema.
     - Execute `npm test` in `backend` (184 unit & integration tests).
     - Execute `npm run build` in `frontend` (Next.js compilation & linting).
- **Acceptance Criteria:** Pull requests are automatically validated against full test suite and build verification.

---

## Task Verification & Acceptance Matrix

| Phase | Task ID | Feature / System Target | Target Acceptance Criteria | Verification Tool / Command |
|---|---|---|---|---|
| 1 | Task 1.1 | Auth & Access Control | JWT header validation on `/api/v1/analyses/*` | `npm test -- test/auth.spec.ts` |
| 1 | Task 1.2 | Env Validation | Startup fails fast with actionable log on missing `DATABASE_URL` | `npm run start:dev` in backend |
| 2 | Task 2.1 | Analyst Transaction | Atomic DB transaction for analyst items & audit log | `npm test -- test/phase7a-incidents-cases.spec.ts` |
| 3 | Task 3.1 | Streaming Parser | Stream large log files (> 10MB) with low RAM footprint | `npm test -- test/parser.spec.ts` |
| 4 | Task 4.1 | URL State Sync | Active analysis persisted in URL `?analysisId=...` | Playwright / manual browser check |
| 5 | Task 5.1 | Continuous Integration | Zero regression on pull requests via GitHub Actions | GitHub Actions workflow execution |
