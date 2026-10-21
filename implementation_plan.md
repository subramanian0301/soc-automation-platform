# SOC Security Platform (Greenfield Architecture) Implementation Plan

## Executive Summary
This document outlines the architecture, database schema, API specification, parser pipeline, frontend state management, and phased development plan for building a clean, enterprise-grade SOC Security Platform from scratch. 

The design strictly eliminates cross-sample data contamination, dual backend data paths, mock data fallbacks, and unauthorized silent generation of security entities.

---

## 1. Final Architecture

```
                                  +-----------------------+
                                  |    Browser Client     |
                                  +-----------+-----------+
                                              |
                                              | HTTP / REST API (Port 4000)
                                              v
                                  +-----------------------+
                                  |   Next.js Frontend    |
                                  | (React + TanStack Q)  |
                                  +-----------+-----------+
                                              |
                                              | REST API requests only (/api/v1/...)
                                              v
                                  +-----------------------+
                                  |    NestJS Backend     |
                                  |    (Single Source)    |
                                  +-----+-----+-----+-----+
                                        |     |     |
            +---------------------------+     |     +--------------------------+
            |                                 |                                |
            v                                 v                                v
+-----------------------+         +-----------------------+        +-----------------------+
|    Upload Storage     |         |   Parser Engine       |        |      Prisma ORM       |
|  (local /uploads)     |         | (Log, JSON, CSV)      |        +-----------+-----------+
+-----------------------+         +-----------------------+                    |
                                                                               v
                                                                   +-----------------------+
                                                                   |     MySQL Database    |
                                                                   |  (Single DB Schema)   |
                                                                   +-----------------------+
```

### Core Architecture Rules:
1. **Single Backend:** All data processing, parsing, storage, and retrieval happens exclusively in NestJS (`/api/v1`). Next.js serves purely as a UI layer (App Router UI components) with **NO** API routes handling data logic or database interactions.
2. **Single Database:** MySQL database accessed via Prisma ORM. No JSON database files (`soc_db.json`), local state files, or secondary DBs.
3. **Source of Truth Priority:** Values present in uploaded source files are stored and served verbatim without recalculation. Missing values return `"Not Available"`.
4. **Strict Isolation by `analysisId`:** Every upload creates one `Analysis` record with a unique UUID (`analysisId`). All child security records have `analysisId` as a foreign key with database-level indexes.

---

## 2. Folder Structure

The project will be organized in a monorepo structure in `d:\soc 2.0`:

```
soc-platform/
├── frontend/                     # Next.js 14 (App Router)
│   ├── app/                      # Next.js App Router pages
│   │   ├── layout.tsx            # Root layout with QueryClient & AnalysisProvider
│   │   ├── page.tsx              # Dashboard page
│   │   ├── upload/               # File upload page
│   │   ├── analysis/             # File Analysis detailed page
│   │   ├── siem/                 # SIEM Events page
│   │   ├── threat-intel/         # Threat Intelligence page
│   │   ├── ioc/                  # IOC Search page
│   │   ├── incidents/            # Incidents Management page
│   │   ├── cases/                # Case Management page
│   │   ├── soar/                 # SOAR Execution page
│   │   ├── assets/               # Assets & Endpoints page
│   │   ├── vulnerabilities/      # Vulnerability Assessment page
│   │   ├── reports/              # Report Generator page
│   │   └── analytics/            # Enterprise & Sample Analytics page
│   ├── components/               # UI components (Header, Sidebar, Cards, Tables, Badges)
│   │   ├── common/               # Reusable UI primitives (Button, Modal, Loader, EmptyState)
│   │   ├── layout/               # TopBar, Navigation Sidebar, ActiveSampleSelector
│   │   └── modules/              # Module-specific UI components
│   ├── context/                  # React Contexts
│   │   └── AnalysisContext.tsx   # Central currentAnalysisId state store
│   ├── features/                 # TanStack Query custom hooks per domain
│   │   ├── useAnalysis.ts
│   │   ├── useSiem.ts
│   │   ├── useIoc.ts
│   │   └── ...
│   ├── lib/                      # API client configuration (Axios/fetch wrappers)
│   │   └── api-client.ts
│   └── types/                    # Shared TypeScript interfaces for frontend
│       └── api.ts
│
├── backend/                      # NestJS REST API Server
│   ├── src/
│   │   ├── main.ts               # Entrypoint (Port 4000, CORS, ValidationPipe)
│   │   ├── app.module.ts         # Root Module
│   │   ├── common/               # Interceptors, Filters, Pipes, Constants
│   │   │   ├── filters/          # Global Exception Filter
│   │   │   ├── interceptors/     # Transform & Logging Interceptors
│   │   │   └── dto/              # Pagination & Standard Response DTOs
│   │   ├── prisma/               # Prisma Service & Module
│   │   │   ├── prisma.service.ts
│   │   │   └── prisma.module.ts
│   │   ├── health/               # Health Check Module (/api/v1/health)
│   │   ├── upload/               # Upload Module (File interceptor, storage handling)
│   │   ├── parser/               # Multi-Format Parser Engine
│   │   │   ├── parser.service.ts # Delegation orchestrator
│   │   │   ├── parsers/          # TextLogParser, JsonParser, CsvParser
│   │   │   ├── normalizer/       # Input normalizer to AnalysisInput
│   │   │   └── interfaces/       # Parser Strategy interface
│   │   ├── analysis/             # Core Analysis Module & Services
│   │   │   ├── analysis.controller.ts
│   │   │   ├── analysis.service.ts
│   │   │   └── dto/
│   │   ├── siem/                 # SIEM Module
│   │   ├── threat-intelligence/  # Threat Intel Module
│   │   ├── ioc/                  # IOC Module
│   │   ├── incidents/            # Incidents Module
│   │   ├── cases/                # Cases Module
│   │   ├── soar/                 # SOAR Module
│   │   ├── assets/               # Assets & Endpoints Module
│   │   ├── vulnerabilities/      # Vulnerability Module
│   │   ├── reports/              # Reports Module
│   │   └── analytics/            # Analytics Module
│   └── test/                     # E2E & Integration Tests
│
├── database/                     # Database Schema & Seed Assets
│   ├── prisma/
│   │   └── schema.prisma         # Single authoritative Prisma Schema
│   └── seed/                     # Development seed data (clearly separated)
│       └── seed.ts
│
├── uploads/                      # Local file storage for uploaded source files
├── docker-compose.yml            # Docker setup for MySQL 8.0 & NestJS/Next.js
├── README.md                     # Complete Setup & Architecture Guide
└── .env.example                  # Environment Variables template
```

---

## 3. Database ER Model

```
+-----------------------------------------------------------------------------------+
|                                     ANALYSIS                                      |
+-----------------------------------------------------------------------------------+
| id (PK) | analysisId (UQ, IDX) | fileName | fileSize | fileType | riskScore | ...   |
+-----------------------------------------+-----------------------------------------+
                                          |
        +---------------------------------+---------------------------------+
        | 1                               | 1                               | 1
        v                                 v                                 v
+---------------+                 +---------------+                 +---------------+
| FILE_METADATA |                 |     HASH      |                 | FILE_PROPERTY |
+---------------+                 +---------------+                 +---------------+
| analysisId FK |                 | analysisId FK |                 | analysisId FK |
+---------------+                 +---------------+                 +---------------+
        | 1                               | 1                               | 1
        v                                 v                                 v
+---------------+                 +---------------+                 +---------------+
|  YARA_RESULT  |                 |  VT_RESULT    |                 |   IOC_ITEM    |
+---------------+                 +---------------+                 +---------------+
| analysisId FK |                 | analysisId FK |                 | analysisId FK |
+---------------+                 +---------------+                 +---------------+
        | 1                               | 1                               | 1
        v                                 v                                 v
+------------------+              +------------------+              +------------------+
| MITRE_TECHNIQUE  |              |  BEHAVIOR_EVENT  |              |  SANDBOX_RESULT  |
+------------------+              +------------------+              +------------------+
| analysisId FK    |              | analysisId FK    |              | analysisId FK    |
+------------------+              +------------------+              +------------------+
        | 1                               | 1                               | 1
        v                                 v                                 v
+------------------+              +------------------+              +------------------+
|    SIEM_EVENT    |              |     INCIDENT     |              |       CASE       |
+------------------+              +------------------+              +------------------+
| analysisId FK    |              | analysisId FK    |              | analysisId FK    |
+------------------+              +------------------+              +------------------+
        | 1                               | 1                               | 1
        v                                 v                                 v
+------------------+              +------------------+              +------------------+
|  SOAR_EXECUTION  |              | ASSET_ENDPOINT   |              |  VULNERABILITY   |
+------------------+              +------------------+              +------------------+
| analysisId FK    |              | analysisId FK    |              | analysisId FK    |
+------------------+              +------------------+              +------------------+
```

---

## 4. Prisma Schema Design

```prisma
datasource db {
  provider = "mysql"
  url      = env("DATABASE_URL")
}

generator client {
  provider = "prisma-client-js"
}

enum ThreatLevel {
  LOW
  MEDIUM
  HIGH
  CRITICAL
  UNKNOWN
}

enum AnalysisStatus {
  PENDING
  PROCESSING
  COMPLETED
  FAILED
}

enum SoarStatus {
  COMPLETED
  PENDING_APPROVAL
  RECOMMENDED
  FAILED
}

model Analysis {
  id               String         @id @default(uuid())
  analysisId       String         @unique @default(cuid())
  fileName         String
  originalFileName String
  fileSize         Int
  fileType         String
  mimeType         String
  uploadedAt       DateTime       @default(now())
  analysisTime     DateTime?
  hostname         String?
  username         String?
  operatingSystem  String?
  riskScore        Int?
  threatLevel      ThreatLevel    @default(UNKNOWN)
  recommendation   String?        @db.Text
  status           AnalysisStatus @default(PENDING)
  source           String?        @db.Text
  createdAt        DateTime       @default(now())
  updatedAt        DateTime       @updatedAt

  // Relationships
  fileMetadata      FileMetadata?
  hashes            Hash?
  fileProperties    FileProperty?
  yaraResults       YaraResult[]
  virusTotalResult  VirusTotalResult?
  iocs              Ioc[]
  mitreTechniques   MitreTechnique[]
  behaviorEvents    BehaviorEvent[]
  sandboxResults    SandboxResult[]
  siemEvents        SiemEvent[]
  incidents         Incident[]
  cases             Case[]
  soarExecutions    SoarExecution[]
  assets            Asset[]
  endpoints         Endpoint[]
  vulnerabilities   Vulnerability[]
  auditLogs         AuditLog[]

  @@index([analysisId])
  @@index([createdAt])
  @@index([threatLevel])
}

model FileMetadata {
  id          String   @id @default(uuid())
  analysisId  String   @unique
  analysis    Analysis @relation(fields: [analysisId], references: [analysisId], onDelete: Cascade)
  filePath    String
  storageKey  String
  extension   String
  headerMagic String?
  encoding    String?

  @@index([analysisId])
}

model Hash {
  id         String   @id @default(uuid())
  analysisId String   @unique
  analysis   Analysis @relation(fields: [analysisId], references: [analysisId], onDelete: Cascade)
  md5        String?
  sha1       String?
  sha256     String?
  ssdeep     String?

  @@index([analysisId])
}

model FileProperty {
  id               String   @id @default(uuid())
  analysisId       String   @unique
  analysis         Analysis @relation(fields: [analysisId], references: [analysisId], onDelete: Cascade)
  entropy          Float?
  digitalSignature String?  // e.g., "Valid", "Not Signed", "Invalid"
  isPacked         Boolean?
  packer           String?
  imports          Json?    // Array of imported DLLs/functions
  suspiciousApis   Json?    // Array of suspicious API strings

  @@index([analysisId])
}

model YaraResult {
  id          String   @id @default(uuid())
  analysisId  String
  analysis    Analysis @relation(fields: [analysisId], references: [analysisId], onDelete: Cascade)
  ruleName    String
  namespace   String?
  tags        Json?
  meta        Json?
  description String?

  @@index([analysisId])
}

model VirusTotalResult {
  id           String   @id @default(uuid())
  analysisId   String   @unique
  analysis     Analysis @relation(fields: [analysisId], references: [analysisId], onDelete: Cascade)
  positives    Int
  total        Int
  permalink    String?
  scanDate     String?
  detections   Json?

  @@index([analysisId])
}

model Ioc {
  id          String   @id @default(uuid())
  analysisId  String
  analysis    Analysis @relation(fields: [analysisId], references: [analysisId], onDelete: Cascade)
  type        String   // IP, DOMAIN, URL, EMAIL, HASH
  value       String
  category    String?
  confidence  Int?
  description String?

  @@index([analysisId])
  @@index([type, value])
}

model MitreTechnique {
  id          String   @id @default(uuid())
  analysisId  String
  analysis    Analysis @relation(fields: [analysisId], references: [analysisId], onDelete: Cascade)
  tactic      String
  techniqueId String   // e.g., T1059.001
  name        String
  description String?  @db.Text

  @@index([analysisId])
}

model BehaviorEvent {
  id          String   @id @default(uuid())
  analysisId  String
  analysis    Analysis @relation(fields: [analysisId], references: [analysisId], onDelete: Cascade)
  eventType   String   // PROCESS, REGISTRY, FILE, NETWORK, PERSISTENCE
  action      String
  target      String
  details     String?  @db.Text
  timestamp   DateTime?

  @@index([analysisId])
}

model SandboxResult {
  id           String   @id @default(uuid())
  analysisId   String
  analysis     Analysis @relation(fields: [analysisId], references: [analysisId], onDelete: Cascade)
  sandboxName  String
  verdict      String
  score        Int?
  details      Json?

  @@index([analysisId])
}

model SiemEvent {
  id          String   @id @default(uuid())
  analysisId  String
  analysis    Analysis @relation(fields: [analysisId], references: [analysisId], onDelete: Cascade)
  eventId     String?
  sourceIp    String?
  destIp      String?
  sourcePort  Int?
  destPort    Int?
  protocol    String?
  action      String?
  severity    String?
  rawEvent    String   @db.Text
  timestamp   DateTime

  @@index([analysisId])
}

model Incident {
  id           String   @id @default(uuid())
  analysisId   String
  analysis     Analysis @relation(fields: [analysisId], references: [analysisId], onDelete: Cascade)
  title        String
  severity     ThreatLevel
  status       String   // OPEN, IN_PROGRESS, RESOLVED, CLOSED
  reason       String   // Source explicit vs Engine rule output with explanation
  assignedTo   String?
  createdAt    DateTime @default(now())

  @@index([analysisId])
}

model Case {
  id           String   @id @default(uuid())
  analysisId   String
  analysis     Analysis @relation(fields: [analysisId], references: [analysisId], onDelete: Cascade)
  caseNumber   String   @unique
  title        String
  status       String
  priority     String
  summary      String?  @db.Text

  @@index([analysisId])
}

model SoarExecution {
  id          String     @id @default(uuid())
  analysisId  String
  analysis    Analysis   @relation(fields: [analysisId], references: [analysisId], onDelete: Cascade)
  actionName  String
  target      String?
  status      SoarStatus
  executionLog String?   @db.Text
  timestamp   DateTime   @default(now())

  @@index([analysisId])
}

model Asset {
  id          String   @id @default(uuid())
  analysisId  String
  analysis    Analysis @relation(fields: [analysisId], references: [analysisId], onDelete: Cascade)
  assetName   String
  ipAddress   String?
  macAddress  String?
  assetType   String?
  criticality String?

  @@index([analysisId])
}

model Endpoint {
  id          String   @id @default(uuid())
  analysisId  String
  analysis    Analysis @relation(fields: [analysisId], references: [analysisId], onDelete: Cascade)
  hostname    String
  osVersion   String?
  agentStatus String?
  lastSeen    DateTime?

  @@index([analysisId])
}

model Vulnerability {
  id          String   @id @default(uuid())
  analysisId  String
  analysis    Analysis @relation(fields: [analysisId], references: [analysisId], onDelete: Cascade)
  cveId       String   // e.g., CVE-2023-1234
  title       String
  cvssScore   Float?
  severity    String?
  description String?  @db.Text

  @@index([analysisId])
}

model AuditLog {
  id          String   @id @default(uuid())
  analysisId  String?
  analysis    Analysis? @relation(fields: [analysisId], references: [analysisId], onDelete: SetNull)
  action      String
  performedBy String
  timestamp   DateTime @default(now())
  details     String?  @db.Text
}
```

---

## 5. API Endpoint Specification

All endpoints are hosted under `/api/v1`.

### Analysis & Core Resources
- `POST   /api/v1/analyses/upload` - Upload source file (.log, .txt, .json, .csv), trigger parser, write DB transaction, return `analysisId`.
- `GET    /api/v1/analyses` - Get list of all historical analyses (metadata only, for selector dropdown and historical overview).
- `GET    /api/v1/analyses/:analysisId` - Get top-level analysis record.
- `DELETE /api/v1/analyses/:analysisId` - Cascade delete analysis record and all child entities.

### Analysis-Scoped Module Endpoints (STRICTLY REQUIRED FOR SELECTED ANALYSIS)
- `GET    /api/v1/analyses/:analysisId/file` - File properties, hashes, metadata.
- `GET    /api/v1/analyses/:analysisId/yara` - YARA match results.
- `GET    /api/v1/analyses/:analysisId/virustotal` - VirusTotal summary and engine breakdown.
- `GET    /api/v1/analyses/:analysisId/iocs` - Extracted IOC indicators (IPs, domains, hashes, URLs).
- `GET    /api/v1/analyses/:analysisId/mitre` - MITRE ATT&CK tactics & techniques.
- `GET    /api/v1/analyses/:analysisId/behavior` - Process, registry, and file behavior events.
- `GET    /api/v1/analyses/:analysisId/sandbox` - Sandbox verdicts and execution details.
- `GET    /api/v1/analyses/:analysisId/siem` - SIEM log events for this analysis.
- `GET    /api/v1/analyses/:analysisId/incidents` - Incidents explicitly present or rule-triggered for this analysis.
- `GET    /api/v1/analyses/:analysisId/cases` - Cases associated with this analysis.
- `GET    /api/v1/analyses/:analysisId/soar` - SOAR actions & execution statuses for this analysis.
- `GET    /api/v1/analyses/:analysisId/assets` - Associated assets.
- `GET    /api/v1/analyses/:analysisId/endpoints` - Associated endpoints.
- `GET    /api/v1/analyses/:analysisId/vulnerabilities` - Identified CVEs for this analysis.
- `GET    /api/v1/analyses/:analysisId/reports` - Comprehensive compiled security report for this analysis.
- `GET    /api/v1/analyses/:analysisId/analytics` - Sample-specific metrics & charts.

### Enterprise / Global Metrics (Explicitly Labeled)
- `GET    /api/v1/analytics/enterprise` - Historical aggregates across all analyses (Total Analyses, Global Incidents Count, Threat Level distribution).

---

## 6. Analysis Data Model & DTO Standards

Every field present in the source file is parsed into a clean normalized `AnalysisInput` TypeScript structure before database insertion:

```typescript
export interface AnalysisInput {
  metadata: {
    fileName: string;
    originalFileName: string;
    fileSize: number;
    fileType: string;
    mimeType: string;
    hostname?: string | null;
    username?: string | null;
    operatingSystem?: string | null;
    analysisTime?: Date | null;
  };
  risk: {
    riskScore?: number | null; // e.g. 98
    threatLevel?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'UNKNOWN';
    recommendation?: string | null;
  };
  hashes?: {
    md5?: string | null;
    sha1?: string | null;
    sha256?: string | null;
    ssdeep?: string | null;
  };
  fileProperties?: {
    entropy?: number | null;
    digitalSignature?: string | null;
    isPacked?: boolean | null;
    packer?: string | null;
    imports?: string[];
    suspiciousApis?: string[];
  };
  yara?: Array<{
    ruleName: string;
    namespace?: string;
    tags?: string[];
    description?: string;
  }>;
  virusTotal?: {
    positives: number;
    total: number;
    permalink?: string;
    scanDate?: string;
    detections?: Record<string, string>;
  };
  iocs?: Array<{
    type: 'IP' | 'DOMAIN' | 'URL' | 'EMAIL' | 'HASH';
    value: string;
    category?: string;
    confidence?: number;
  }>;
  mitre?: Array<{
    tactic: string;
    techniqueId: string;
    name: string;
    description?: string;
  }>;
  behavior?: Array<{
    eventType: string;
    action: string;
    target: string;
    details?: string;
    timestamp?: Date;
  }>;
  sandbox?: Array<{
    sandboxName: string;
    verdict: string;
    score?: number;
    details?: any;
  }>;
  siem?: Array<{
    eventId?: string;
    sourceIp?: string;
    destIp?: string;
    sourcePort?: number;
    destPort?: number;
    protocol?: string;
    action?: string;
    severity?: string;
    rawEvent: string;
    timestamp: Date;
  }>;
  incident?: Array<{
    title: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'UNKNOWN';
    status: string;
    reason: string;
  }>;
  soar?: Array<{
    actionName: string;
    target?: string;
    status: 'COMPLETED' | 'PENDING_APPROVAL' | 'RECOMMENDED' | 'FAILED';
    executionLog?: string;
  }>;
  assets?: Array<{
    assetName: string;
    ipAddress?: string;
    assetType?: string;
  }>;
  endpoints?: Array<{
    hostname: string;
    osVersion?: string;
  }>;
  vulnerabilities?: Array<{
    cveId: string;
    title: string;
    cvssScore?: number;
    severity?: string;
    description?: string;
  }>;
}
```

---

## 7. Parser Architecture

```
                            +--------------------------+
                            |      ParserService       |
                            |  (Strategy Router/Facade)|
                            +------------+-------------+
                                         |
            +----------------------------+----------------------------+
            |                            |                            |
            v                            v                            v
+-----------------------+    +-----------------------+    +-----------------------+
|    TextLogParser      |    |      JsonParser       |    |      CsvParser        |
|  (Key-Value / Log)    |    |  (Structured Security)|    | (Tabular Event Logs)  |
+-----------+-----------+    +-----------+-----------+    +-----------+-----------+
            |                            |                            |
            +----------------------------+----------------------------+
                                         |
                                         v
                            +--------------------------+
                            |     AnalysisNormalizer   |
                            | (Returns AnalysisInput)  |
                            +--------------------------+
```

### Parser Workflow:
1. **Format Identification:** Inspect file MIME type, extension, and initial bytes.
2. **Strategy Execution:** Select matching parser (`TextLogParser`, `JsonParser`, or `CsvParser`).
3. **Raw Value Extraction:** Parse key-value lines, structured JSON fields, or CSV headers into raw key-value sets.
4. **Normalizer Step:** Map raw extracted fields to the `AnalysisInput` schema. Preserve raw scores (e.g. `Risk Score: 98/100` -> `riskScore: 98`).
5. **No Synthetic Logic:** Missing fields are left `undefined`/`null` so that database layers and API consumers accurately present `"Not Available"`.

---

## 8. Frontend State Architecture & `currentAnalysisId` Design

```
                                 +-------------------------+
                                 |    AnalysisContext      |
                                 |  currentAnalysisId      |
                                 |  (string | null)        |
                                 +------------+------------+
                                              |
                   +--------------------------+--------------------------+
                   |                                                     |
                   v                                                     v
      When currentAnalysisId != null                        When currentAnalysisId == null
                   |                                                     |
                   v                                                     v
+--------------------------------------+            +--------------------------------------+
| Enable TanStack Queries:             |            | Disable all analysis queries.        |
| ['analysis', currentAnalysisId]      |            | Render clean UI state:               |
| ['analysis-iocs', currentAnalysisId] |            | "No Active Analysis"                 |
| ['analysis-siem', currentAnalysisId] |            | Zero cached stale data display!      |
+--------------------------------------+            +--------------------------------------+
```

### React `AnalysisContext`:
```typescript
interface AnalysisContextType {
  currentAnalysisId: string | null;
  setCurrentAnalysisId: (id: string | null) => void;
  clearAnalysis: () => void;
}
```

### TanStack Query Integration:
All analysis feature hooks follow this strict pattern:
```typescript
export function useAnalysisIocs(analysisId: string | null) {
  return useQuery({
    queryKey: ['analysis-iocs', analysisId],
    queryFn: () => fetchAnalysisIocs(analysisId!),
    enabled: Boolean(analysisId), // Query is completely DISABLED when analysisId is null
    staleTime: 5 * 60 * 1000,
  });
}
```

When `analysisId` is null, components display:
```tsx
if (!currentAnalysisId) {
  return <NoActiveAnalysisState />;
}
```
No previous analysis remains visible, no fallback values are rendered, and no cross-sample mixing can occur.

---

## 9. Module Dependency Structure

```
                     +-------------------+
                     |   Prisma Module   |
                     +---------+---------+
                               |
                               v
                     +-------------------+
                     |   Upload Module   |
                     +---------+---------+
                               |
                               v
                     +-------------------+
                     |   Parser Module   |
                     +---------+---------+
                               |
                               v
                     +-------------------+
                     |  Analysis Module  |
                     +---------+---------+
                               |
       +-----------------------+-----------------------+
       |                       |                       |
       v                       v                       v
+--------------+        +--------------+        +--------------+
| SIEM Module  |        |  IOC Module  |        | Threat Intel |
+--------------+        +--------------+        +--------------+
       |                       |                       |
       +-----------------------+-----------------------+
                               |
                               v
+--------------------------------------------------------------+
| Incidents, Cases, SOAR, Assets, Endpoints, Vulnerabilities   |
+--------------------------------------------------------------+
```

---

## 10. Testing Strategy

1. **Parser Unit Tests:** Test `TextLogParser`, `JsonParser`, and `CsvParser` against sample test fixtures (TEST A [Risk 3, Low], TEST B [Risk 33, Medium], TEST C [Risk 75, High], TEST D [Risk 98, Critical]).
2. **Database Integration Tests:** Verify Prisma transactional creation for `Analysis` and child tables. Confirm cascade delete removes child rows without orphans.
3. **Cross-Sample Isolation Tests:**
   - Upload Sample A (Risk 3).
   - Upload Sample B (Risk 98).
   - Fetch `/api/v1/analyses/{SampleA_ID}/iocs` and verify zero Sample B indicators exist.
   - Set `currentAnalysisId` to `null` and verify empty states render `"No Active Analysis"`.
4. **Frontend E2E & Component Tests:** Verify UI state switching between samples and verify missing values display `"Not Available"`.

---

## 11. Proposed Phased Development Roadmap

### Phase 1: Greenfield Foundation & Project Initialization (CURRENT TARGET)
- Initialize project structure in `d:\soc 2.0`.
- Setup NestJS backend root structure, TypeScript config, ESLint.
- Setup Next.js frontend root structure, Tailwind CSS, TypeScript config.
- Configure MySQL connection via Prisma ORM and generate initial migrations.
- Implement Health Check API endpoint (`GET /api/v1/health`).
- Implement environment configuration (`.env` and `.env.example`).
- Verify end-to-end backend compilation, migration execution, and frontend startup.

### Phase 2: Parser Engine, Upload Service & Database Persistence
- Implement local file upload interceptor and storage service.
- Implement multi-format `ParserService` (`TextLogParser`, `JsonParser`, `CsvParser`, `Normalizer`).
- Implement transactional `AnalysisService.createAnalysisWithChildren`.
- Create `/api/v1/analyses/upload` and `/api/v1/analyses` REST endpoints.

### Phase 3: Frontend Upload & Core File Analysis UI
- Implement file drag-and-drop upload component.
- Build File Analysis view displaying hashes, file properties, YARA, VT, digital signatures, and risk scores.

### Phase 4: Central `currentAnalysisId` System & TopBar Selector
- Build `AnalysisContext` and top bar active sample selector.
- Add sample clearance capability and "No Active Analysis" UI states across modules.

### Phase 5: Dashboard Implementation
- Build Dashboard separating `CURRENT ANALYSIS` section from `ENTERPRISE / HISTORICAL OVERVIEW`.

### Phase 6: Core Security Modules (SIEM, IOC, Threat Intel, MITRE, Behavior, Sandbox)
- Build analysis-scoped endpoints and frontend screens for SIEM events, IOC Search, Threat Intelligence, MITRE matrix, Behavior tree, and Sandbox results.

### Phase 7: Incident, Case & SOAR Management
- Implement analysis-scoped Incident management (with explicit creation rationale tracking), Case management, and SOAR execution views.

### Phase 8: Assets, Endpoints, Logs & Vulnerabilities
- Implement analysis-scoped Assets, Endpoints, raw Logs viewer, and Vulnerability (CVE) modules.

### Phase 9: Reports & Enterprise Analytics
- Implement automated report compilation for selected `analysisId`.
- Build Enterprise & Sample Analytics dashboards.

### Phase 10: Integration & Build Validation
- Run full test suites, automated cross-sample verification, frontend/backend production builds, and write comprehensive `README.md`.

---

## 12. Verification Plan for Phase 1

### Automated Checks:
- NestJS compilation: `cd backend && npm run build`
- Prisma schema validation: `npx prisma validate`
- Next.js TypeScript check: `cd frontend && npm run build` (or `npx tsc --noEmit`)

### Manual & API Verification:
- Run backend on port 4000 and query `http://localhost:4000/api/v1/health` to confirm `{ "status": "ok", "timestamp": "..." }`.
- Run frontend on port 3000 and verify clean render.
