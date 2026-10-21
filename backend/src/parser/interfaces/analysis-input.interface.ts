import { ThreatLevel, SoarStatus } from '@prisma/client';

export interface AnalysisInputMetadata {
  fileName: string;
  originalFileName: string;
  fileSize: number;
  fileType: string;
  mimeType: string;
  hostname?: string | null;
  username?: string | null;
  operatingSystem?: string | null;
  analysisTime?: Date | null;
}

export interface AnalysisInputRisk {
  riskScore?: number | null;
  threatLevel?: ThreatLevel | null;
  recommendation?: string | null;
}

export interface AnalysisInputHashes {
  md5?: string | null;
  sha1?: string | null;
  sha256?: string | null;
  ssdeep?: string | null;
}

export interface AnalysisInputFileProperties {
  entropy?: number | null;
  digitalSignature?: string | null;
  isPacked?: boolean | null;
  packer?: string | null;
  imports?: any;
  suspiciousApis?: any;
}

export interface AnalysisInputYara {
  ruleName: string;
  namespace?: string | null;
  tags?: any;
  meta?: any;
  description?: string | null;
}

export interface AnalysisInputVirusTotal {
  positives: number;
  total: number;
  permalink?: string | null;
  scanDate?: string | null;
  detections?: any;
}

export interface AnalysisInputIoc {
  type: string;
  value: string;
  category?: string | null;
  confidence?: number | null;
  description?: string | null;
}

export interface AnalysisInputMitre {
  tactic: string;
  techniqueId: string;
  name: string;
  description?: string | null;
}

export interface AnalysisInputBehavior {
  eventType: string;
  action: string;
  target: string;
  details?: string | null;
  timestamp?: Date | null;
  [key: string]: any;
}

export interface AnalysisInputSandbox {
  sandboxName: string;
  verdict: string;
  score?: number | null;
  details?: any;
  [key: string]: any;
}

export interface AnalysisInputSiem {
  eventId?: string | null;
  sourceIp?: string | null;
  destIp?: string | null;
  sourcePort?: number | null;
  destPort?: number | null;
  protocol?: string | null;
  action?: string | null;
  severity?: string | null;
  rawEvent: string;
  timestamp: Date;
}

export interface AnalysisInputIncident {
  title: string;
  severity?: ThreatLevel | null;
  status: string;
  reason: string;
  assignedTo?: string | null;
}

export interface AnalysisInputSoar {
  actionName: string;
  description?: string | null;
  actionType?: string | null;
  target?: string | null;
  status: SoarStatus;
  triggeredBy?: string | null;
  source?: string | null;
  result?: string | null;
  executionLog?: string | null;
  executedAt?: Date | null;
  completedAt?: Date | null;
}

export interface AnalysisInputAsset {
  assetName?: string;
  hostname?: string | null;
  ipAddress?: string | null;
  macAddress?: string | null;
  assetType?: string | null;
  criticality?: string | null;
  operatingSystem?: string | null;
  owner?: string | null;
  user?: string | null;
  status?: string | null;
  source?: string | null;
  description?: string | null;
  evidence?: string | null;
}

export interface AnalysisInputEndpoint {
  hostname?: string;
  ipAddress?: string | null;
  osVersion?: string | null;
  operatingSystem?: string | null;
  user?: string | null;
  agentStatus?: string | null;
  status?: string | null;
  endpointType?: string | null;
  source?: string | null;
  evidence?: string | null;
  lastSeen?: Date | null;
}

export interface AnalysisInputVulnerability {
  cveId?: string;
  vulnerabilityId?: string;
  title?: string;
  name?: string;
  cvssScore?: number | null;
  severity?: string | null;
  description?: string | null;
  affectedAsset?: string | null;
  packageName?: string | null;
  installedVersion?: string | null;
  fixedVersion?: string | null;
  status?: string | null;
  remediation?: string | null;
  source?: string | null;
  evidence?: string | null;
}

export interface AnalysisInput {
  metadata: AnalysisInputMetadata;
  risk: AnalysisInputRisk;
  hashes?: AnalysisInputHashes | null;
  fileProperties?: AnalysisInputFileProperties | null;
  yara?: AnalysisInputYara[] | null;
  virusTotal?: AnalysisInputVirusTotal | null;
  iocs?: AnalysisInputIoc[] | null;
  mitre?: AnalysisInputMitre[] | null;
  behavior?: AnalysisInputBehavior[] | null;
  sandbox?: AnalysisInputSandbox[] | null;
  siem?: AnalysisInputSiem[] | null;
  incident?: AnalysisInputIncident[] | null;
  soar?: AnalysisInputSoar[] | null;
  assets?: AnalysisInputAsset[] | null;
  endpoints?: AnalysisInputEndpoint[] | null;
  vulnerabilities?: AnalysisInputVulnerability[] | null;
  parsingStatus?: string;
  parsingWarnings?: string[];
  unrecognizedFields?: any;
  provenance?: any;
}
