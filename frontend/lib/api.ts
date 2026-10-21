const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4000/api/v1';

let cachedToken: string | null = null;

export async function getAuthToken(): Promise<string> {
  if (typeof window !== 'undefined') {
    const localToken = localStorage.getItem('soc_access_token');
    if (localToken) return localToken;
  }
  if (cachedToken) return cachedToken;

  try {
    const res = await fetch(`${API_BASE_URL}/auth/demo-token`);
    if (res.ok) {
      const data = await res.json();
      cachedToken = data.access_token;
      if (typeof window !== 'undefined' && cachedToken) {
        localStorage.setItem('soc_access_token', cachedToken);
      }
      return cachedToken || '';
    }
  } catch (e) {
    console.warn('Unable to auto-fetch demo token:', e);
  }
  return '';
}

async function authFetch(url: string | URL, options: RequestInit = {}): Promise<Response> {
  let token = await getAuthToken();
  const headers = new Headers(options.headers || {});
  if (token && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  let res = await fetch(url.toString(), {
    ...options,
    headers,
  });

  if (res.status === 401) {
    cachedToken = null;
    if (typeof window !== 'undefined') {
      localStorage.removeItem('soc_access_token');
    }
    // Attempt re-auth once if demo token can be refreshed
    token = await getAuthToken();
    if (token) {
      const retryHeaders = new Headers(options.headers || {});
      retryHeaders.set('Authorization', `Bearer ${token}`);
      res = await fetch(url.toString(), {
        ...options,
        headers: retryHeaders,
      });
    }
  } else if (res.status === 403) {
    cachedToken = null;
    if (typeof window !== 'undefined') {
      localStorage.removeItem('soc_access_token');
    }
  }

  return res;
}

export interface UploadResponse {
  analysisId: string;
  originalFileName: string;
  fileType: string;
  fileSize: number;
  riskScore: number | null;
  threatLevel: string | null;
  status: string;
  uploadedAt: string;
}

export interface AnalysisDetail {
  id: string;
  analysisId: string;
  fileName: string;
  originalFileName: string;
  fileSize: number;
  fileType: string;
  mimeType: string;
  uploadedAt: string;
  analysisTime?: string | null;
  hostname?: string | null;
  username?: string | null;
  operatingSystem?: string | null;
  riskScore?: number | null;
  threatLevel?: string | null;
  recommendation?: string | null;
  status: string;
  parsingStatus?: string | null;
  parsingWarnings?: string[] | null;
  unrecognizedFields?: any;
  provenance?: any;
  source?: string | null;
  fileMetadata?: {
    filePath: string;
    storageKey: string;
    extension: string;
    calculatedMd5?: string | null;
    calculatedSha1?: string | null;
    calculatedSha256?: string | null;
  } | null;
  hashes?: {
    md5?: string | null;
    sha1?: string | null;
    sha256?: string | null;
    ssdeep?: string | null;
  } | null;
  fileProperties?: {
    entropy?: number | null;
    digitalSignature?: string | null;
    isPacked?: boolean | null;
    packer?: string | null;
  } | null;
  yaraResults?: Array<{
    id: string;
    ruleName: string;
    namespace?: string | null;
    tags?: any;
    description?: string | null;
  }>;
  virusTotalResult?: {
    positives: number;
    total: number;
    permalink?: string | null;
    scanDate?: string | null;
  } | null;
  iocs?: Array<{
    id: string;
    type: string;
    value: string;
    category?: string | null;
    confidence?: number | null;
    description?: string | null;
  }>;
  mitreTechniques?: Array<{
    id: string;
    tactic: string;
    techniqueId: string;
    name: string;
    description?: string | null;
  }>;
  behaviorEvents?: Array<{
    id: string;
    eventType: string;
    action: string;
    target: string;
    details?: string | null;
    timestamp?: string | null;
  }>;
  sandboxResults?: Array<{
    id: string;
    sandboxName: string;
    verdict: string;
    score?: number | null;
  }>;
  siemEvents?: Array<{
    id: string;
    eventId?: string | null;
    sourceIp?: string | null;
    destIp?: string | null;
    sourcePort?: number | null;
    destPort?: number | null;
    protocol?: string | null;
    action?: string | null;
    severity?: string | null;
    rawEvent: string;
    timestamp: string;
  }>;
  incidents?: Array<{
    id: string;
    title: string;
    severity?: string | null;
    status: string;
    reason: string;
    assignedTo?: string | null;
  }>;
  soarExecutions?: Array<{
    id: string;
    actionName: string;
    target?: string | null;
    status: string;
    executionLog?: string | null;
  }>;
  assets?: Array<{
    id: string;
    assetName: string;
    ipAddress?: string | null;
    assetType?: string | null;
  }>;
  endpoints?: Array<{
    id: string;
    hostname: string;
    osVersion?: string | null;
  }>;
  vulnerabilities?: Array<{
    id: string;
    cveId: string;
    title: string;
    cvssScore?: number | null;
    severity?: string | null;
  }>;
}

export async function uploadAnalysisFile(file: File): Promise<UploadResponse> {
  const formData = new FormData();
  formData.append('file', file);

  const res = await authFetch(`${API_BASE_URL}/analyses/upload`, {
    method: 'POST',
    body: formData,
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.message || `Upload failed with HTTP status ${res.status}`);
  }

  return res.json();
}

export async function fetchAllAnalyses(): Promise<UploadResponse[]> {
  const res = await authFetch(`${API_BASE_URL}/analyses`);
  if (!res.ok) {
    throw new Error(`Failed to fetch analyses list: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchAnalysisById(analysisId: string): Promise<AnalysisDetail> {
  const res = await authFetch(`${API_BASE_URL}/analyses/${analysisId}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch analysis '${analysisId}': ${res.statusText}`);
  }
  return res.json();
}

export interface SiemEventsResponse {
  analysisId: string;
  totalCount: number;
  parsingStatus?: string | null;
  parsingWarnings?: string[] | null;
  provenance?: any;
  events: Array<{
    id: string;
    eventId?: string | null;
    sourceIp?: string | null;
    destIp?: string | null;
    sourcePort?: number | null;
    destPort?: number | null;
    protocol?: string | null;
    action?: string | null;
    severity?: string | null;
    rawEvent: string;
    timestamp: string;
  }>;
}

export interface IocsResponse {
  analysisId: string;
  totalCount: number;
  parsingStatus?: string | null;
  provenance?: any;
  iocs: Array<{
    id: string;
    type: string;
    value: string;
    category?: string | null;
    confidence?: number | null;
    description?: string | null;
  }>;
}

export async function fetchAnalysisSiem(
  analysisId: string,
  params?: { severity?: string; search?: string; sourceIp?: string; destIp?: string },
): Promise<SiemEventsResponse> {
  const url = new URL(`${API_BASE_URL}/analyses/${analysisId}/siem`);
  if (params?.severity && params.severity !== 'ALL') url.searchParams.append('severity', params.severity);
  if (params?.search) url.searchParams.append('search', params.search);
  if (params?.sourceIp) url.searchParams.append('sourceIp', params.sourceIp);
  if (params?.destIp) url.searchParams.append('destIp', params.destIp);

  const res = await authFetch(url.toString());
  if (!res.ok) {
    throw new Error(`Failed to fetch SIEM events for '${analysisId}': ${res.statusText}`);
  }
  return res.json();
}

export async function fetchAnalysisIocs(
  analysisId: string,
  params?: { type?: string; search?: string; category?: string },
): Promise<IocsResponse> {
  const url = new URL(`${API_BASE_URL}/analyses/${analysisId}/iocs`);
  if (params?.type && params.type !== 'ALL') url.searchParams.append('type', params.type);
  if (params?.search) url.searchParams.append('search', params.search);
  if (params?.category) url.searchParams.append('category', params.category);

  const res = await authFetch(url.toString());
  if (!res.ok) {
    throw new Error(`Failed to fetch IOCs for '${analysisId}': ${res.statusText}`);
  }
  return res.json();
}

export interface ThreatIntelResponse {
  analysisId: string;
  hasData: boolean;
  riskScore?: number | null;
  threatLevel?: string | null;
  recommendation?: string | null;
  parsingStatus?: string | null;
  provenance?: any;
  virusTotalResult?: {
    positives: number;
    total: number;
    permalink?: string | null;
    scanDate?: string | null;
  } | null;
  yaraResults?: Array<{
    id: string;
    ruleName: string;
    namespace?: string | null;
    tags?: any;
    description?: string | null;
  }>;
  iocs?: Array<{
    id: string;
    type: string;
    value: string;
    category?: string | null;
    confidence?: number | null;
    description?: string | null;
  }>;
}

export interface MitreResponse {
  analysisId: string;
  totalCount: number;
  parsingStatus?: string | null;
  provenance?: any;
  techniques: Array<{
    id: string;
    tactic: string;
    techniqueId: string;
    name: string;
    description?: string | null;
  }>;
}

export interface BehaviorResponse {
  analysisId: string;
  totalCount: number;
  parsingStatus?: string | null;
  provenance?: any;
  events: Array<{
    id: string;
    eventType: string;
    action: string;
    target: string;
    details?: string | null;
    timestamp?: string | null;
  }>;
}

export interface SandboxResponse {
  analysisId: string;
  totalCount: number;
  parsingStatus?: string | null;
  provenance?: any;
  results: Array<{
    id: string;
    sandboxName: string;
    verdict: string;
    score?: number | null;
    details?: any;
  }>;
}

export async function fetchAnalysisThreatIntel(analysisId: string): Promise<ThreatIntelResponse> {
  const res = await authFetch(`${API_BASE_URL}/analyses/${analysisId}/threat-intel`);
  if (!res.ok) {
    throw new Error(`Failed to fetch Threat Intelligence for '${analysisId}': ${res.statusText}`);
  }
  return res.json();
}

export async function fetchAnalysisMitre(analysisId: string): Promise<MitreResponse> {
  const res = await authFetch(`${API_BASE_URL}/analyses/${analysisId}/mitre`);
  if (!res.ok) {
    throw new Error(`Failed to fetch MITRE ATT&CK techniques for '${analysisId}': ${res.statusText}`);
  }
  return res.json();
}

export async function fetchAnalysisBehavior(analysisId: string): Promise<BehaviorResponse> {
  const res = await authFetch(`${API_BASE_URL}/analyses/${analysisId}/behavior`);
  if (!res.ok) {
    throw new Error(`Failed to fetch Behavior events for '${analysisId}': ${res.statusText}`);
  }
  return res.json();
}

export async function fetchAnalysisSandbox(analysisId: string): Promise<SandboxResponse> {
  const res = await authFetch(`${API_BASE_URL}/analyses/${analysisId}/sandbox`);
  if (!res.ok) {
    throw new Error(`Failed to fetch Sandbox results for '${analysisId}': ${res.statusText}`);
  }
  return res.json();
}

export interface IncidentsResponse {
  analysisId: string;
  totalCount: number;
  incidents: Array<{
    id: string;
    analysisId: string;
    title: string;
    severity?: string | null;
    status: string;
    reason: string;
    assignedTo?: string | null;
    createdAt: string;
  }>;
}

export interface CasesResponse {
  analysisId: string;
  totalCount: number;
  cases: Array<{
    id: string;
    analysisId: string;
    caseNumber: string;
    title: string;
    status: string;
    priority: string;
    summary?: string | null;
  }>;
}

export async function fetchAnalysisIncidents(analysisId: string): Promise<IncidentsResponse> {
  const res = await authFetch(`${API_BASE_URL}/analyses/${analysisId}/incidents`);
  if (!res.ok) {
    throw new Error(`Failed to fetch Incidents for '${analysisId}': ${res.statusText}`);
  }
  return res.json();
}

export async function createAnalystIncident(
  analysisId: string,
  payload: { title: string; severity?: string; status?: string; reason?: string; assignedTo?: string },
): Promise<any> {
  const res = await authFetch(`${API_BASE_URL}/analyses/${analysisId}/incidents`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.message || `Failed to create incident: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchAnalysisCases(analysisId: string): Promise<CasesResponse> {
  const res = await authFetch(`${API_BASE_URL}/analyses/${analysisId}/cases`);
  if (!res.ok) {
    throw new Error(`Failed to fetch Cases for '${analysisId}': ${res.statusText}`);
  }
  return res.json();
}

export async function createAnalystCase(
  analysisId: string,
  payload: { title: string; status?: string; priority?: string; summary?: string },
): Promise<any> {
  const res = await authFetch(`${API_BASE_URL}/analyses/${analysisId}/cases`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.message || `Failed to create case: ${res.statusText}`);
  }
  return res.json();
}

export interface SoarRecord {
  id: string;
  analysisId: string;
  actionName: string;
  description?: string | null;
  actionType?: string | null;
  target?: string | null;
  status: string;
  triggeredBy?: string | null;
  source?: string | null;
  result?: string | null;
  executionLog?: string | null;
  executedAt?: string | null;
  completedAt?: string | null;
  timestamp: string;
}

export interface SoarResponse {
  analysisId: string;
  totalCount: number;
  soarExecutions: SoarRecord[];
}

export async function fetchAnalysisSoar(analysisId: string): Promise<SoarResponse> {
  const res = await authFetch(`${API_BASE_URL}/analyses/${analysisId}/soar`);
  if (!res.ok) {
    throw new Error(`Failed to fetch SOAR actions for '${analysisId}': ${res.statusText}`);
  }
  return res.json();
}

export async function createAnalystSoarAction(
  analysisId: string,
  payload: {
    actionName: string;
    description?: string;
    actionType?: string;
    target?: string;
    status?: string;
    triggeredBy?: string;
    isSimulation?: boolean;
    confirmed?: boolean;
    isConfirmed?: boolean;
  },
): Promise<SoarRecord> {
  const res = await authFetch(`${API_BASE_URL}/analyses/${analysisId}/soar`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.message || `Failed to create SOAR action: ${res.statusText}`);
  }
  return res.json();
}

export interface AssetRecord {
  id: string;
  analysisId: string;
  assetName: string;
  hostname?: string | null;
  ipAddress?: string | null;
  macAddress?: string | null;
  assetType?: string | null;
  criticality?: string | null;
  operatingSystem?: string | null;
  owner?: string | null;
  status?: string | null;
  source?: string | null;
  description?: string | null;
  evidence?: string | null;
  createdAt?: string;
  updatedAt?: string;
}

export interface AssetsResponse {
  analysisId: string;
  totalCount: number;
  assets: AssetRecord[];
}

export interface EndpointRecord {
  id: string;
  analysisId: string;
  hostname: string;
  ipAddress?: string | null;
  osVersion?: string | null;
  operatingSystem?: string | null;
  user?: string | null;
  agentStatus?: string | null;
  status?: string | null;
  endpointType?: string | null;
  source?: string | null;
  evidence?: string | null;
  lastSeen?: string | null;
  createdAt?: string;
  updatedAt?: string;
}

export interface EndpointsResponse {
  analysisId: string;
  totalCount: number;
  endpoints: EndpointRecord[];
}

export async function fetchAnalysisAssets(analysisId: string): Promise<AssetsResponse> {
  const res = await authFetch(`${API_BASE_URL}/analyses/${analysisId}/assets`);
  if (!res.ok) {
    throw new Error(`Failed to fetch Assets for '${analysisId}': ${res.statusText}`);
  }
  return res.json();
}

export async function fetchAnalysisEndpoints(analysisId: string): Promise<EndpointsResponse> {
  const res = await authFetch(`${API_BASE_URL}/analyses/${analysisId}/endpoints`);
  if (!res.ok) {
    throw new Error(`Failed to fetch Endpoints for '${analysisId}': ${res.statusText}`);
  }
  return res.json();
}

export interface VulnerabilityRecord {
  id: string;
  analysisId: string;
  cveId: string;
  title: string;
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
  createdAt?: string;
  updatedAt?: string;
}

export interface VulnerabilitiesResponse {
  analysisId: string;
  totalCount: number;
  vulnerabilities: VulnerabilityRecord[];
}

export async function fetchAnalysisVulnerabilities(analysisId: string): Promise<VulnerabilitiesResponse> {
  const res = await authFetch(`${API_BASE_URL}/analyses/${analysisId}/vulnerabilities`);
  if (!res.ok) {
    throw new Error(`Failed to fetch Vulnerabilities for '${analysisId}': ${res.statusText}`);
  }
  return res.json();
}

export interface EnterpriseAnalyticsResponse {
  scope: string;
  generatedAt: string;
  totalAnalyses: number;
  riskScoreDistribution: {
    low: number;
    medium: number;
    high: number;
    critical: number;
    missing: number;
  };
  threatLevelDistribution: {
    LOW: number;
    MEDIUM: number;
    HIGH: number;
    CRITICAL: number;
    MISSING: number;
  };
  counts: {
    incidents: number;
    cases: number;
    vulnerabilities: number;
    assets: number;
    endpoints: number;
    soarExecutions: number;
  };
  vulnerabilitiesBySeverity: Record<string, number>;
  soarStatusBreakdown: {
    simulations: number;
    completed: number;
    other: number;
  };
}

export async function fetchAnalysisReport(analysisId: string, reportType: string): Promise<any> {
  const res = await authFetch(`${API_BASE_URL}/analyses/${analysisId}/reports/${reportType}`);
  if (!res.ok) {
    throw new Error(`Failed to generate report '${reportType}' for '${analysisId}': ${res.statusText}`);
  }
  return res.json();
}

/**
 * Downloads a generated PDF or CSV report using authenticated Bearer header.
 * The file is retrieved as a Blob so that the JWT is NEVER exposed in the URL.
 */
export async function downloadReportFile(
  analysisId: string,
  reportType: string,
  format: 'pdf' | 'csv',
): Promise<void> {
  const url = `${API_BASE_URL}/analyses/${analysisId}/reports/${reportType}/export?format=${format}`;
  const res = await authFetch(url);

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(
      errorData.message || `Export download failed with HTTP status ${res.status}`,
    );
  }

  const blob = await res.blob();
  if (typeof window !== 'undefined') {
    const blobUrl = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = blobUrl;
    link.download = `report_${reportType}_${analysisId}.${format}`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(blobUrl);
  }
}

/**
 * @deprecated Use downloadReportFile instead. Query-string JWT authentication is strictly removed.
 */
export function getExportReportUrl(analysisId: string, reportType: string, format: 'pdf' | 'csv'): string {
  return `${API_BASE_URL}/analyses/${analysisId}/reports/${reportType}/export?format=${format}`;
}

export async function fetchEnterpriseAnalytics(): Promise<EnterpriseAnalyticsResponse> {
  const res = await authFetch(`${API_BASE_URL}/analytics/enterprise`);
  if (!res.ok) {
    throw new Error(`Failed to fetch Enterprise Analytics: ${res.statusText}`);
  }
  return res.json();
}
