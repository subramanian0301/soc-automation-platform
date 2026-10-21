'use client';

import React from 'react';
import { useAnalysisContext } from '@/context/AnalysisContext';
import {
  fetchAnalysisById,
  fetchAllAnalyses,
  fetchEnterpriseAnalytics,
  AnalysisDetail,
  UploadResponse,
  EnterpriseAnalyticsResponse,
} from '@/lib/api';
import { useQuery } from '@tanstack/react-query';
import { PageHeader } from '@/components/ui/PageHeader';
import { MetricCard } from '@/components/ui/MetricCard';
import { DataTable, Column } from '@/components/ui/DataTable';
import { SeverityBadge } from '@/components/ui/SeverityBadge';
import { EmptyState } from '@/components/ui/EmptyState';
import { getModuleState } from '@/lib/moduleState';

import {
  FileText,
  ShieldAlert,
  Hash,
  Activity,
  Layers,
  Terminal,
  AlertTriangle,
  Upload,
  Server,
  ShieldCheck,
  CheckCircle,
  FileCode,
  Globe,
  Database,
  Crosshair,
  ArrowRight,
  TrendingUp,
  AlertCircle,
  Bug,
  FolderGit2,
} from 'lucide-react';

interface DashboardProps {
  onOpenUpload: () => void;
}

export function Dashboard({ onOpenUpload }: DashboardProps) {
  const { currentAnalysisId, setCurrentAnalysisId } = useAnalysisContext();

  // 1. Fetch Enterprise Analytics (Enterprise-scoped metrics)
  const { data: enterpriseData } = useQuery<EnterpriseAnalyticsResponse>({
    queryKey: ['enterprise-analytics'],
    queryFn: fetchEnterpriseAnalytics,
    refetchInterval: 15000,
  });

  // 2. Fetch All Historical Analyses (for Recent Analyses Table & Dropdowns)
  const { data: analysesList = [] } = useQuery<UploadResponse[]>({
    queryKey: ['analyses-list'],
    queryFn: fetchAllAnalyses,
    refetchInterval: 10000,
  });

  // 3. Fetch Active Analysis Details (Analysis-scoped)
  const {
    data: analysis,
    isLoading: isAnalysisLoading,
    isError: isAnalysisError,
    error: analysisError,
  } = useQuery<AnalysisDetail>({
    queryKey: ['analysis', currentAnalysisId],
    queryFn: () => fetchAnalysisById(currentAnalysisId!),
    enabled: Boolean(currentAnalysisId),
  });

  // Threat level badge helper (preserves data-testid="threat-level")
  const getThreatBadge = (level?: string | null) => {
    if (!level) return <span data-testid="threat-level" className="text-slate-400 text-xs font-semibold">Not Available</span>;
    const clean = level.toUpperCase();
    if (clean === 'CRITICAL')
      return <span data-testid="threat-level" className="px-3 py-1 bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/30 rounded-full font-bold text-xs uppercase tracking-wider">CRITICAL</span>;
    if (clean === 'HIGH')
      return <span data-testid="threat-level" className="px-3 py-1 bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/30 rounded-full font-bold text-xs uppercase tracking-wider">HIGH</span>;
    if (clean === 'MEDIUM')
      return <span data-testid="threat-level" className="px-3 py-1 bg-yellow-500/10 text-yellow-600 dark:text-yellow-400 border border-yellow-500/30 rounded-full font-bold text-xs uppercase tracking-wider">MEDIUM</span>;
    if (clean === 'LOW')
      return <span data-testid="threat-level" className="px-3 py-1 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30 rounded-full font-bold text-xs uppercase tracking-wider">LOW</span>;
    return <span data-testid="threat-level" className="text-slate-400 text-xs font-semibold">{level}</span>;
  };

  // Helper for packed status formatting (preserves data-testid)
  const getPackedStatus = (fileProperties?: AnalysisDetail['fileProperties']) => {
    if (!fileProperties || fileProperties.isPacked === null || fileProperties.isPacked === undefined) {
      return 'Not Available';
    }
    if (fileProperties.isPacked) {
      return fileProperties.packer ? `Yes (${fileProperties.packer})` : 'Yes';
    }
    return 'No';
  };

  // Table Columns Definition for Recent Analyses
  const columns: Column<UploadResponse>[] = [
    {
      header: 'File Name',
      cell: (item) => (
        <div className="flex items-center space-x-2.5 max-w-[220px]">
          <FileText className="w-4 h-4 text-indigo-600 dark:text-sky-400 shrink-0" />
          <span className="font-semibold text-slate-900 dark:text-slate-100 truncate" title={item.originalFileName}>
            {item.originalFileName}
          </span>
        </div>
      ),
    },
    {
      header: 'File Type',
      cell: (item) => (
        <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
          {item.fileType}
        </span>
      ),
    },
    {
      header: 'Risk Score',
      cell: (item) =>
        item.riskScore !== null && item.riskScore !== undefined ? (
          <span className={`font-bold font-mono ${item.riskScore >= 70 ? 'text-rose-600 dark:text-rose-400' : 'text-slate-700 dark:text-slate-300'}`}>
            {item.riskScore} / 100
          </span>
        ) : (
          <span className="text-slate-400">N/A</span>
        ),
    },
    {
      header: 'Threat Level',
      cell: (item) => (item.threatLevel ? <SeverityBadge severity={item.threatLevel} /> : <span className="text-slate-400">N/A</span>),
    },
    {
      header: 'Uploaded',
      cell: (item) => (
        <span className="text-slate-500 dark:text-slate-400 text-xs">
          {new Date(item.uploadedAt).toLocaleString()}
        </span>
      ),
    },
    {
      header: 'Action',
      cell: (item) => {
        const isSelected = item.analysisId === currentAnalysisId;
        return (
          <button
            onClick={(e) => {
              e.stopPropagation();
              setCurrentAnalysisId(item.analysisId);
            }}
            className={`px-3 py-1 text-xs font-semibold rounded-lg transition-all flex items-center gap-1 ${
              isSelected
                ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30'
                : 'bg-indigo-600 text-white dark:bg-sky-600 hover:opacity-90'
            }`}
          >
            {isSelected ? 'Active' : 'Inspect'}
            {!isSelected && <ArrowRight className="w-3 h-3" />}
          </button>
        );
      },
    },
  ];

  const highRiskCount =
    enterpriseData
      ? (enterpriseData.riskScoreDistribution.high || 0) + (enterpriseData.riskScoreDistribution.critical || 0)
      : analysesList.filter((a) => (a.riskScore && a.riskScore >= 70) || a.threatLevel === 'HIGH' || a.threatLevel === 'CRITICAL').length;

  return (
    <div data-testid="dashboard-view" className="space-y-8">
      {/* Page Header */}
      <PageHeader
        title="Security Overview"
        description="Enterprise Security Operations Center & Analysis Workspace"
        badge="Enterprise Live"
      >
        <button
          onClick={onOpenUpload}
          className="flex items-center space-x-2 bg-indigo-600 hover:bg-indigo-700 dark:bg-sky-600 dark:hover:bg-sky-500 text-white font-medium text-xs px-4 py-2.5 rounded-xl transition-all shadow-md active:scale-95"
        >
          <Upload className="w-4 h-4" />
          <span>Upload Security File</span>
        </button>
      </PageHeader>

      {/* Enterprise KPI Cards Section */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Total Analyses"
          value={enterpriseData?.totalAnalyses ?? analysesList.length}
          subtitle="Enterprise-wide historical records"
          icon={<FileText className="w-5 h-5" />}
          variant="default"
        />
        <MetricCard
          title="High-Risk Analyses"
          value={highRiskCount}
          subtitle="Severity High / Critical"
          icon={<ShieldAlert className="w-5 h-5 text-rose-500" />}
          variant="danger"
        />
        <MetricCard
          title="Open Incidents"
          value={enterpriseData?.counts.incidents ?? 0}
          subtitle="Active SOC Response Cases"
          icon={<AlertTriangle className="w-5 h-5 text-amber-500" />}
          variant="warning"
        />
        <MetricCard
          title="Vulnerabilities"
          value={enterpriseData?.counts.vulnerabilities ?? 0}
          subtitle="Identified CVE Security Threats"
          icon={<Bug className="w-5 h-5 text-rose-500" />}
          variant="danger"
        />
      </div>

      {/* Recent Historical Analyses Table Section */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
            Recent Analysis History
            <span className="text-xs font-semibold px-2 py-0.5 rounded-full bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400">
              {analysesList.length} total
            </span>
          </h2>
        </div>

        <DataTable<UploadResponse>
          data={analysesList}
          columns={columns}
          searchPlaceholder="Search analyses by filename or filetype..."
          searchFilterKeys={['originalFileName', 'fileType', 'threatLevel']}
          initialPageSize={10}
          selectedItemId={currentAnalysisId}
          getItemId={(item) => item.analysisId}
          onRowClick={(item) => setCurrentAnalysisId(item.analysisId)}
        />
      </div>

      {/* ACTIVE ANALYSIS WORKSPACE INSPECTOR */}
      <div className="pt-4 border-t border-slate-200 dark:border-slate-800">
        <h2 className="text-lg font-bold text-slate-900 dark:text-slate-100 mb-4 flex items-center gap-2">
          Active Analysis Workspace
          {currentAnalysisId && (
            <span className="font-mono text-xs text-indigo-600 dark:text-sky-400 font-semibold bg-indigo-50 dark:bg-sky-500/10 px-2.5 py-1 rounded-md border border-indigo-200 dark:border-sky-500/30">
              ID: {currentAnalysisId}
            </span>
          )}
        </h2>

        {/* 1. EMPTY STATE: When no analysis selected */}
        {!currentAnalysisId && (
          <div data-testid="no-analysis-state">
            <EmptyState
              title="No Active Analysis Selected"
              description="Select an active security analysis from the table above or upload a new file (.log, .txt, .json, .csv) to view analysis-scoped findings."
              action={{
                label: 'Upload Analysis File',
                onClick: onOpenUpload,
              }}
            />
          </div>
        )}

        {/* 2. LOADING STATE */}
        {currentAnalysisId && isAnalysisLoading && (
          <div data-testid="loading-state" className="p-12 text-center bg-white dark:bg-[#111726] rounded-xl border border-slate-200 dark:border-slate-800">
            <div className="flex flex-col items-center space-y-3">
              <div className="h-8 w-8 border-4 border-indigo-500/30 dark:border-sky-500/30 border-t-indigo-600 dark:border-t-sky-500 rounded-full animate-spin" />
              <p className="text-xs font-mono text-slate-500 dark:text-slate-400">Loading analysis data for {currentAnalysisId}...</p>
            </div>
          </div>
        )}

        {/* 3. ERROR STATE */}
        {currentAnalysisId && (isAnalysisError || !analysis) && !isAnalysisLoading && (
          <div data-testid="error-state" className="p-6 bg-rose-500/10 border border-rose-500/20 rounded-xl text-center text-rose-700 dark:text-rose-400 space-y-2">
            <AlertTriangle className="h-8 w-8 mx-auto" />
            <h3 className="text-sm font-bold">Failed to Load Analysis</h3>
            <p className="text-xs">{analysisError instanceof Error ? analysisError.message : 'Analysis record could not be retrieved from API.'}</p>
          </div>
        )}

        {/* 4. ACTIVE ANALYSIS DETAILS DISPLAY */}
        {currentAnalysisId && analysis && !isAnalysisLoading && (() => {
          const yaraState = getModuleState({
            items: analysis.yaraResults,
            sectionKey: 'yara',
            parsingStatus: analysis.parsingStatus,
            parsingWarnings: analysis.parsingWarnings,
            provenance: analysis.provenance,
          });

          const vtState = getModuleState({
            items: analysis.virusTotalResult,
            sectionKey: 'virusTotal',
            parsingStatus: analysis.parsingStatus,
            parsingWarnings: analysis.parsingWarnings,
            provenance: analysis.provenance,
          });

          const iocState = getModuleState({
            items: analysis.iocs,
            sectionKey: 'iocs',
            parsingStatus: analysis.parsingStatus,
            parsingWarnings: analysis.parsingWarnings,
            provenance: analysis.provenance,
          });

          const mitreState = getModuleState({
            items: analysis.mitreTechniques,
            sectionKey: 'mitre',
            parsingStatus: analysis.parsingStatus,
            parsingWarnings: analysis.parsingWarnings,
            provenance: analysis.provenance,
          });

          const behaviorState = getModuleState({
            items: analysis.behaviorEvents,
            sectionKey: 'behavior',
            parsingStatus: analysis.parsingStatus,
            parsingWarnings: analysis.parsingWarnings,
            provenance: analysis.provenance,
          });

          const sandboxState = getModuleState({
            items: analysis.sandboxResults,
            sectionKey: 'sandbox',
            parsingStatus: analysis.parsingStatus,
            parsingWarnings: analysis.parsingWarnings,
            provenance: analysis.provenance,
          });

          const siemState = getModuleState({
            items: analysis.siemEvents,
            sectionKey: 'siem',
            parsingStatus: analysis.parsingStatus,
            parsingWarnings: analysis.parsingWarnings,
            provenance: analysis.provenance,
          });

          return (
            <div className="space-y-6">
              {/* SECTION A: Overview Metadata */}
              <div data-testid="overview-section" className="bg-white dark:bg-[#111726] border border-slate-200 dark:border-slate-800/80 rounded-2xl p-6 shadow-sm space-y-4">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-200 dark:border-slate-800/80 pb-4">
                  <div className="flex items-center space-x-4">
                    <div className="h-12 w-12 bg-indigo-500/10 dark:bg-sky-500/10 border border-indigo-500/20 dark:border-sky-500/20 rounded-xl flex items-center justify-center text-indigo-600 dark:text-sky-400 shrink-0">
                      <FileText className="h-6 w-6" />
                    </div>
                    <div>
                      <div className="flex items-center space-x-3">
                        <h3 className="text-lg font-bold text-slate-900 dark:text-white tracking-tight">{analysis.originalFileName}</h3>
                        <span className="text-xs font-mono px-2 py-0.5 bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 rounded border border-slate-200 dark:border-slate-700">
                          {analysis.fileType}
                        </span>
                      </div>
                      <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">Analysis-Scoped SOC Dashboard &bull; ID: <span className="font-mono text-slate-800 dark:text-slate-300">{analysis.analysisId}</span></p>
                    </div>
                  </div>

                  <div className="flex items-center space-x-3">
                    <span className="text-xs font-bold text-emerald-700 dark:text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-3 py-1.5 rounded-lg flex items-center gap-1.5">
                      <ShieldCheck className="h-4 w-4" />
                      Source-of-Truth Active
                    </span>
                  </div>
                </div>

                {/* Grid Metadata */}
                <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3 text-xs">
                  <div className="bg-slate-50 dark:bg-slate-900/60 p-2.5 rounded-xl border border-slate-200 dark:border-slate-800/80">
                    <span className="text-[10px] text-slate-400 font-bold uppercase block mb-1">Analysis ID</span>
                    <span className="font-mono text-slate-800 dark:text-slate-200 truncate block" title={analysis.analysisId}>{analysis.analysisId}</span>
                  </div>
                  <div className="bg-slate-50 dark:bg-slate-900/60 p-2.5 rounded-xl border border-slate-200 dark:border-slate-800/80">
                    <span className="text-[10px] text-slate-400 font-bold uppercase block mb-1">Filename</span>
                    <span className="font-mono text-slate-800 dark:text-slate-200 truncate block" title={analysis.originalFileName}>{analysis.originalFileName}</span>
                  </div>
                  <div className="bg-slate-50 dark:bg-slate-900/60 p-2.5 rounded-xl border border-slate-200 dark:border-slate-800/80">
                    <span className="text-[10px] text-slate-400 font-bold uppercase block mb-1">File Type</span>
                    <span className="font-mono text-slate-800 dark:text-slate-200 block">{analysis.fileType}</span>
                  </div>
                  <div className="bg-slate-50 dark:bg-slate-900/60 p-2.5 rounded-xl border border-slate-200 dark:border-slate-800/80">
                    <span className="text-[10px] text-slate-400 font-bold uppercase block mb-1">File Size</span>
                    <span className="font-mono text-slate-800 dark:text-slate-200 block">{(analysis.fileSize / 1024).toFixed(1)} KB</span>
                  </div>
                  <div className="bg-slate-50 dark:bg-slate-900/60 p-2.5 rounded-xl border border-slate-200 dark:border-slate-800/80">
                    <span className="text-[10px] text-slate-400 font-bold uppercase block mb-1">Upload Time</span>
                    <span className="font-mono text-slate-800 dark:text-slate-200 truncate block" title={new Date(analysis.uploadedAt).toLocaleString()}>
                      {new Date(analysis.uploadedAt).toLocaleTimeString()}
                    </span>
                  </div>
                  <div className="bg-slate-50 dark:bg-slate-900/60 p-2.5 rounded-xl border border-slate-200 dark:border-slate-800/80">
                    <span className="text-[10px] text-slate-400 font-bold uppercase block mb-1">Host</span>
                    <span data-testid="hostname" className="font-mono text-slate-800 dark:text-slate-200 truncate block">{analysis.hostname || 'Not Available'}</span>
                  </div>
                  <div className="bg-slate-50 dark:bg-slate-900/60 p-2.5 rounded-xl border border-slate-200 dark:border-slate-800/80">
                    <span className="text-[10px] text-slate-400 font-bold uppercase block mb-1">Username</span>
                    <span data-testid="username" className="font-mono text-slate-800 dark:text-slate-200 truncate block">{analysis.username || 'Not Available'}</span>
                  </div>
                  <div className="bg-slate-50 dark:bg-slate-900/60 p-2.5 rounded-xl border border-slate-200 dark:border-slate-800/80">
                    <span className="text-[10px] text-slate-400 font-bold uppercase block mb-1">OS</span>
                    <span data-testid="operating-system" className="font-mono text-slate-800 dark:text-slate-200 truncate block">{analysis.operatingSystem || 'Not Available'}</span>
                  </div>
                </div>
              </div>

              {/* SECTION B: Risk Summary */}
              <div data-testid="risk-summary-section" className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="bg-white dark:bg-[#111726] border border-slate-200 dark:border-slate-800/80 rounded-2xl p-6 shadow-sm flex flex-col justify-between space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold uppercase tracking-wider text-slate-400">Risk Score</span>
                    <Activity className="h-4 w-4 text-indigo-600 dark:text-sky-400" />
                  </div>
                  <div>
                    {analysis.riskScore !== null && analysis.riskScore !== undefined ? (
                      <div className="flex items-baseline space-x-2">
                        <span data-testid="risk-score" className="text-4xl font-extrabold text-slate-900 dark:text-white">{analysis.riskScore}</span>
                        <span className="text-sm font-semibold text-slate-400">/ 100</span>
                      </div>
                    ) : (
                      <span data-testid="risk-score" className="text-lg font-bold text-slate-400">Not Available</span>
                    )}
                  </div>
                  <p className="text-[11px] text-slate-500">Source-provided quantitative risk metric</p>
                </div>

                <div className="bg-white dark:bg-[#111726] border border-slate-200 dark:border-slate-800/80 rounded-2xl p-6 shadow-sm flex flex-col justify-between space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold uppercase tracking-wider text-slate-400">Threat Level</span>
                    <ShieldAlert className="h-4 w-4 text-indigo-600 dark:text-sky-400" />
                  </div>
                  <div>{getThreatBadge(analysis.threatLevel)}</div>
                  <p className="text-[11px] text-slate-500">Source-provided threat severity level</p>
                </div>

                <div className="bg-white dark:bg-[#111726] border border-slate-200 dark:border-slate-800/80 rounded-2xl p-6 shadow-sm flex flex-col justify-between space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold uppercase tracking-wider text-slate-400">Analysis Status</span>
                    <CheckCircle className="h-4 w-4 text-indigo-600 dark:text-sky-400" />
                  </div>
                  <div>
                    <span className="px-3 py-1 bg-indigo-500/10 text-indigo-600 dark:bg-sky-500/20 dark:text-sky-400 border border-indigo-500/20 dark:border-sky-500/30 rounded-full font-bold text-xs uppercase tracking-wider">
                      {analysis.status || 'Not Available'}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-500">Backend analysis engine state</p>
                </div>
              </div>

              {/* SECTION C & D: File Properties & Hashes */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div data-testid="file-properties-section" className="bg-white dark:bg-[#111726] border border-slate-200 dark:border-slate-800/80 rounded-2xl p-6 shadow-sm space-y-4">
                  <div className="flex items-center space-x-2 border-b border-slate-200 dark:border-slate-800/80 pb-3">
                    <FileCode className="h-4 w-4 text-indigo-600 dark:text-sky-400" />
                    <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">File Properties</h3>
                  </div>
                  <div className="grid grid-cols-2 gap-3 text-xs">
                    <div className="p-3 bg-slate-50 dark:bg-slate-900/60 rounded-xl border border-slate-200 dark:border-slate-800/80 space-y-1">
                      <span className="text-[10px] text-slate-400 font-bold uppercase">File Name</span>
                      <p className="font-mono text-slate-800 dark:text-slate-200 truncate" title={analysis.fileName}>{analysis.fileName || 'Not Available'}</p>
                    </div>
                    <div className="p-3 bg-slate-50 dark:bg-slate-900/60 rounded-xl border border-slate-200 dark:border-slate-800/80 space-y-1">
                      <span className="text-[10px] text-slate-400 font-bold uppercase">Original File Name</span>
                      <p className="font-mono text-slate-800 dark:text-slate-200 truncate" title={analysis.originalFileName}>{analysis.originalFileName || 'Not Available'}</p>
                    </div>
                    <div className="p-3 bg-slate-50 dark:bg-slate-900/60 rounded-xl border border-slate-200 dark:border-slate-800/80 space-y-1">
                      <span className="text-[10px] text-slate-400 font-bold uppercase">File Size</span>
                      <p className="font-mono text-slate-800 dark:text-slate-200">{analysis.fileSize ? `${analysis.fileSize} bytes` : 'Not Available'}</p>
                    </div>
                    <div className="p-3 bg-slate-50 dark:bg-slate-900/60 rounded-xl border border-slate-200 dark:border-slate-800/80 space-y-1">
                      <span className="text-[10px] text-slate-400 font-bold uppercase">File Type</span>
                      <p className="font-mono text-slate-800 dark:text-slate-200">{analysis.fileType || 'Not Available'}</p>
                    </div>
                    <div className="p-3 bg-slate-50 dark:bg-slate-900/60 rounded-xl border border-slate-200 dark:border-slate-800/80 space-y-1">
                      <span className="text-[10px] text-slate-400 font-bold uppercase">Entropy</span>
                      <p data-testid="entropy" className="font-mono text-slate-800 dark:text-slate-200">
                        {analysis.fileProperties?.entropy !== null && analysis.fileProperties?.entropy !== undefined
                          ? analysis.fileProperties.entropy
                          : 'Not Available'}
                      </p>
                    </div>
                    <div className="p-3 bg-slate-50 dark:bg-slate-900/60 rounded-xl border border-slate-200 dark:border-slate-800/80 space-y-1">
                      <span className="text-[10px] text-slate-400 font-bold uppercase">Digital Signature</span>
                      <p data-testid="digital-signature" className="font-mono text-slate-800 dark:text-slate-200">
                        {analysis.fileProperties?.digitalSignature || 'Not Available'}
                      </p>
                    </div>
                    <div className="p-3 bg-slate-50 dark:bg-slate-900/60 rounded-xl border border-slate-200 dark:border-slate-800/80 space-y-1">
                      <span className="text-[10px] text-slate-400 font-bold uppercase">Packed Status</span>
                      <p data-testid="packed-status" className="font-mono text-slate-800 dark:text-slate-200">{getPackedStatus(analysis.fileProperties)}</p>
                    </div>
                    <div className="p-3 bg-slate-50 dark:bg-slate-900/60 rounded-xl border border-slate-200 dark:border-slate-800/80 space-y-1">
                      <span className="text-[10px] text-slate-400 font-bold uppercase">Packer Info</span>
                      <p data-testid="packer-info" className="font-mono text-slate-800 dark:text-slate-200">{analysis.fileProperties?.packer || 'Not Available'}</p>
                    </div>
                  </div>
                </div>

                <div data-testid="hashes-section" className="bg-white dark:bg-[#111726] border border-slate-200 dark:border-slate-800/80 rounded-2xl p-6 shadow-sm space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800/80 pb-3">
                    <div className="flex items-center space-x-2">
                      <Hash className="h-4 w-4 text-indigo-600 dark:text-sky-400" />
                      <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">Cryptographic Hashes</h3>
                    </div>
                    <span className="text-[11px] font-semibold text-slate-500">Calculated & Reported</span>
                  </div>

                  <div className="space-y-3 font-mono text-xs">
                    {analysis.fileMetadata?.calculatedSha256 && (
                      <div className="p-3 bg-indigo-50/50 dark:bg-sky-500/10 rounded-xl border border-indigo-200/60 dark:border-sky-500/30 space-y-1">
                        <span className="text-[10px] text-indigo-700 dark:text-sky-400 uppercase font-sans font-bold block">
                          Calculated SHA256 (Uploaded File Bytes)
                        </span>
                        <p data-testid="calculated-sha256-hash" className="text-slate-900 dark:text-slate-100 break-all font-bold">
                          {analysis.fileMetadata.calculatedSha256}
                        </p>
                      </div>
                    )}

                    <div className="p-3 bg-slate-50 dark:bg-slate-900/60 rounded-xl border border-slate-200 dark:border-slate-800/80 space-y-1">
                      <span className="text-[10px] text-slate-400 uppercase font-sans font-bold block">MD5 (Reported in Document)</span>
                      <p data-testid="md5-hash" className="text-slate-800 dark:text-slate-200 break-all">{analysis.hashes?.md5 || 'Not Available'}</p>
                    </div>
                    <div className="p-3 bg-slate-50 dark:bg-slate-900/60 rounded-xl border border-slate-200 dark:border-slate-800/80 space-y-1">
                      <span className="text-[10px] text-slate-400 uppercase font-sans font-bold block">SHA1 (Reported in Document)</span>
                      <p data-testid="sha1-hash" className="text-slate-800 dark:text-slate-200 break-all">{analysis.hashes?.sha1 || 'Not Available'}</p>
                    </div>
                    <div className="p-3 bg-slate-50 dark:bg-slate-900/60 rounded-xl border border-slate-200 dark:border-slate-800/80 space-y-1">
                      <span className="text-[10px] text-slate-400 uppercase font-sans font-bold block">SHA256 (Reported in Document)</span>
                      <p data-testid="sha256-hash" className="text-slate-800 dark:text-slate-200 break-all">{analysis.hashes?.sha256 || 'Not Available'}</p>
                    </div>
                  </div>
                </div>
              </div>

              {/* SECTION: Parsing Details & Source Provenance */}
              <div data-testid="parsing-details-section" className="bg-white dark:bg-[#111726] border border-slate-200 dark:border-slate-800/80 rounded-2xl p-6 shadow-sm space-y-4">
                <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800/80 pb-3">
                  <div className="flex items-center space-x-2">
                    <Terminal className="h-4 w-4 text-indigo-600 dark:text-sky-400" />
                    <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">Parsing Details & Data Provenance</h3>
                  </div>
                  <span className={`text-xs font-bold px-2.5 py-0.5 rounded-full border ${
                    analysis.parsingStatus === 'COMPLETED'
                      ? 'bg-emerald-500/10 text-emerald-600 border-emerald-500/30 dark:text-emerald-400'
                      : 'bg-amber-500/10 text-amber-600 border-amber-500/30 dark:text-amber-400'
                  }`}>
                    Status: {analysis.parsingStatus || 'COMPLETED'}
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-sans">
                  <div className="p-3 bg-slate-50 dark:bg-slate-900/60 rounded-xl border border-slate-200 dark:border-slate-800/80 space-y-2">
                    <span className="text-[10px] text-slate-400 font-bold uppercase block">Source Provenance</span>
                    <div className="space-y-1 font-mono text-[11px] text-slate-700 dark:text-slate-300">
                      <p><span className="text-slate-400">Parser Used:</span> {analysis.provenance?.parser || 'Multi-Format Ingestion Engine'}</p>
                      <p><span className="text-slate-400">Detected Format:</span> {analysis.fileType}</p>
                      <p><span className="text-slate-400">Source Disk File:</span> {analysis.fileMetadata?.filePath || 'Preserved in /uploads'}</p>
                      {analysis.fileMetadata?.calculatedSha256 && (
                        <p><span className="text-slate-400">File SHA256:</span> {analysis.fileMetadata.calculatedSha256}</p>
                      )}
                    </div>
                  </div>

                  <div className="p-3 bg-slate-50 dark:bg-slate-900/60 rounded-xl border border-slate-200 dark:border-slate-800/80 space-y-2">
                    <span className="text-[10px] text-slate-400 font-bold uppercase block">Parsing Warnings & Retained Fields</span>
                    {analysis.parsingWarnings && analysis.parsingWarnings.length > 0 ? (
                      <ul className="list-disc list-inside text-amber-600 dark:text-amber-400 font-mono text-[11px] space-y-1">
                        {analysis.parsingWarnings.map((w, idx) => (
                          <li key={idx}>{w}</li>
                        ))}
                      </ul>
                    ) : (
                      <p className="text-slate-500 dark:text-slate-400 text-xs italic">No parsing warnings recorded. All structures cleanly parsed.</p>
                    )}

                    {analysis.unrecognizedFields && (
                      <div className="mt-2 pt-2 border-t border-slate-200 dark:border-slate-800">
                        <span className="text-[10px] text-slate-400 font-bold uppercase block mb-1">Preserved Source Unmapped Fields</span>
                        <pre className="p-2 bg-slate-900 text-sky-400 rounded-lg font-mono text-[10px] overflow-x-auto max-h-32">
                          {JSON.stringify(analysis.unrecognizedFields, null, 2)}
                        </pre>
                      </div>
                    )}
                  </div>
                </div>
              </div>

              {/* SECTION E & F: YARA & VirusTotal */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div data-testid="yara-section" className="bg-white dark:bg-[#111726] border border-slate-200 dark:border-slate-800/80 rounded-2xl p-6 shadow-sm space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800/80 pb-3">
                    <div className="flex items-center space-x-2">
                      <ShieldAlert className="h-4 w-4 text-indigo-600 dark:text-sky-400" />
                      <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">YARA Rules</h3>
                    </div>
                    <span className="text-xs text-slate-500 dark:text-slate-400">{yaraState.badgeText}</span>
                  </div>

                  {yaraState.isAvailable ? (
                    <div data-testid="yara-rules" className="space-y-2">
                      {analysis.yaraResults!.map((yara) => (
                        <div key={yara.id} className="p-3 bg-slate-50 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800/80 rounded-xl space-y-1 text-xs">
                          <div className="flex items-center justify-between">
                            <span className="font-bold text-rose-600 dark:text-rose-400 font-mono">{yara.ruleName}</span>
                            <span className="text-[10px] font-mono text-slate-500 dark:text-slate-400">
                              Severity: {(yara as any).severity || 'Not Available'}
                            </span>
                          </div>
                          <p className="text-[11px] text-slate-600 dark:text-slate-300">{yara.description || 'Not Available'}</p>
                        </div>
                      ))}
                    </div>
                  ) : yaraState.isConfirmedEmpty ? (
                    <p className="text-xs text-slate-400 italic font-mono">0 matches (Source confirmed clean)</p>
                  ) : yaraState.isParsingIncomplete ? (
                    <p className="text-xs text-amber-500 italic font-mono">Parsing incomplete for YARA rules</p>
                  ) : (
                    <p className="text-xs text-slate-400 italic">Not Available</p>
                  )}
                </div>

                <div data-testid="virustotal-section" className="bg-white dark:bg-[#111726] border border-slate-200 dark:border-slate-800/80 rounded-2xl p-6 shadow-sm space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800/80 pb-3">
                    <div className="flex items-center space-x-2">
                      <Globe className="h-4 w-4 text-indigo-600 dark:text-sky-400" />
                      <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">VirusTotal Intelligence</h3>
                    </div>
                    <span className="text-xs text-slate-500 dark:text-slate-400">{vtState.badgeText}</span>
                  </div>

                  {vtState.isAvailable ? (
                    <div className="grid grid-cols-2 gap-3 text-xs">
                      <div className="p-3 bg-slate-50 dark:bg-slate-900/60 rounded-xl border border-slate-200 dark:border-slate-800/80 space-y-1">
                        <span className="text-[10px] text-slate-400 font-bold uppercase">Detection Ratio</span>
                        <p data-testid="virustotal-ratio" className="font-mono text-slate-900 dark:text-slate-100 font-bold text-sm">
                          {analysis.virusTotalResult!.positives} / {analysis.virusTotalResult!.total}
                        </p>
                      </div>
                      <div className="p-3 bg-slate-50 dark:bg-slate-900/60 rounded-xl border border-slate-200 dark:border-slate-800/80 space-y-1">
                        <span className="text-[10px] text-slate-400 font-bold uppercase">Verdict</span>
                        <p className="font-mono text-slate-800 dark:text-slate-200">
                          {(analysis.virusTotalResult as any).verdict || (analysis.virusTotalResult!.positives > 0 ? 'MALICIOUS' : 'CLEAN')}
                        </p>
                      </div>
                      <div className="p-3 bg-slate-50 dark:bg-slate-900/60 rounded-xl border border-slate-200 dark:border-slate-800/80 space-y-1">
                        <span className="text-[10px] text-slate-400 font-bold uppercase">Threat Category</span>
                        <p className="font-mono text-slate-800 dark:text-slate-200">
                          {(analysis.virusTotalResult as any).threatCategory || (analysis.virusTotalResult as any).threatName || 'Not Available'}
                        </p>
                      </div>
                      <div className="p-3 bg-slate-50 dark:bg-slate-900/60 rounded-xl border border-slate-200 dark:border-slate-800/80 space-y-1">
                        <span className="text-[10px] text-slate-400 font-bold uppercase">Severity</span>
                        <p className="font-mono text-slate-800 dark:text-slate-200">
                          {(analysis.virusTotalResult as any).severity || 'Not Available'}
                        </p>
                      </div>
                    </div>
                  ) : vtState.isConfirmedEmpty ? (
                    <p className="text-xs text-slate-400 italic font-mono">Confirmed clean (0 detections)</p>
                  ) : vtState.isParsingIncomplete ? (
                    <p className="text-xs text-amber-500 italic font-mono">Parsing incomplete for VirusTotal data</p>
                  ) : (
                    <p className="text-xs text-slate-400 italic">Not Available</p>
                  )}
                </div>
              </div>

              {/* SECTION G: IOC Summary */}
              <div data-testid="ioc-section" className="bg-white dark:bg-[#111726] border border-slate-200 dark:border-slate-800/80 rounded-2xl p-6 shadow-sm space-y-4">
                <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800/80 pb-3">
                  <div className="flex items-center space-x-2">
                    <Layers className="h-4 w-4 text-indigo-600 dark:text-sky-400" />
                    <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">Indicators of Compromise (IOC Summary)</h3>
                  </div>
                  <span className="text-xs text-slate-500 dark:text-slate-400">{iocState.badgeText}</span>
                </div>

                {iocState.isAvailable ? (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs">
                      <thead className="bg-slate-50 dark:bg-slate-900/60 text-slate-500 dark:text-slate-400 uppercase text-[10px] font-bold">
                        <tr>
                          <th className="p-3">Type</th>
                          <th className="p-3">Value</th>
                          <th className="p-3">Category</th>
                          <th className="p-3">Confidence</th>
                          <th className="p-3">Description</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-200 dark:divide-slate-800/60 font-mono text-slate-700 dark:text-slate-300">
                        {analysis.iocs!.map((ioc) => (
                          <tr key={ioc.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/30">
                            <td className="p-3">
                              <span className="px-2 py-0.5 rounded bg-indigo-50 dark:bg-sky-500/10 text-indigo-600 dark:text-sky-400 font-sans font-bold text-[10px]">
                                {ioc.type}
                              </span>
                            </td>
                            <td className="p-3 text-slate-900 dark:text-slate-100">{ioc.value}</td>
                            <td className="p-3 font-sans text-slate-500 dark:text-slate-400">{ioc.category || 'Not Available'}</td>
                            <td className="p-3 font-sans text-slate-500 dark:text-slate-400">
                              {ioc.confidence !== null && ioc.confidence !== undefined ? `${ioc.confidence}%` : 'Not Available'}
                            </td>
                            <td className="p-3 font-sans text-slate-500 dark:text-slate-400">{ioc.description || 'Not Available'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : iocState.isConfirmedEmpty ? (
                  <p className="text-xs text-slate-400 italic font-mono">0 indicators (Source confirmed empty)</p>
                ) : iocState.isParsingIncomplete ? (
                  <p className="text-xs text-amber-500 italic font-mono">Parsing incomplete for IOCs</p>
                ) : (
                  <p className="text-xs text-slate-400 italic">Not Available</p>
                )}
              </div>

              {/* SECTION H & I: MITRE & Behavior */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div data-testid="mitre-section" className="bg-white dark:bg-[#111726] border border-slate-200 dark:border-slate-800/80 rounded-2xl p-6 shadow-sm space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800/80 pb-3">
                    <div className="flex items-center space-x-2">
                      <Crosshair className="h-4 w-4 text-indigo-600 dark:text-sky-400" />
                      <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">MITRE ATT&CK Techniques</h3>
                    </div>
                    <span className="text-xs text-slate-500 dark:text-slate-400">{mitreState.badgeText}</span>
                  </div>

                  {mitreState.isAvailable ? (
                    <div className="space-y-2">
                      {analysis.mitreTechniques!.map((mitre) => (
                        <div key={mitre.id} className="p-3 bg-slate-50 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800/80 rounded-xl flex justify-between items-center text-xs">
                          <div>
                            <span className="font-bold text-amber-600 dark:text-amber-400 font-mono mr-2">{mitre.techniqueId}</span>
                            <span className="text-slate-800 dark:text-slate-200">{mitre.name}</span>
                          </div>
                          <span className="text-[10px] text-slate-500 dark:text-slate-400 font-sans">{mitre.tactic || 'Not Available'}</span>
                        </div>
                      ))}
                    </div>
                  ) : mitreState.isConfirmedEmpty ? (
                    <p className="text-xs text-slate-400 italic font-mono">0 techniques (Source confirmed empty)</p>
                  ) : mitreState.isParsingIncomplete ? (
                    <p className="text-xs text-amber-500 italic font-mono">Parsing incomplete for MITRE techniques</p>
                  ) : (
                    <p className="text-xs text-slate-400 italic">Not Available</p>
                  )}
                </div>

                <div data-testid="behavior-section" className="bg-white dark:bg-[#111726] border border-slate-200 dark:border-slate-800/80 rounded-2xl p-6 shadow-sm space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800/80 pb-3">
                    <div className="flex items-center space-x-2">
                      <Activity className="h-4 w-4 text-indigo-600 dark:text-sky-400" />
                      <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">Behavior Events</h3>
                    </div>
                    <span className="text-xs text-slate-500 dark:text-slate-400">{behaviorState.badgeText}</span>
                  </div>

                  {behaviorState.isAvailable ? (
                    <div className="space-y-2 text-xs font-mono max-h-60 overflow-y-auto">
                      {analysis.behaviorEvents!.map((bev) => (
                        <div key={bev.id} className="p-3 bg-slate-50 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800/80 rounded-xl space-y-1">
                          <div className="flex justify-between text-[10px] text-slate-500 dark:text-slate-400 font-sans">
                            <span className="font-bold text-indigo-600 dark:text-sky-400 uppercase">{bev.eventType}</span>
                            <span>{bev.timestamp ? new Date(bev.timestamp).toLocaleString() : '—'}</span>
                          </div>
                          <p className="text-slate-800 dark:text-slate-200 font-bold">{bev.action}: <span className="text-slate-600 dark:text-slate-400 font-normal">{bev.target}</span></p>
                          {bev.details && <p className="text-[11px] text-slate-500 dark:text-slate-400 font-sans">{bev.details}</p>}
                        </div>
                      ))}
                    </div>
                  ) : behaviorState.isConfirmedEmpty ? (
                    <p className="text-xs text-slate-400 italic font-mono">0 events (Source confirmed empty)</p>
                  ) : behaviorState.isParsingIncomplete ? (
                    <p className="text-xs text-amber-500 italic font-mono">Parsing incomplete for behavior events</p>
                  ) : (
                    <p className="text-xs text-slate-400 italic">Not Available</p>
                  )}
                </div>
              </div>

              {/* SECTION J & K: Sandbox & SIEM */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div data-testid="sandbox-section" className="bg-white dark:bg-[#111726] border border-slate-200 dark:border-slate-800/80 rounded-2xl p-6 shadow-sm space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800/80 pb-3">
                    <div className="flex items-center space-x-2">
                      <Database className="h-4 w-4 text-indigo-600 dark:text-sky-400" />
                      <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">Sandbox Results</h3>
                    </div>
                    <span className="text-xs text-slate-500 dark:text-slate-400">{sandboxState.badgeText}</span>
                  </div>

                  {sandboxState.isAvailable ? (
                    <div className="space-y-2">
                      {analysis.sandboxResults!.map((sb) => (
                        <div key={sb.id} className="p-3 bg-slate-50 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800/80 rounded-xl flex justify-between items-center text-xs">
                          <div>
                            <span className="font-bold text-slate-800 dark:text-slate-200 font-sans">{sb.sandboxName}</span>
                            <span className="block text-[10px] text-slate-500 dark:text-slate-400 font-mono">Verdict: {sb.verdict}</span>
                          </div>
                          <span className="text-xs font-bold text-amber-600 dark:text-amber-400 font-mono">
                            Score: {sb.score !== null && sb.score !== undefined ? sb.score : 'Not Available'}
                          </span>
                        </div>
                      ))}
                    </div>
                  ) : sandboxState.isConfirmedEmpty ? (
                    <p className="text-xs text-slate-400 italic font-mono">0 runs (Source confirmed empty)</p>
                  ) : sandboxState.isParsingIncomplete ? (
                    <p className="text-xs text-amber-500 italic font-mono">Parsing incomplete for sandbox results</p>
                  ) : (
                    <p className="text-xs text-slate-400 italic">Not Available</p>
                  )}
                </div>

                <div data-testid="siem-section" className="bg-white dark:bg-[#111726] border border-slate-200 dark:border-slate-800/80 rounded-2xl p-6 shadow-sm space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800/80 pb-3">
                    <div className="flex items-center space-x-2">
                      <Terminal className="h-4 w-4 text-indigo-600 dark:text-sky-400" />
                      <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">SIEM Summary</h3>
                    </div>
                    <span className="text-xs text-slate-500 dark:text-slate-400">{siemState.badgeText}</span>
                  </div>

                  {siemState.isAvailable ? (
                    <div className="space-y-2 font-mono text-xs max-h-60 overflow-y-auto">
                      {analysis.siemEvents!.map((ev) => (
                        <div key={ev.id} className="p-3 bg-slate-50 dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800/80 rounded-xl space-y-1">
                          <div className="flex items-center justify-between text-[10px] text-slate-500 dark:text-slate-400 font-sans border-b border-slate-200 dark:border-slate-800/50 pb-1 mb-1">
                            <span>{ev.timestamp ? new Date(ev.timestamp).toLocaleString() : 'Not Available'}</span>
                            <span className="text-amber-600 dark:text-amber-400 font-bold uppercase">{ev.severity || 'Not Available'}</span>
                          </div>
                          <p className="text-slate-800 dark:text-slate-300 break-all">{ev.rawEvent}</p>
                        </div>
                      ))}
                    </div>
                  ) : siemState.isConfirmedEmpty ? (
                    <p className="text-xs text-slate-400 italic font-mono">0 events (Source confirmed empty)</p>
                  ) : siemState.isParsingIncomplete ? (
                    <p className="text-xs text-amber-500 italic font-mono">Parsing incomplete for SIEM events</p>
                  ) : (
                    <p className="text-xs text-slate-400 italic">Not Available</p>
                  )}
                </div>
              </div>
            </div>
          );
        })()}
      </div>
    </div>
  );
}
