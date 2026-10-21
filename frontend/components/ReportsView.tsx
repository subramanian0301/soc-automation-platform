'use client';

import React, { useState } from 'react';
import { useAnalysisContext } from '@/context/AnalysisContext';
import { useQuery } from '@tanstack/react-query';
import {
  fetchAnalysisReport,
  fetchEnterpriseAnalytics,
  downloadReportFile,
  EnterpriseAnalyticsResponse,
} from '@/lib/api';
import { PageHeader } from '@/components/ui/PageHeader';
import { EmptyState } from '@/components/ui/EmptyState';
import {
  FileText,
  Download,
  BarChart3,
  ShieldAlert,
  Terminal,
  Bug,
  Server,
  Zap,
  FileSpreadsheet,
} from 'lucide-react';

interface ReportsViewProps {
  onOpenUpload?: () => void;
}

export type ReportCategory =
  | 'analysis-summary'
  | 'security-findings'
  | 'incidents-cases'
  | 'assets-endpoints'
  | 'vulnerabilities'
  | 'soar-activity'
  | 'enterprise-analytics';

export function ReportsView({ onOpenUpload }: ReportsViewProps) {
  const { currentAnalysisId } = useAnalysisContext();
  const [selectedCategory, setSelectedCategory] = useState<ReportCategory>('analysis-summary');

  const isEnterprise = selectedCategory === 'enterprise-analytics';

  // Analysis-scoped report query
  const {
    data: reportData,
    isLoading: isReportLoading,
    error: reportError,
  } = useQuery({
    queryKey: ['analysis', currentAnalysisId, 'reports', selectedCategory],
    queryFn: () => fetchAnalysisReport(currentAnalysisId!, selectedCategory),
    enabled: Boolean(currentAnalysisId) && !isEnterprise,
  });

  // Enterprise analytics query
  const {
    data: enterpriseData,
    isLoading: isEnterpriseLoading,
    error: enterpriseError,
  } = useQuery<EnterpriseAnalyticsResponse>({
    queryKey: ['analytics', 'enterprise'],
    queryFn: fetchEnterpriseAnalytics,
    enabled: isEnterprise,
  });

  const [exportingFormat, setExportingFormat] = useState<'pdf' | 'csv' | null>(null);

  const handleExport = async (format: 'pdf' | 'csv') => {
    if (!currentAnalysisId || isEnterprise || exportingFormat) return;
    try {
      setExportingFormat(format);
      await downloadReportFile(currentAnalysisId, selectedCategory, format);
    } catch (err: any) {
      console.error('Failed to export report:', err);
      alert(`Report export failed: ${err.message || 'Unknown error'}`);
    } finally {
      setExportingFormat(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <PageHeader
        title="Report Center & Enterprise Analytics"
        description={
          isEnterprise
            ? 'Enterprise-wide historical records aggregate'
            : `Analysis-scoped report engine for ID: ${currentAnalysisId || 'None Selected'}`
        }
        badge={isEnterprise ? 'Enterprise Scope' : 'Analysis Scope'}
      >
        {!isEnterprise && currentAnalysisId && (
          <div className="flex items-center space-x-3">
            <button
              onClick={() => handleExport('pdf')}
              disabled={exportingFormat !== null}
              className="flex items-center space-x-2 px-3.5 py-2 bg-rose-600 hover:bg-rose-700 disabled:opacity-50 text-white rounded-xl font-semibold text-xs transition shadow-sm active:scale-95"
            >
              <Download className={`h-4 w-4 ${exportingFormat === 'pdf' ? 'animate-bounce' : ''}`} />
              <span>{exportingFormat === 'pdf' ? 'Exporting...' : 'Export PDF'}</span>
            </button>
            <button
              onClick={() => handleExport('csv')}
              disabled={exportingFormat !== null}
              className="flex items-center space-x-2 px-3.5 py-2 bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white rounded-xl font-semibold text-xs transition shadow-sm active:scale-95"
            >
              <FileSpreadsheet className={`h-4 w-4 ${exportingFormat === 'csv' ? 'animate-bounce' : ''}`} />
              <span>{exportingFormat === 'csv' ? 'Exporting...' : 'Export CSV'}</span>
            </button>
          </div>
        )}
      </PageHeader>

      {/* Category Tabs */}
      <div className="flex items-center space-x-2 border-b border-slate-200 dark:border-slate-800/80 pb-3 overflow-x-auto">
        <button
          onClick={() => setSelectedCategory('analysis-summary')}
          className={`flex items-center space-x-2 px-3.5 py-2 rounded-xl text-xs font-semibold transition ${
            selectedCategory === 'analysis-summary'
              ? 'bg-indigo-600 text-white dark:bg-sky-500/20 dark:text-sky-400 border border-indigo-600 dark:border-sky-500/30'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          <FileText className="h-4 w-4" />
          <span>Analysis Summary</span>
        </button>

        <button
          onClick={() => setSelectedCategory('security-findings')}
          className={`flex items-center space-x-2 px-3.5 py-2 rounded-xl text-xs font-semibold transition ${
            selectedCategory === 'security-findings'
              ? 'bg-indigo-600 text-white dark:bg-sky-500/20 dark:text-sky-400 border border-indigo-600 dark:border-sky-500/30'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          <ShieldAlert className="h-4 w-4" />
          <span>Security Findings</span>
        </button>

        <button
          onClick={() => setSelectedCategory('incidents-cases')}
          className={`flex items-center space-x-2 px-3.5 py-2 rounded-xl text-xs font-semibold transition ${
            selectedCategory === 'incidents-cases'
              ? 'bg-indigo-600 text-white dark:bg-sky-500/20 dark:text-sky-400 border border-indigo-600 dark:border-sky-500/30'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          <Terminal className="h-4 w-4" />
          <span>Incidents & Cases</span>
        </button>

        <button
          onClick={() => setSelectedCategory('assets-endpoints')}
          className={`flex items-center space-x-2 px-3.5 py-2 rounded-xl text-xs font-semibold transition ${
            selectedCategory === 'assets-endpoints'
              ? 'bg-indigo-600 text-white dark:bg-sky-500/20 dark:text-sky-400 border border-indigo-600 dark:border-sky-500/30'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          <Server className="h-4 w-4" />
          <span>Assets & Endpoints</span>
        </button>

        <button
          onClick={() => setSelectedCategory('vulnerabilities')}
          className={`flex items-center space-x-2 px-3.5 py-2 rounded-xl text-xs font-semibold transition ${
            selectedCategory === 'vulnerabilities'
              ? 'bg-indigo-600 text-white dark:bg-sky-500/20 dark:text-sky-400 border border-indigo-600 dark:border-sky-500/30'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          <Bug className="h-4 w-4" />
          <span>Vulnerabilities</span>
        </button>

        <button
          onClick={() => setSelectedCategory('soar-activity')}
          className={`flex items-center space-x-2 px-3.5 py-2 rounded-xl text-xs font-semibold transition ${
            selectedCategory === 'soar-activity'
              ? 'bg-indigo-600 text-white dark:bg-sky-500/20 dark:text-sky-400 border border-indigo-600 dark:border-sky-500/30'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          <Zap className="h-4 w-4" />
          <span>SOAR Activity</span>
        </button>

        <button
          onClick={() => setSelectedCategory('enterprise-analytics')}
          className={`flex items-center space-x-2 px-3.5 py-2 rounded-xl text-xs font-semibold transition ${
            selectedCategory === 'enterprise-analytics'
              ? 'bg-emerald-600 text-white dark:bg-emerald-500/20 dark:text-emerald-400 border border-emerald-600 dark:border-emerald-500/30'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          <BarChart3 className="h-4 w-4" />
          <span>Enterprise Analytics</span>
        </button>
      </div>

      {/* Main Body */}
      {isEnterprise ? (
        isEnterpriseLoading ? (
          <div className="p-12 text-center bg-white dark:bg-[#111726] rounded-xl border border-slate-200 dark:border-slate-800">
            <div className="flex items-center justify-center space-x-3">
              <div className="w-5 h-5 border-2 border-emerald-600 border-t-transparent rounded-full animate-spin" />
              <span className="text-xs font-mono text-slate-500 dark:text-slate-400">Computing Enterprise Analytics...</span>
            </div>
          </div>
        ) : enterpriseError ? (
          <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-700 dark:text-rose-400 text-xs">
            Failed to load enterprise analytics: {(enterpriseError as Error).message}
          </div>
        ) : enterpriseData ? (
          <div className="space-y-6">
            <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-800 dark:text-emerald-300 text-xs flex flex-col sm:flex-row justify-between sm:items-center gap-2">
              <div>
                <span className="font-bold">Scope: {enterpriseData.scope}</span>
                <p className="text-[11px] text-emerald-700 dark:text-emerald-400/80">
                  All stored historical analyses in MySQL database. Calculated dynamically without fabrication.
                </p>
              </div>
              <span className="font-mono text-[11px] text-emerald-600 dark:text-emerald-400 shrink-0">
                Generated: {new Date(enterpriseData.generatedAt).toLocaleString()}
              </span>
            </div>

            {/* High Level Counts */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
              <div className="bg-white dark:bg-[#111726] border border-slate-200 dark:border-slate-800 p-4 rounded-xl shadow-sm">
                <span className="text-slate-500 dark:text-slate-400 block text-[11px] font-semibold mb-1">Total Stored Analyses</span>
                <span className="text-2xl font-bold text-slate-900 dark:text-slate-100">{enterpriseData.totalAnalyses}</span>
              </div>
              <div className="bg-white dark:bg-[#111726] border border-slate-200 dark:border-slate-800 p-4 rounded-xl shadow-sm">
                <span className="text-slate-500 dark:text-slate-400 block text-[11px] font-semibold mb-1">Total Incidents & Cases</span>
                <span className="text-xl font-bold text-slate-900 dark:text-slate-100">
                  {enterpriseData.counts.incidents} Incidents / {enterpriseData.counts.cases} Cases
                </span>
              </div>
              <div className="bg-white dark:bg-[#111726] border border-slate-200 dark:border-slate-800 p-4 rounded-xl shadow-sm">
                <span className="text-slate-500 dark:text-slate-400 block text-[11px] font-semibold mb-1">Total Vulnerabilities</span>
                <span className="text-2xl font-bold text-slate-900 dark:text-slate-100">{enterpriseData.counts.vulnerabilities}</span>
              </div>
              <div className="bg-white dark:bg-[#111726] border border-slate-200 dark:border-slate-800 p-4 rounded-xl shadow-sm">
                <span className="text-slate-500 dark:text-slate-400 block text-[11px] font-semibold mb-1">Assets & Endpoints</span>
                <span className="text-xl font-bold text-slate-900 dark:text-slate-100">
                  {enterpriseData.counts.assets} Assets / {enterpriseData.counts.endpoints} Endpoints
                </span>
              </div>
            </div>

            {/* Distributions */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="bg-white dark:bg-[#111726] border border-slate-200 dark:border-slate-800 p-5 rounded-xl shadow-sm space-y-3">
                <h3 className="text-sm font-bold text-slate-900 dark:text-slate-200">Risk Score Distribution</h3>
                <div className="space-y-2 text-xs">
                  <div className="flex justify-between text-slate-700 dark:text-slate-300">
                    <span>Critical (86-100)</span>
                    <span className="font-bold text-rose-600 dark:text-rose-400">{enterpriseData.riskScoreDistribution.critical}</span>
                  </div>
                  <div className="flex justify-between text-slate-700 dark:text-slate-300">
                    <span>High (51-85)</span>
                    <span className="font-bold text-amber-600 dark:text-amber-400">{enterpriseData.riskScoreDistribution.high}</span>
                  </div>
                  <div className="flex justify-between text-slate-700 dark:text-slate-300">
                    <span>Medium (21-50)</span>
                    <span className="font-bold text-indigo-600 dark:text-sky-400">{enterpriseData.riskScoreDistribution.medium}</span>
                  </div>
                  <div className="flex justify-between text-slate-700 dark:text-slate-300">
                    <span>Low (0-20)</span>
                    <span className="font-bold text-emerald-600 dark:text-emerald-400">{enterpriseData.riskScoreDistribution.low}</span>
                  </div>
                  <div className="flex justify-between text-slate-400">
                    <span>Missing / Not Available</span>
                    <span>{enterpriseData.riskScoreDistribution.missing}</span>
                  </div>
                </div>
              </div>

              <div className="bg-white dark:bg-[#111726] border border-slate-200 dark:border-slate-800 p-5 rounded-xl shadow-sm space-y-3">
                <h3 className="text-sm font-bold text-slate-900 dark:text-slate-200">SOAR Activity Breakdown</h3>
                <div className="space-y-2 text-xs">
                  <div className="flex justify-between text-slate-700 dark:text-slate-300">
                    <span>Simulations (Dry Runs)</span>
                    <span className="font-bold text-indigo-600 dark:text-sky-400">{enterpriseData.soarStatusBreakdown.simulations}</span>
                  </div>
                  <div className="flex justify-between text-slate-700 dark:text-slate-300">
                    <span>Executed Actions</span>
                    <span className="font-bold text-emerald-600 dark:text-emerald-400">{enterpriseData.soarStatusBreakdown.completed}</span>
                  </div>
                  <div className="flex justify-between text-slate-400">
                    <span>Other / Pending</span>
                    <span>{enterpriseData.soarStatusBreakdown.other}</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        ) : null
      ) : !currentAnalysisId ? (
        <EmptyState
          icon={<FileText className="w-8 h-8 text-indigo-600 dark:text-sky-400" />}
          title="No Active Analysis Selected"
          description="Select an active analysis from the header dropdown or upload a file to generate analysis-scoped security reports."
          action={
            onOpenUpload
              ? {
                  label: 'Upload New File',
                  onClick: onOpenUpload,
                }
              : undefined
          }
        />
      ) : isReportLoading ? (
        <div className="p-12 text-center bg-white dark:bg-[#111726] rounded-xl border border-slate-200 dark:border-slate-800">
          <div className="flex items-center justify-center space-x-3">
            <div className="w-5 h-5 border-2 border-indigo-600 dark:border-sky-400 border-t-transparent rounded-full animate-spin" />
            <span className="text-xs font-mono text-slate-500 dark:text-slate-400">Generating Report...</span>
          </div>
        </div>
      ) : reportError ? (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-700 dark:text-rose-400 text-xs">
          Failed to generate report: {(reportError as Error).message}
        </div>
      ) : reportData ? (
        <div className="bg-white dark:bg-[#111726] border border-slate-200 dark:border-slate-800 rounded-xl p-6 space-y-6 shadow-sm">
          <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800/80 pb-4">
            <div>
              <h2 className="text-base font-bold text-slate-900 dark:text-slate-100 uppercase tracking-wider">
                {reportData.reportType}
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Generated At: {new Date(reportData.generatedAt).toLocaleString()}
              </p>
            </div>
            <span className="text-xs px-2.5 py-1 rounded bg-indigo-50 dark:bg-sky-500/10 text-indigo-600 dark:text-sky-400 border border-indigo-200 dark:border-sky-500/20 font-mono">
              {currentAnalysisId}
            </span>
          </div>

          <div className="bg-slate-50 dark:bg-slate-950 p-4 rounded-lg border border-slate-200 dark:border-slate-800/80 overflow-x-auto">
            <pre className="text-xs text-slate-800 dark:text-slate-300 font-mono leading-relaxed">
              {JSON.stringify(reportData, null, 2)}
            </pre>
          </div>
        </div>
      ) : null}
    </div>
  );
}
