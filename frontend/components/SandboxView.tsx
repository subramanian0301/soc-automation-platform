'use client';

import React from 'react';
import { useAnalysisContext } from '@/context/AnalysisContext';
import { fetchAnalysisSandbox, SandboxResponse } from '@/lib/api';
import { useQuery } from '@tanstack/react-query';
import {
  Database,
  AlertTriangle,
  Upload,
  Layers,
  CheckCircle,
} from 'lucide-react';

interface SandboxViewProps {
  onOpenUpload: () => void;
}

export function SandboxView({ onOpenUpload }: SandboxViewProps) {
  const { currentAnalysisId } = useAnalysisContext();

  const {
    data: sandboxData,
    isLoading,
    isError,
    error,
    refetch,
  } = useQuery<SandboxResponse>({
    queryKey: ['analysis', currentAnalysisId, 'sandbox'],
    queryFn: () => fetchAnalysisSandbox(currentAnalysisId!),
    enabled: Boolean(currentAnalysisId),
  });

  // 1. EMPTY STATE: currentAnalysisId === null
  if (!currentAnalysisId) {
    return (
      <div
        data-testid="no-analysis-state"
        className="flex-1 flex flex-col items-center justify-center p-12 text-center bg-[#0a0d14]"
      >
        <div className="max-w-md w-full bg-[#111726] border border-slate-800 rounded-2xl p-8 shadow-2xl space-y-6">
          <div className="h-16 w-16 bg-sky-500/10 border border-sky-500/20 rounded-2xl flex items-center justify-center text-sky-400 mx-auto shadow-inner">
            <Database className="h-8 w-8" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-slate-100">No Active Analysis Selected</h2>
            <p className="text-xs text-slate-400 mt-2 leading-relaxed">
              Select an active security analysis from the top dropdown or upload a file to view Sandbox Analysis results.
            </p>
          </div>
          <button
            onClick={onOpenUpload}
            className="w-full bg-sky-600 hover:bg-sky-500 text-white font-medium text-xs py-3 rounded-xl transition shadow-lg shadow-sky-600/20 flex items-center justify-center space-x-2"
          >
            <Upload className="h-4 w-4" />
            <span>Upload Analysis File</span>
          </button>
        </div>
      </div>
    );
  }

  // 2. LOADING STATE
  if (isLoading) {
    return (
      <div
        data-testid="loading-state"
        className="flex-1 flex items-center justify-center p-12 bg-[#0a0d14]"
      >
        <div className="flex flex-col items-center space-y-3">
          <div className="h-10 w-10 border-4 border-sky-500/30 border-t-sky-500 rounded-full animate-spin" />
          <p className="text-xs font-mono text-slate-400">Loading Sandbox results for {currentAnalysisId}...</p>
        </div>
      </div>
    );
  }

  // 3. ERROR STATE
  if (isError || !sandboxData) {
    return (
      <div
        data-testid="error-state"
        className="flex-1 flex items-center justify-center p-12 bg-[#0a0d14]"
      >
        <div className="bg-rose-500/10 border border-rose-500/20 rounded-2xl p-6 text-center max-w-md text-rose-300 space-y-4">
          <AlertTriangle className="h-8 w-8 text-rose-400 mx-auto" />
          <div>
            <h3 className="text-sm font-bold">Failed to Load Sandbox Results</h3>
            <p className="text-xs mt-1">{error instanceof Error ? error.message : 'Sandbox results could not be retrieved.'}</p>
          </div>
          <button
            onClick={() => refetch()}
            className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white font-medium text-xs rounded-xl transition flex items-center justify-center space-x-2 mx-auto"
          >
            <Database className="h-3.5 w-3.5" />
            <span>Retry Request</span>
          </button>
        </div>
      </div>
    );
  }

  const results = sandboxData.results || [];

  return (
    <div data-testid="sandbox-view" className="flex-1 p-6 md:p-8 bg-[#0a0d14] text-slate-100 overflow-y-auto space-y-6">
      
      {/* Header Bar */}
      <div className="bg-[#111726] border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div className="flex items-center space-x-3">
            <div className="h-10 w-10 bg-sky-500/10 border border-sky-500/20 rounded-xl flex items-center justify-center text-sky-400 shadow-inner">
              <Database className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white tracking-tight">Sandbox Analysis Execution</h2>
              <p className="text-xs text-slate-400">Persisted Sandbox Results &bull; ID: <span className="font-mono text-slate-300">{currentAnalysisId}</span></p>
            </div>
          </div>

          <div className="flex items-center space-x-3">
            <span className="text-xs font-bold text-sky-400 bg-sky-500/10 border border-sky-500/20 px-3 py-1.5 rounded-lg flex items-center gap-2 font-mono">
              <Layers className="h-4 w-4" />
              <span>{sandboxData.totalCount} Sandbox Runs</span>
            </span>
          </div>
        </div>
      </div>

      {/* Results Cards Grid */}
      <div className="bg-[#111726] border border-slate-800 rounded-2xl p-6 shadow-lg space-y-4">
        {results.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            {results.map((sb) => (
              <div key={sb.id} className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl space-y-3">
                <div className="flex justify-between items-center border-b border-slate-800/60 pb-2">
                  <span className="font-bold text-slate-100 text-sm font-sans">{sb.sandboxName}</span>
                  <span className="font-mono text-amber-400 font-bold">
                    Score: {sb.score !== null && sb.score !== undefined ? sb.score : 'Not Available'}
                  </span>
                </div>
                <div className="flex justify-between items-center font-mono">
                  <span className="text-slate-400">Verdict:</span>
                  <span className="text-rose-400 font-bold uppercase">{sb.verdict}</span>
                </div>
                {sb.details && (
                  <div className="p-2 bg-slate-950/60 rounded border border-slate-800/60 font-mono text-[11px] text-slate-400">
                    {JSON.stringify(sb.details)}
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          <div data-testid="no-sandbox-data" className="p-12 text-center text-slate-400 space-y-2">
            <Database className="h-10 w-10 text-slate-500 mx-auto" />
            <p className="text-sm font-semibold text-slate-200">No Sandbox Data Available</p>
            <p className="text-xs text-slate-500">The currently selected analysis does not contain any persisted sandbox execution results.</p>
          </div>
        )}
      </div>

    </div>
  );
}
