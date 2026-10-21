'use client';

import React from 'react';
import { useAnalysisContext } from '@/context/AnalysisContext';
import { fetchAnalysisMitre, MitreResponse } from '@/lib/api';
import { useQuery } from '@tanstack/react-query';
import {
  Crosshair,
  AlertTriangle,
  Upload,
  Terminal,
  Layers,
  RotateCcw,
} from 'lucide-react';

interface MitreViewProps {
  onOpenUpload: () => void;
}

export function MitreView({ onOpenUpload }: MitreViewProps) {
  const { currentAnalysisId } = useAnalysisContext();

  const {
    data: mitreData,
    isLoading,
    isError,
    error,
    refetch,
  } = useQuery<MitreResponse>({
    queryKey: ['analysis', currentAnalysisId, 'mitre'],
    queryFn: () => fetchAnalysisMitre(currentAnalysisId!),
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
            <Crosshair className="h-8 w-8" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-slate-100">No Active Analysis Selected</h2>
            <p className="text-xs text-slate-400 mt-2 leading-relaxed">
              Select an active security analysis from the top dropdown or upload a file to view MITRE ATT&CK technique mappings.
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
          <p className="text-xs font-mono text-slate-400">Loading MITRE ATT&CK techniques for {currentAnalysisId}...</p>
        </div>
      </div>
    );
  }

  // 3. ERROR STATE
  if (isError || !mitreData) {
    return (
      <div
        data-testid="error-state"
        className="flex-1 flex items-center justify-center p-12 bg-[#0a0d14]"
      >
        <div className="bg-rose-500/10 border border-rose-500/20 rounded-2xl p-6 text-center max-w-md text-rose-300 space-y-4">
          <AlertTriangle className="h-8 w-8 text-rose-400 mx-auto" />
          <div>
            <h3 className="text-sm font-bold">Failed to Load MITRE ATT&CK Data</h3>
            <p className="text-xs mt-1">{error instanceof Error ? error.message : 'MITRE techniques could not be retrieved.'}</p>
          </div>
          <button
            onClick={() => refetch()}
            className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white font-medium text-xs rounded-xl transition flex items-center justify-center space-x-2 mx-auto"
          >
            <RotateCcw className="h-3.5 w-3.5" />
            <span>Retry Request</span>
          </button>
        </div>
      </div>
    );
  }

  const techniques = mitreData.techniques || [];

  return (
    <div data-testid="mitre-view" className="flex-1 p-6 md:p-8 bg-[#0a0d14] text-slate-100 overflow-y-auto space-y-6">
      
      {/* Header Bar */}
      <div className="bg-[#111726] border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div className="flex items-center space-x-3">
            <div className="h-10 w-10 bg-amber-500/10 border border-amber-500/20 rounded-xl flex items-center justify-center text-amber-400 shadow-inner">
              <Crosshair className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white tracking-tight">MITRE ATT&CK Mapping</h2>
              <p className="text-xs text-slate-400">Explicit Source-Provided Techniques &bull; ID: <span className="font-mono text-slate-300">{currentAnalysisId}</span></p>
            </div>
          </div>

          <div className="flex items-center space-x-3">
            <span className="text-xs font-bold text-amber-400 bg-amber-500/10 border border-amber-500/20 px-3 py-1.5 rounded-lg flex items-center gap-2 font-mono">
              <Layers className="h-4 w-4" />
              <span>{mitreData.totalCount} Explicit Techniques</span>
            </span>
          </div>
        </div>
      </div>

      {/* Techniques Grid / List */}
      <div className="bg-[#111726] border border-slate-800 rounded-2xl p-6 shadow-lg space-y-4">
        {techniques.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {techniques.map((item) => (
              <div key={item.id} className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl space-y-2">
                <div className="flex items-center justify-between border-b border-slate-800/60 pb-2">
                  <span className="font-mono font-bold text-amber-400 text-sm">{item.techniqueId}</span>
                  <span className="text-xs font-sans text-slate-400 font-semibold">{item.tactic || 'Not Available'}</span>
                </div>
                <h4 className="text-xs font-bold text-slate-100">{item.name}</h4>
                <p className="text-[11px] text-slate-400 leading-relaxed">{item.description || 'Not Available'}</p>
              </div>
            ))}
          </div>
        ) : (
          <div data-testid="no-mitre-data" className="p-12 text-center text-slate-400 space-y-2">
            <Crosshair className="h-10 w-10 text-slate-500 mx-auto" />
            <p className="text-sm font-semibold text-slate-200">No MITRE ATT&CK Data Available</p>
            <p className="text-xs text-slate-500">The currently selected analysis does not explicitly contain any MITRE ATT&CK techniques.</p>
          </div>
        )}
      </div>

    </div>
  );
}
