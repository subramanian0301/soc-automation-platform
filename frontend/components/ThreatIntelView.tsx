import React from 'react';
import { useAnalysisContext } from '@/context/AnalysisContext';
import { fetchAnalysisThreatIntel, ThreatIntelResponse } from '@/lib/api';
import { useQuery } from '@tanstack/react-query';
import { getModuleState } from '@/lib/moduleState';
import {
  ShieldAlert,
  AlertTriangle,
  Upload,
  Globe,
  Layers,
  RotateCcw,
} from 'lucide-react';

interface ThreatIntelViewProps {
  onOpenUpload: () => void;
}

export function ThreatIntelView({ onOpenUpload }: ThreatIntelViewProps) {
  const { currentAnalysisId } = useAnalysisContext();

  const {
    data: intelData,
    isLoading,
    isError,
    error,
    refetch,
  } = useQuery<ThreatIntelResponse>({
    queryKey: ['analysis', currentAnalysisId, 'threat-intel'],
    queryFn: () => fetchAnalysisThreatIntel(currentAnalysisId!),
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
            <ShieldAlert className="h-8 w-8" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-slate-100">No Active Analysis Selected</h2>
            <p className="text-xs text-slate-400 mt-2 leading-relaxed">
              Select an active security analysis from the top dropdown or upload a file to view analysis-scoped Threat Intelligence.
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
          <p className="text-xs font-mono text-slate-400">Loading Threat Intelligence for {currentAnalysisId}...</p>
        </div>
      </div>
    );
  }

  // 3. ERROR STATE with Retry
  if (isError || !intelData) {
    return (
      <div
        data-testid="error-state"
        className="flex-1 flex items-center justify-center p-12 bg-[#0a0d14]"
      >
        <div className="bg-rose-500/10 border border-rose-500/20 rounded-2xl p-6 text-center max-w-md text-rose-300 space-y-4">
          <AlertTriangle className="h-8 w-8 text-rose-400 mx-auto" />
          <div>
            <h3 className="text-sm font-bold">Failed to Load Threat Intelligence</h3>
            <p className="text-xs mt-1">{error instanceof Error ? error.message : 'Threat Intelligence record could not be retrieved.'}</p>
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

  const { riskScore, threatLevel, recommendation, virusTotalResult, yaraResults = [], iocs = [], parsingStatus, provenance } = intelData;

  const vtState = getModuleState({
    items: virusTotalResult,
    sectionKey: 'virusTotal',
    parsingStatus,
    provenance,
  });

  const yaraState = getModuleState({
    items: yaraResults,
    sectionKey: 'yara',
    parsingStatus,
    provenance,
  });

  const iocState = getModuleState({
    items: iocs,
    sectionKey: 'iocs',
    parsingStatus,
    provenance,
  });

  return (
    <div data-testid="threat-intel-view" className="flex-1 p-6 md:p-8 bg-[#0a0d14] text-slate-100 overflow-y-auto space-y-6">
      
      {/* Header Bar */}
      <div className="bg-[#111726] border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div className="flex items-center space-x-3">
            <div className="h-10 w-10 bg-sky-500/10 border border-sky-500/20 rounded-xl flex items-center justify-center text-sky-400 shadow-inner">
              <ShieldAlert className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white tracking-tight">Threat Intelligence Summary</h2>
              <p className="text-xs text-slate-400">Analysis-Scoped Source Findings &bull; ID: <span className="font-mono text-slate-300">{currentAnalysisId}</span></p>
            </div>
          </div>
        </div>

        {/* Source Risk Overview */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          <div className="p-4 bg-slate-900/60 rounded-xl border border-slate-800 space-y-1">
            <span className="text-[10px] text-slate-400 uppercase font-bold">Quantitative Risk Score</span>
            <p className="text-2xl font-extrabold text-white">
              {riskScore !== null && riskScore !== undefined ? `${riskScore} / 100` : 'Not Available'}
            </p>
          </div>
          <div className="p-4 bg-slate-900/60 rounded-xl border border-slate-800 space-y-1">
            <span className="text-[10px] text-slate-400 uppercase font-bold">Threat Severity Level</span>
            <p className="text-xl font-bold text-sky-400 uppercase">
              {threatLevel || 'Not Available'}
            </p>
          </div>
          <div className="p-4 bg-slate-900/60 rounded-xl border border-slate-800 space-y-1">
            <span className="text-[10px] text-slate-400 uppercase font-bold">Recommendation</span>
            <p className="text-slate-300">{recommendation || 'Not Available'}</p>
          </div>
        </div>
      </div>

      {/* VirusTotal & YARA Summary */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* VirusTotal Section */}
        <div className="bg-[#111726] border border-slate-800 rounded-2xl p-6 shadow-lg space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center space-x-2">
              <Globe className="h-4 w-4 text-sky-400" />
              <h3 className="text-sm font-bold text-slate-100">VirusTotal Detection Intelligence</h3>
            </div>
            <span className="text-xs text-slate-400">{vtState.badgeText}</span>
          </div>
          {vtState.isAvailable ? (
            <div className="space-y-3 text-xs">
              <div className="p-3 bg-slate-900/60 rounded-xl border border-slate-800 flex justify-between items-center font-mono">
                <span className="text-slate-400">Positives / Total Ratio:</span>
                <span className="text-slate-100 font-bold text-sm">{virusTotalResult!.positives} / {virusTotalResult!.total}</span>
              </div>
              <div className="p-3 bg-slate-900/60 rounded-xl border border-slate-800 flex justify-between items-center font-mono">
                <span className="text-slate-400">Scan Date:</span>
                <span className="text-slate-200">{virusTotalResult!.scanDate || 'Not Available'}</span>
              </div>
              {virusTotalResult!.permalink && (
                <div className="p-3 bg-slate-900/60 rounded-xl border border-slate-800 font-mono text-[11px] truncate">
                  <span className="text-slate-400 block">Source Reference Permalink:</span>
                  <span className="text-sky-400">{virusTotalResult!.permalink}</span>
                </div>
              )}
            </div>
          ) : vtState.isConfirmedEmpty ? (
            <p className="text-xs text-slate-400 italic font-mono">Confirmed clean (0 detections)</p>
          ) : vtState.isParsingIncomplete ? (
            <p className="text-xs text-amber-500 italic font-mono">Parsing incomplete for VirusTotal data</p>
          ) : (
            <p className="text-xs text-slate-400 italic">Not Provided</p>
          )}
        </div>

        {/* YARA Section */}
        <div className="bg-[#111726] border border-slate-800 rounded-2xl p-6 shadow-lg space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center space-x-2">
              <ShieldAlert className="h-4 w-4 text-sky-400" />
              <h3 className="text-sm font-bold text-slate-100">YARA Signature Matches</h3>
            </div>
            <span className="text-xs text-slate-400">{yaraState.badgeText}</span>
          </div>
          {yaraState.isAvailable ? (
            <div className="space-y-2 text-xs">
              {yaraResults.map((yara) => (
                <div key={yara.id} className="p-3 bg-slate-900/60 border border-slate-800 rounded-xl space-y-1">
                  <span className="font-bold text-rose-400 font-mono">{yara.ruleName}</span>
                  <p className="text-[11px] text-slate-300">{yara.description || 'Not Available'}</p>
                </div>
              ))}
            </div>
          ) : yaraState.isConfirmedEmpty ? (
            <p className="text-xs text-slate-400 italic font-mono">0 matches (Source confirmed clean)</p>
          ) : yaraState.isParsingIncomplete ? (
            <p className="text-xs text-amber-500 italic font-mono">Parsing incomplete for YARA rules</p>
          ) : (
            <p className="text-xs text-slate-400 italic">Not Provided</p>
          )}
        </div>
      </div>

      {/* Extracted IOC Intelligence Metadata Table */}
      <div className="bg-[#111726] border border-slate-800 rounded-2xl p-6 shadow-lg space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center space-x-2">
            <Layers className="h-4 w-4 text-sky-400" />
            <h3 className="text-sm font-bold text-slate-100">Extracted Indicator Threat Metadata</h3>
          </div>
          <span className="text-xs text-slate-400">{iocState.badgeText}</span>
        </div>

        {iocState.isAvailable ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/80 text-slate-400 uppercase text-[10px] font-bold border-b border-slate-800">
                <tr>
                  <th className="p-3">Type</th>
                  <th className="p-3">Indicator Value</th>
                  <th className="p-3">Category</th>
                  <th className="p-3">Confidence</th>
                  <th className="p-3">Description</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono text-slate-300">
                {iocs.map((ioc) => (
                  <tr key={ioc.id} className="hover:bg-slate-800/30 transition">
                    <td className="p-3 font-sans">
                      <span className="px-2 py-0.5 rounded bg-sky-500/10 text-sky-400 font-bold text-[10px]">
                        {ioc.type}
                      </span>
                    </td>
                    <td className="p-3 text-slate-100 font-bold break-all">{ioc.value}</td>
                    <td className="p-3 font-sans text-slate-400">{ioc.category || 'Not Available'}</td>
                    <td className="p-3 font-sans text-slate-400">
                      {ioc.confidence !== null && ioc.confidence !== undefined ? `${ioc.confidence}%` : 'Not Available'}
                    </td>
                    <td className="p-3 font-sans text-slate-400 max-w-md">{ioc.description || 'Not Available'}</td>
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
          <p className="text-xs text-slate-400 italic">Not Provided</p>
        )}
      </div>

    </div>
  );
}
