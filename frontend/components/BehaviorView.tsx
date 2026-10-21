'use client';

import React from 'react';
import { useAnalysisContext } from '@/context/AnalysisContext';
import { fetchAnalysisBehavior, BehaviorResponse } from '@/lib/api';
import { useQuery } from '@tanstack/react-query';
import {
  Activity,
  AlertTriangle,
  Upload,
  Cpu,
  Server,
  Layers,
} from 'lucide-react';

interface BehaviorViewProps {
  onOpenUpload: () => void;
}

export function BehaviorView({ onOpenUpload }: BehaviorViewProps) {
  const { currentAnalysisId } = useAnalysisContext();

  const {
    data: behaviorData,
    isLoading,
    isError,
    error,
    refetch,
  } = useQuery<BehaviorResponse>({
    queryKey: ['analysis', currentAnalysisId, 'behavior'],
    queryFn: () => fetchAnalysisBehavior(currentAnalysisId!),
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
            <Activity className="h-8 w-8" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-slate-100">No Active Analysis Selected</h2>
            <p className="text-xs text-slate-400 mt-2 leading-relaxed">
              Select an active security analysis from the top dropdown or upload a file to view Behavior Analysis events.
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
          <p className="text-xs font-mono text-slate-400">Loading Behavior events for {currentAnalysisId}...</p>
        </div>
      </div>
    );
  }

  // 3. ERROR STATE
  if (isError || !behaviorData) {
    return (
      <div
        data-testid="error-state"
        className="flex-1 flex items-center justify-center p-12 bg-[#0a0d14]"
      >
        <div className="bg-rose-500/10 border border-rose-500/20 rounded-2xl p-6 text-center max-w-md text-rose-300 space-y-4">
          <AlertTriangle className="h-8 w-8 text-rose-400 mx-auto" />
          <div>
            <h3 className="text-sm font-bold">Failed to Load Behavior Data</h3>
            <p className="text-xs mt-1">{error instanceof Error ? error.message : 'Behavior events could not be retrieved.'}</p>
          </div>
          <button
            onClick={() => refetch()}
            className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white font-medium text-xs rounded-xl transition flex items-center justify-center space-x-2 mx-auto"
          >
            <Activity className="h-3.5 w-3.5" />
            <span>Retry Request</span>
          </button>
        </div>
      </div>
    );
  }

  const events = behaviorData.events || [];

  return (
    <div data-testid="behavior-view" className="flex-1 p-6 md:p-8 bg-[#0a0d14] text-slate-100 overflow-y-auto space-y-6">
      
      {/* Header Bar */}
      <div className="bg-[#111726] border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div className="flex items-center space-x-3">
            <div className="h-10 w-10 bg-sky-500/10 border border-sky-500/20 rounded-xl flex items-center justify-center text-sky-400 shadow-inner">
              <Activity className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white tracking-tight">Behavior Event Timeline</h2>
              <p className="text-xs text-slate-400">Analysis-Scoped Endpoint Behavior &bull; ID: <span className="font-mono text-slate-300">{currentAnalysisId}</span></p>
            </div>
          </div>

          <div className="flex items-center space-x-3">
            <span className="text-xs font-bold text-sky-400 bg-sky-500/10 border border-sky-500/20 px-3 py-1.5 rounded-lg flex items-center gap-2 font-mono">
              <Layers className="h-4 w-4" />
              <span>{behaviorData.totalCount} Events Recorded</span>
            </span>
          </div>
        </div>
      </div>

      {/* Events Table / Timeline */}
      <div className="bg-[#111726] border border-slate-800 rounded-2xl p-6 shadow-lg space-y-4">
        {events.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/80 text-slate-400 uppercase text-[10px] font-bold border-b border-slate-800">
                <tr>
                  <th className="p-3">Event Type</th>
                  <th className="p-3">Action</th>
                  <th className="p-3">Target / Object</th>
                  <th className="p-3">Details</th>
                  <th className="p-3">Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono text-slate-300">
                {events.map((ev) => (
                  <tr key={ev.id} className="hover:bg-slate-800/30 transition">
                    <td className="p-3 font-sans">
                      <span className="px-2 py-0.5 rounded bg-sky-500/10 text-sky-400 font-bold text-[10px] uppercase">
                        {ev.eventType}
                      </span>
                    </td>
                    <td className="p-3 font-bold text-slate-200">{ev.action}</td>
                    <td className="p-3 text-slate-300 max-w-xs truncate" title={ev.target}>{ev.target}</td>
                    <td className="p-3 font-sans text-slate-400 max-w-md">{ev.details || '—'}</td>
                    <td className="p-3 text-slate-400 whitespace-nowrap">
                      {ev.timestamp ? new Date(ev.timestamp).toLocaleString() : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div data-testid="no-behavior-data" className="p-12 text-center text-slate-400 space-y-2">
            <Activity className="h-10 w-10 text-slate-500 mx-auto" />
            <p className="text-sm font-semibold text-slate-200">No Behavior Data Available</p>
            <p className="text-xs text-slate-500">The currently selected analysis does not contain any persisted behavior events.</p>
          </div>
        )}
      </div>

    </div>
  );
}
