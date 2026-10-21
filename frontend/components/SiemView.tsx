'use client';

import React, { useState } from 'react';
import { useAnalysisContext } from '@/context/AnalysisContext';
import { fetchAnalysisSiem, SiemEventsResponse } from '@/lib/api';
import { useQuery } from '@tanstack/react-query';
import { PageHeader } from '@/components/ui/PageHeader';
import { EmptyState } from '@/components/ui/EmptyState';
import { SeverityBadge } from '@/components/ui/SeverityBadge';
import {
  Terminal,
  Search,
  Filter,
  AlertTriangle,
  Upload,
  Activity,
} from 'lucide-react';

interface SiemViewProps {
  onOpenUpload: () => void;
}

export function SiemView({ onOpenUpload }: SiemViewProps) {
  const { currentAnalysisId } = useAnalysisContext();
  const [search, setSearch] = useState<string>('');
  const [severity, setSeverity] = useState<string>('ALL');

  const {
    data: siemData,
    isLoading,
    isError,
    error,
    refetch,
  } = useQuery<SiemEventsResponse>({
    queryKey: ['analysis', currentAnalysisId, 'siem', { severity, search }],
    queryFn: () => fetchAnalysisSiem(currentAnalysisId!, { severity, search }),
    enabled: Boolean(currentAnalysisId),
  });

  const [isNotesExpanded, setIsNotesExpanded] = useState<boolean>(true);

  // 1. EMPTY STATE
  if (!currentAnalysisId) {
    return (
      <div data-testid="no-analysis-state">
        <EmptyState
          icon={<Terminal className="w-8 h-8 text-indigo-600 dark:text-sky-400" />}
          title="No Active Analysis Selected"
          description="Select an active security analysis from the top dropdown or upload a file to view analysis-scoped SIEM log events."
          action={{
            label: 'Upload Analysis File',
            onClick: onOpenUpload,
          }}
        />
      </div>
    );
  }

  // 2. LOADING STATE
  if (isLoading) {
    return (
      <div data-testid="loading-state" className="p-12 text-center bg-white dark:bg-[#111726] rounded-xl border border-slate-200 dark:border-slate-800">
        <div className="flex flex-col items-center space-y-3">
          <div className="h-8 w-8 border-4 border-indigo-500/30 dark:border-sky-500/30 border-t-indigo-600 dark:border-t-sky-500 rounded-full animate-spin" />
          <p className="text-xs font-mono text-slate-500 dark:text-slate-400">Fetching SIEM events for {currentAnalysisId}...</p>
        </div>
      </div>
    );
  }

  // 3. ERROR STATE
  if (isError || !siemData) {
    return (
      <div data-testid="error-state" className="p-6 bg-rose-500/10 border border-rose-500/20 rounded-xl text-center text-rose-700 dark:text-rose-400 space-y-3">
        <AlertTriangle className="h-8 w-8 mx-auto text-rose-500" />
        <div>
          <h3 className="text-sm font-bold">Failed to Load SIEM Events</h3>
          <p className="text-xs mt-1">{error instanceof Error ? error.message : 'SIEM records could not be retrieved.'}</p>
        </div>
        <button
          onClick={() => refetch()}
          className="px-4 py-2 bg-rose-600 text-white font-medium text-xs rounded-xl hover:bg-rose-700 transition mx-auto flex items-center gap-2"
        >
          <Activity className="h-3.5 w-3.5" />
          <span>Retry Request</span>
        </button>
      </div>
    );
  }

  const events = siemData.events || [];
  const hasFilterActive = search.trim().length > 0 || severity !== 'ALL';

  return (
    <div data-testid="siem-view" className="space-y-6 w-full max-w-full overflow-hidden">
      <PageHeader
        title="SIEM Log & Event Analysis"
        description={`Analysis-scoped security timeline for ${currentAnalysisId}`}
        badge={`${siemData.totalCount} Total Events`}
      />

      {/* Filter Controls Header */}
      <div className="bg-white dark:bg-[#111726] border border-slate-200 dark:border-slate-800/80 rounded-2xl p-4 shadow-sm">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="relative md:col-span-2">
            <Search className="h-4 w-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search SIEM events by keyword, raw event, IP, event ID..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 focus:border-indigo-500 dark:focus:border-sky-500 rounded-xl pl-9 pr-4 py-2 text-xs text-slate-900 dark:text-slate-100 placeholder-slate-400 focus:outline-none transition font-mono"
            />
          </div>

          <div className="relative">
            <Filter className="h-4 w-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 focus:border-indigo-500 dark:focus:border-sky-500 rounded-xl pl-9 pr-4 py-2 text-xs text-slate-900 dark:text-slate-100 focus:outline-none transition appearance-none cursor-pointer"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
              <option value="INFO">INFO</option>
            </select>
          </div>
        </div>
      </div>

      {/* Events Table / Status View */}
      <div className="bg-white dark:bg-[#111726] border border-slate-200 dark:border-slate-800/80 rounded-2xl p-6 shadow-sm space-y-4 w-full overflow-hidden">
        {events.length > 0 ? (
          <div className="overflow-x-auto w-full">
            <table className="w-full text-left text-xs min-w-[700px]">
              <thead className="bg-slate-50 dark:bg-slate-900/80 text-slate-500 dark:text-slate-400 uppercase text-[10px] font-bold border-b border-slate-200 dark:border-slate-800">
                <tr>
                  <th className="p-3">Timestamp</th>
                  <th className="p-3">Event ID</th>
                  <th className="p-3">Severity</th>
                  <th className="p-3">Action</th>
                  <th className="p-3">Source IP</th>
                  <th className="p-3">Dest IP</th>
                  <th className="p-3">Protocol</th>
                  <th className="p-3">Raw Event</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-800/60 font-mono text-slate-700 dark:text-slate-300">
                {events.map((ev) => (
                  <tr key={ev.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/30 transition">
                    <td className="p-3 text-slate-500 dark:text-slate-400 whitespace-nowrap">
                      {ev.timestamp ? new Date(ev.timestamp).toLocaleString() : '—'}
                    </td>
                    <td className="p-3 font-bold text-slate-900 dark:text-slate-200">{ev.eventId || '—'}</td>
                    <td className="p-3">
                      {ev.severity ? <SeverityBadge severity={ev.severity} /> : <span className="text-slate-400">—</span>}
                    </td>
                    <td className="p-3 text-indigo-600 dark:text-sky-400 font-sans">{ev.action || '—'}</td>
                    <td className="p-3 text-slate-700 dark:text-slate-300">{ev.sourceIp || '—'}</td>
                    <td className="p-3 text-slate-700 dark:text-slate-300">{ev.destIp || '—'}</td>
                    <td className="p-3 text-slate-500 dark:text-slate-400">{ev.protocol || '—'}</td>
                    <td className="p-3 text-slate-800 dark:text-slate-300 max-w-md break-all">{ev.rawEvent}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div data-testid="no-siem-data" className="p-8 text-center text-slate-500 dark:text-slate-400 space-y-4 w-full">
            {hasFilterActive ? (
              <div className="space-y-2">
                <p className="text-sm font-semibold text-slate-800 dark:text-slate-200">
                  No SIEM events match search filter
                </p>
                <p className="text-xs text-slate-400">
                  Try clearing the search query or adjusting severity filters.
                </p>
                <button
                  onClick={() => {
                    setSearch('');
                    setSeverity('ALL');
                  }}
                  className="mt-2 px-3 py-1.5 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 text-xs font-medium rounded-lg transition"
                >
                  Clear Filters
                </button>
              </div>
            ) : (
              <div className="max-w-3xl mx-auto space-y-4 w-full">
                <div className="inline-flex p-3 rounded-full bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300">
                  <Terminal className="w-6 h-6" />
                </div>
                <div>
                  <p className="text-sm font-semibold text-slate-800 dark:text-slate-200">
                    {siemData.provenance?.providedSections && !siemData.provenance.providedSections.includes('siem')
                      ? 'Static Analysis Report (No SIEM Telemetry)'
                      : 'No SIEM Data Available'}
                  </p>
                  <p className="text-xs text-slate-400 mt-1 max-w-xl mx-auto leading-relaxed">
                    {siemData.provenance?.providedSections && !siemData.provenance.providedSections.includes('siem')
                      ? `The active file was parsed as a static threat report containing [${siemData.provenance.providedSections.join(', ')}]. It does not contain streaming SIEM log entries.`
                      : 'The currently selected analysis does not contain any persisted SIEM log entries.'}
                  </p>
                </div>

                {siemData.parsingWarnings && siemData.parsingWarnings.length > 0 && (
                  <div className="p-4 bg-amber-500/10 border border-amber-500/20 rounded-xl text-left text-amber-700 dark:text-amber-300 text-xs space-y-2 w-full">
                    <div className="flex items-center justify-between border-b border-amber-500/20 pb-2">
                      <p className="font-semibold flex items-center gap-1.5">
                        <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0" />
                        <span>Parsing Notes ({siemData.parsingStatus || 'PARTIAL'} &bull; {siemData.parsingWarnings.length} records):</span>
                      </p>
                      <button
                        type="button"
                        onClick={() => setIsNotesExpanded(!isNotesExpanded)}
                        className="text-[11px] font-medium underline hover:text-amber-600 dark:hover:text-amber-200 transition"
                      >
                        {isNotesExpanded ? 'Collapse' : 'Expand All'}
                      </button>
                    </div>
                    {isNotesExpanded && (
                      <div className="max-h-60 overflow-y-auto space-y-1.5 pr-1 font-mono text-[11px] leading-relaxed">
                        {siemData.parsingWarnings.map((w: string, idx: number) => (
                          <div key={idx} className="p-2 bg-amber-500/5 rounded-lg border border-amber-500/10 break-words whitespace-pre-wrap">
                            {w}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                <div className="pt-2">
                  <button
                    onClick={onOpenUpload}
                    className="inline-flex items-center gap-2 px-4 py-2 bg-indigo-600 dark:bg-sky-500 hover:bg-indigo-700 dark:hover:bg-sky-600 text-white font-medium text-xs rounded-xl transition shadow-sm"
                  >
                    <Upload className="w-3.5 h-3.5" />
                    <span>Upload SIEM Log File (.log, .json, .csv)</span>
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
