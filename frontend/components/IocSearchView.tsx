'use client';

import React, { useState } from 'react';
import { useAnalysisContext } from '@/context/AnalysisContext';
import { fetchAnalysisIocs, IocsResponse } from '@/lib/api';
import { useQuery } from '@tanstack/react-query';
import { PageHeader } from '@/components/ui/PageHeader';
import { EmptyState } from '@/components/ui/EmptyState';
import {
  Layers,
  Search,
  Filter,
  AlertTriangle,
  Shield,
} from 'lucide-react';

interface IocSearchViewProps {
  onOpenUpload: () => void;
}

export function IocSearchView({ onOpenUpload }: IocSearchViewProps) {
  const { currentAnalysisId } = useAnalysisContext();
  const [search, setSearch] = useState<string>('');
  const [type, setType] = useState<string>('ALL');

  const {
    data: iocData,
    isLoading,
    isError,
    error,
    refetch,
  } = useQuery<IocsResponse>({
    queryKey: ['analysis', currentAnalysisId, 'iocs', { type, search }],
    queryFn: () => fetchAnalysisIocs(currentAnalysisId!, { type, search }),
    enabled: Boolean(currentAnalysisId),
  });

  // 1. EMPTY STATE
  if (!currentAnalysisId) {
    return (
      <div data-testid="no-analysis-state">
        <EmptyState
          icon={<Layers className="w-8 h-8 text-indigo-600 dark:text-sky-400" />}
          title="No Active Analysis Selected"
          description="Select an active security analysis from the top dropdown or upload a file to perform analysis-scoped IOC search."
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
          <p className="text-xs font-mono text-slate-500 dark:text-slate-400">Searching IOCs for {currentAnalysisId}...</p>
        </div>
      </div>
    );
  }

  // 3. ERROR STATE
  if (isError || !iocData) {
    return (
      <div data-testid="error-state" className="p-6 bg-rose-500/10 border border-rose-500/20 rounded-xl text-center text-rose-700 dark:text-rose-400 space-y-3">
        <AlertTriangle className="h-8 w-8 mx-auto text-rose-500" />
        <div>
          <h3 className="text-sm font-bold">Failed to Load IOC Data</h3>
          <p className="text-xs mt-1">{error instanceof Error ? error.message : 'IOC records could not be retrieved.'}</p>
        </div>
        <button
          onClick={() => refetch()}
          className="px-4 py-2 bg-rose-600 text-white font-medium text-xs rounded-xl hover:bg-rose-700 transition mx-auto flex items-center gap-2"
        >
          <Shield className="h-3.5 w-3.5" />
          <span>Retry Request</span>
        </button>
      </div>
    );
  }

  const iocs = iocData.iocs || [];
  const hasSearchQuery = search.trim().length > 0;
  const hasTypeFilter = type !== 'ALL';

  return (
    <div data-testid="ioc-search-view" className="space-y-6">
      <PageHeader
        title="IOC Search & Analysis"
        description={`Extracted Indicators of Compromise for analysis ${currentAnalysisId}`}
        badge={`${iocData.totalCount} Extracted IOCs`}
      />

      {/* Filter Controls Header */}
      <div className="bg-white dark:bg-[#111726] border border-slate-200 dark:border-slate-800/80 rounded-2xl p-4 shadow-sm">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="relative md:col-span-2">
            <Search className="h-4 w-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search IOCs by value (e.g., 198.51.100.45, malware-update.example)..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 focus:border-indigo-500 dark:focus:border-sky-500 rounded-xl pl-9 pr-4 py-2 text-xs text-slate-900 dark:text-slate-100 placeholder-slate-400 focus:outline-none transition font-mono"
            />
          </div>

          <div className="relative">
            <Filter className="h-4 w-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <select
              value={type}
              onChange={(e) => setType(e.target.value)}
              className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 focus:border-indigo-500 dark:focus:border-sky-500 rounded-xl pl-9 pr-4 py-2 text-xs text-slate-900 dark:text-slate-100 focus:outline-none transition appearance-none cursor-pointer"
            >
              <option value="ALL">All IOC Types</option>
              <option value="IP">IP Address</option>
              <option value="DOMAIN">Domain</option>
              <option value="URL">URL</option>
              <option value="EMAIL">Email</option>
              <option value="HASH">Hash</option>
              <option value="INDICATOR">Other Indicator</option>
            </select>
          </div>
        </div>
      </div>

      {/* IOC Table */}
      <div className="bg-white dark:bg-[#111726] border border-slate-200 dark:border-slate-800/80 rounded-2xl p-6 shadow-sm space-y-4">
        {iocs.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 dark:bg-slate-900/80 text-slate-500 dark:text-slate-400 uppercase text-[10px] font-bold border-b border-slate-200 dark:border-slate-800">
                <tr>
                  <th className="p-3">Type</th>
                  <th className="p-3">Indicator Value</th>
                  <th className="p-3">Category</th>
                  <th className="p-3">Confidence</th>
                  <th className="p-3">Description / Metadata</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-800/60 font-mono text-slate-700 dark:text-slate-300">
                {iocs.map((ioc) => (
                  <tr key={ioc.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/30 transition">
                    <td className="p-3">
                      <span className="px-2 py-0.5 rounded bg-indigo-50 dark:bg-sky-500/10 text-indigo-600 dark:text-sky-400 font-sans font-bold text-[10px]">
                        {ioc.type}
                      </span>
                    </td>
                    <td className="p-3 text-slate-900 dark:text-slate-100 font-bold break-all">{ioc.value}</td>
                    <td className="p-3 font-sans text-slate-500 dark:text-slate-400">{ioc.category || 'Not Available'}</td>
                    <td className="p-3 font-sans text-slate-500 dark:text-slate-400">
                      {ioc.confidence !== null && ioc.confidence !== undefined ? `${ioc.confidence}%` : 'Not Available'}
                    </td>
                    <td className="p-3 font-sans text-slate-500 dark:text-slate-400 max-w-md">{ioc.description || 'Not Available'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div data-testid="no-ioc-data" className="p-12 text-center text-slate-500 dark:text-slate-400 space-y-2">
            <p className="text-sm font-semibold">
              {hasSearchQuery || hasTypeFilter ? 'No IOC Found' : 'No IOC Data Available'}
            </p>
            <p className="text-xs text-slate-400">
              {hasSearchQuery || hasTypeFilter
                ? `No indicators matched the query '${search}' within active analysis ${currentAnalysisId}.`
                : 'The currently selected analysis does not contain any extracted IOC records.'}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
