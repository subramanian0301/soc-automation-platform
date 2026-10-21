'use client';

import React, { useState } from 'react';
import { useAnalysisContext } from '@/context/AnalysisContext';
import { fetchAnalysisCases, createAnalystCase, CasesResponse } from '@/lib/api';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Briefcase,
  AlertTriangle,
  Upload,
  Plus,
  X,
  Shield,
  Layers,
} from 'lucide-react';

interface CasesViewProps {
  onOpenUpload: () => void;
}

export function CasesView({ onOpenUpload }: CasesViewProps) {
  const { currentAnalysisId } = useAnalysisContext();
  const queryClient = useQueryClient();

  const [isModalOpen, setIsModalOpen] = useState<boolean>(false);
  const [title, setTitle] = useState<string>('');
  const [priority, setPriority] = useState<string>('HIGH');
  const [status, setStatus] = useState<string>('NEW');
  const [summary, setSummary] = useState<string>('');
  const [formError, setFormError] = useState<string | null>(null);

  const {
    data: casesData,
    isLoading,
    isError,
    error,
  } = useQuery<CasesResponse>({
    queryKey: ['analysis', currentAnalysisId, 'cases'],
    queryFn: () => fetchAnalysisCases(currentAnalysisId!),
    enabled: Boolean(currentAnalysisId),
  });

  const createMutation = useMutation({
    mutationFn: (payload: { title: string; status?: string; priority?: string; summary?: string }) =>
      createAnalystCase(currentAnalysisId!, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['analysis', currentAnalysisId, 'cases'] });
      setIsModalOpen(false);
      setTitle('');
      setSummary('');
      setFormError(null);
    },
    onError: (err: any) => {
      setFormError(err instanceof Error ? err.message : 'Failed to create case');
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim()) {
      setFormError('Title is required');
      return;
    }
    createMutation.mutate({
      title: title.trim(),
      priority,
      status,
      summary: summary.trim() || undefined,
    });
  };

  // 1. EMPTY STATE: currentAnalysisId === null
  if (!currentAnalysisId) {
    return (
      <div
        data-testid="no-analysis-state"
        className="flex-1 flex flex-col items-center justify-center p-12 text-center bg-[#0a0d14]"
      >
        <div className="max-w-md w-full bg-[#111726] border border-slate-800 rounded-2xl p-8 shadow-2xl space-y-6">
          <div className="h-16 w-16 bg-sky-500/10 border border-sky-500/20 rounded-2xl flex items-center justify-center text-sky-400 mx-auto shadow-inner">
            <Briefcase className="h-8 w-8" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-slate-100">No Active Analysis Selected</h2>
            <p className="text-xs text-slate-400 mt-2 leading-relaxed">
              Select an active security analysis from the top dropdown or upload a file to view Cases.
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
          <p className="text-xs font-mono text-slate-400">Loading Cases for {currentAnalysisId}...</p>
        </div>
      </div>
    );
  }

  // 3. ERROR STATE
  if (isError || !casesData) {
    return (
      <div
        data-testid="error-state"
        className="flex-1 flex items-center justify-center p-12 bg-[#0a0d14]"
      >
        <div className="bg-rose-500/10 border border-rose-500/20 rounded-2xl p-6 text-center max-w-md text-rose-300 space-y-3">
          <AlertTriangle className="h-8 w-8 text-rose-400 mx-auto" />
          <h3 className="text-sm font-bold">Failed to Load Cases</h3>
          <p className="text-xs">{error instanceof Error ? error.message : 'Case records could not be retrieved.'}</p>
        </div>
      </div>
    );
  }

  const casesList = casesData.cases || [];

  return (
    <div data-testid="cases-view" className="flex-1 p-6 md:p-8 bg-[#0a0d14] text-slate-100 overflow-y-auto space-y-6">
      
      {/* Header Bar */}
      <div className="bg-[#111726] border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div className="flex items-center space-x-3">
            <div className="h-10 w-10 bg-sky-500/10 border border-sky-500/20 rounded-xl flex items-center justify-center text-sky-400 shadow-inner">
              <Briefcase className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white tracking-tight">Case Management</h2>
              <p className="text-xs text-slate-400">Analysis-Scoped Investigation Cases &bull; ID: <span className="font-mono text-slate-300">{currentAnalysisId}</span></p>
            </div>
          </div>

          <div className="flex items-center space-x-3">
            <button
              onClick={() => setIsModalOpen(true)}
              className="flex items-center space-x-2 bg-sky-600 hover:bg-sky-500 text-white font-medium text-xs px-4 py-2 rounded-lg transition shadow-lg shadow-sky-600/20 active:scale-95"
            >
              <Plus className="h-4 w-4" />
              <span>Create Analyst Case</span>
            </button>
            <span className="text-xs font-bold text-sky-400 bg-sky-500/10 border border-sky-500/20 px-3 py-1.5 rounded-lg flex items-center gap-2 font-mono">
              <Shield className="h-4 w-4" />
              <span>{casesData.totalCount} Cases</span>
            </span>
          </div>
        </div>
      </div>

      {/* Cases Table / List */}
      <div className="bg-[#111726] border border-slate-800 rounded-2xl p-6 shadow-lg space-y-4">
        {casesList.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/80 text-slate-400 uppercase text-[10px] font-bold border-b border-slate-800">
                <tr>
                  <th className="p-3">Case Number</th>
                  <th className="p-3">Title</th>
                  <th className="p-3">Priority</th>
                  <th className="p-3">Status</th>
                  <th className="p-3">Summary / Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono text-slate-300">
                {casesList.map((cs) => (
                  <tr key={cs.id} className="hover:bg-slate-800/30 transition">
                    <td className="p-3 font-bold text-sky-400">{cs.caseNumber}</td>
                    <td className="p-3 font-bold text-slate-100 font-sans">{cs.title}</td>
                    <td className="p-3 font-sans">
                      <span className={`px-2 py-0.5 rounded font-bold text-[10px] uppercase ${
                        cs.priority.toUpperCase() === 'HIGH' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' :
                        cs.priority.toUpperCase() === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' :
                        'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                      }`}>
                        {cs.priority}
                      </span>
                    </td>
                    <td className="p-3 font-sans">
                      <span className="px-2 py-0.5 rounded bg-sky-500/10 text-sky-400 font-bold text-[10px] uppercase">
                        {cs.status}
                      </span>
                    </td>
                    <td className="p-3 font-sans text-slate-400 max-w-md">{cs.summary || 'Not Available'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div data-testid="no-case-data" className="p-12 text-center text-slate-400 space-y-2">
            <Briefcase className="h-10 w-10 text-slate-500 mx-auto" />
            <p className="text-sm font-semibold text-slate-200">No Case Data Available</p>
            <p className="text-xs text-slate-500">The currently selected analysis does not contain any cases.</p>
          </div>
        )}
      </div>

      {/* Analyst Case Creation Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-[#111726] border border-slate-800 rounded-2xl p-6 max-w-md w-full space-y-4 shadow-2xl">
            <div className="flex justify-between items-center border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <Briefcase className="h-4 w-4 text-sky-400" />
                Create Analyst Case
              </h3>
              <button onClick={() => setIsModalOpen(false)} className="text-slate-400 hover:text-white transition">
                <X className="h-4 w-4" />
              </button>
            </div>

            {formError && (
              <div className="p-3 bg-rose-500/10 border border-rose-500/20 text-rose-300 rounded-xl text-xs">
                {formError}
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 font-semibold mb-1">Case Title *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g., Host Compromise Investigation Case"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 focus:border-sky-500 rounded-xl p-2.5 text-slate-200 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-slate-400 font-semibold mb-1">Priority</label>
                <select
                  value={priority}
                  onChange={(e) => setPriority(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 focus:border-sky-500 rounded-xl p-2.5 text-slate-200 focus:outline-none cursor-pointer"
                >
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-400 font-semibold mb-1">Case Summary / Objectives</label>
                <textarea
                  placeholder="Summary of case investigation goals..."
                  value={summary}
                  onChange={(e) => setSummary(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 focus:border-sky-500 rounded-xl p-2.5 text-slate-200 focus:outline-none h-20"
                />
              </div>

              <div className="pt-2 flex justify-end space-x-2">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl transition font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createMutation.isPending}
                  className="px-4 py-2 bg-sky-600 hover:bg-sky-500 text-white rounded-xl transition font-medium shadow-lg shadow-sky-600/20"
                >
                  {createMutation.isPending ? 'Creating...' : 'Create Case'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

    </div>
  );
}
