'use client';

import React, { useState } from 'react';
import { useAnalysisContext } from '@/context/AnalysisContext';
import { fetchAnalysisIncidents, createAnalystIncident, IncidentsResponse } from '@/lib/api';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { PageHeader } from '@/components/ui/PageHeader';
import { EmptyState } from '@/components/ui/EmptyState';
import { SeverityBadge } from '@/components/ui/SeverityBadge';
import {
  AlertTriangle,
  Plus,
  X,
} from 'lucide-react';

interface IncidentsViewProps {
  onOpenUpload: () => void;
}

export function IncidentsView({ onOpenUpload }: IncidentsViewProps) {
  const { currentAnalysisId } = useAnalysisContext();
  const queryClient = useQueryClient();

  const [isModalOpen, setIsModalOpen] = useState<boolean>(false);
  const [title, setTitle] = useState<string>('');
  const [severity, setSeverity] = useState<string>('HIGH');
  const [status, setStatus] = useState<string>('OPEN');
  const [reason, setReason] = useState<string>('');
  const [assignedTo, setAssignedTo] = useState<string>('');
  const [formError, setFormError] = useState<string | null>(null);

  const {
    data: incidentsData,
    isLoading,
    isError,
    error,
  } = useQuery<IncidentsResponse>({
    queryKey: ['analysis', currentAnalysisId, 'incidents'],
    queryFn: () => fetchAnalysisIncidents(currentAnalysisId!),
    enabled: Boolean(currentAnalysisId),
  });

  const createMutation = useMutation({
    mutationFn: (payload: { title: string; severity?: string; status?: string; reason?: string; assignedTo?: string }) =>
      createAnalystIncident(currentAnalysisId!, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['analysis', currentAnalysisId, 'incidents'] });
      setIsModalOpen(false);
      setTitle('');
      setReason('');
      setAssignedTo('');
      setFormError(null);
    },
    onError: (err: any) => {
      setFormError(err instanceof Error ? err.message : 'Failed to create incident');
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
      severity,
      status,
      reason: reason.trim() || 'Analyst created incident',
      assignedTo: assignedTo.trim() || undefined,
    });
  };

  // 1. EMPTY STATE
  if (!currentAnalysisId) {
    return (
      <div data-testid="no-analysis-state">
        <EmptyState
          icon={<AlertTriangle className="w-8 h-8 text-rose-500" />}
          title="No Active Analysis Selected"
          description="Select an active security analysis from the top dropdown or upload a file to view Incidents."
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
          <p className="text-xs font-mono text-slate-500 dark:text-slate-400">Loading Incidents for {currentAnalysisId}...</p>
        </div>
      </div>
    );
  }

  // 3. ERROR STATE
  if (isError || !incidentsData) {
    return (
      <div data-testid="error-state" className="p-6 bg-rose-500/10 border border-rose-500/20 rounded-xl text-center text-rose-700 dark:text-rose-400 space-y-2">
        <AlertTriangle className="h-8 w-8 mx-auto" />
        <h3 className="text-sm font-bold">Failed to Load Incidents</h3>
        <p className="text-xs">{error instanceof Error ? error.message : 'Incident records could not be retrieved.'}</p>
      </div>
    );
  }

  const incidents = incidentsData.incidents || [];

  return (
    <div data-testid="incidents-view" className="space-y-6">
      <PageHeader
        title="Incident Response Management"
        description={`Analysis-scoped security incidents for ${currentAnalysisId}`}
        badge={`${incidentsData.totalCount} Incidents`}
      >
        <button
          onClick={() => setIsModalOpen(true)}
          className="flex items-center space-x-2 bg-rose-600 hover:bg-rose-700 text-white font-medium text-xs px-4 py-2.5 rounded-xl transition shadow-md active:scale-95"
        >
          <Plus className="h-4 w-4" />
          <span>Create Analyst Incident</span>
        </button>
      </PageHeader>

      {/* Incidents Table */}
      <div className="bg-white dark:bg-[#111726] border border-slate-200 dark:border-slate-800/80 rounded-2xl p-6 shadow-sm space-y-4">
        {incidents.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 dark:bg-slate-900/80 text-slate-500 dark:text-slate-400 uppercase text-[10px] font-bold border-b border-slate-200 dark:border-slate-800">
                <tr>
                  <th className="p-3">Title</th>
                  <th className="p-3">Severity</th>
                  <th className="p-3">Status</th>
                  <th className="p-3">Reason / Source</th>
                  <th className="p-3">Assigned To</th>
                  <th className="p-3">Created At</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-800/60 font-mono text-slate-700 dark:text-slate-300">
                {incidents.map((inc) => (
                  <tr key={inc.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/30 transition">
                    <td className="p-3 font-bold text-slate-900 dark:text-slate-100 font-sans">{inc.title}</td>
                    <td className="p-3">
                      {inc.severity ? <SeverityBadge severity={inc.severity} /> : <span className="text-slate-400 font-sans">N/A</span>}
                    </td>
                    <td className="p-3 font-sans">
                      <span className="px-2 py-0.5 rounded bg-indigo-50 dark:bg-sky-500/10 text-indigo-600 dark:text-sky-400 font-bold text-[10px] uppercase">
                        {inc.status}
                      </span>
                    </td>
                    <td className="p-3 font-sans text-slate-500 dark:text-slate-400 max-w-md">{inc.reason || 'Not Available'}</td>
                    <td className="p-3 font-sans text-slate-700 dark:text-slate-300">{inc.assignedTo || 'Not Available'}</td>
                    <td className="p-3 text-slate-500 dark:text-slate-400 whitespace-nowrap">
                      {new Date(inc.createdAt).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div data-testid="no-incident-data" className="p-12 text-center text-slate-500 dark:text-slate-400 space-y-2">
            <AlertTriangle className="h-10 w-10 text-slate-400 mx-auto" />
            <p className="text-sm font-semibold text-slate-700 dark:text-slate-200">No Incident Data Available</p>
            <p className="text-xs text-slate-400">The currently selected analysis does not contain any incidents.</p>
          </div>
        )}
      </div>

      {/* Analyst Incident Creation Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-[#111726] border border-slate-200 dark:border-slate-800 rounded-2xl p-6 max-w-md w-full space-y-4 shadow-2xl">
            <div className="flex justify-between items-center border-b border-slate-200 dark:border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-rose-500" />
                Create Analyst Incident
              </h3>
              <button onClick={() => setIsModalOpen(false)} className="text-slate-400 hover:text-slate-600 dark:hover:text-white transition">
                <X className="h-4 w-4" />
              </button>
            </div>

            {formError && (
              <div className="p-3 bg-rose-500/10 border border-rose-500/20 text-rose-700 dark:text-rose-300 rounded-xl text-xs">
                {formError}
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-600 dark:text-slate-400 font-semibold mb-1">Incident Title *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g., Suspicious C2 Connection Detected"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 focus:border-indigo-500 dark:focus:border-sky-500 rounded-xl p-2.5 text-slate-900 dark:text-slate-100 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-slate-600 dark:text-slate-400 font-semibold mb-1">Severity</label>
                <select
                  value={severity}
                  onChange={(e) => setSeverity(e.target.value)}
                  className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 focus:border-indigo-500 dark:focus:border-sky-500 rounded-xl p-2.5 text-slate-900 dark:text-slate-100 focus:outline-none cursor-pointer"
                >
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-600 dark:text-slate-400 font-semibold mb-1">Reason / Justification</label>
                <textarea
                  placeholder="Explain analyst findings requiring incident creation..."
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 focus:border-indigo-500 dark:focus:border-sky-500 rounded-xl p-2.5 text-slate-900 dark:text-slate-100 focus:outline-none h-20"
                />
              </div>

              <div>
                <label className="block text-slate-600 dark:text-slate-400 font-semibold mb-1">Assigned Analyst</label>
                <input
                  type="text"
                  placeholder="e.g., Analyst John"
                  value={assignedTo}
                  onChange={(e) => setAssignedTo(e.target.value)}
                  className="w-full bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 focus:border-indigo-500 dark:focus:border-sky-500 rounded-xl p-2.5 text-slate-900 dark:text-slate-100 focus:outline-none"
                />
              </div>

              <div className="pt-2 flex justify-end space-x-2">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  className="px-4 py-2 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 rounded-xl transition font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createMutation.isPending}
                  className="px-4 py-2 bg-rose-600 hover:bg-rose-700 text-white rounded-xl transition font-medium shadow-md"
                >
                  {createMutation.isPending ? 'Creating...' : 'Create Incident'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
