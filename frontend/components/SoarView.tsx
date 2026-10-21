'use client';

import React, { useState } from 'react';
import { useAnalysisContext } from '@/context/AnalysisContext';
import { fetchAnalysisSoar, createAnalystSoarAction, SoarResponse, SoarRecord } from '@/lib/api';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Zap,
  AlertTriangle,
  Upload,
  Plus,
  X,
  Shield,
  CheckCircle2,
  Clock,
  Play,
  AlertOctagon,
  HelpCircle,
  Activity,
  UserCheck,
} from 'lucide-react';

interface SoarViewProps {
  onOpenUpload: () => void;
}

const PRESET_PLAYBOOKS = [
  { name: 'Isolate Host from Network', type: 'Host Isolation', defaultTarget: 'Affected Endpoint' },
  { name: 'Block Malicious IP in Firewall', type: 'Firewall Rule', defaultTarget: 'C2 Source IP' },
  { name: 'Quarantine Malicious Executable', type: 'Endpoint Quarantine', defaultTarget: 'Suspicious Process/Hash' },
  { name: 'Revoke Compromised Credentials', type: 'Access Control', defaultTarget: 'Compromised User' },
  { name: 'Collect Forensics Memory Dump', type: 'Forensics Triage', defaultTarget: 'Target Host' },
];

export function SoarView({ onOpenUpload }: SoarViewProps) {
  const { currentAnalysisId } = useAnalysisContext();
  const queryClient = useQueryClient();

  // Modal State
  const [isModalOpen, setIsModalOpen] = useState<boolean>(false);
  const [selectedPreset, setSelectedPreset] = useState<string>(PRESET_PLAYBOOKS[0].name);
  const [customActionName, setCustomActionName] = useState<string>('');
  const [actionType, setActionType] = useState<string>(PRESET_PLAYBOOKS[0].type);
  const [target, setTarget] = useState<string>('');
  const [description, setDescription] = useState<string>('');
  const [triggeredBy, setTriggeredBy] = useState<string>('Analyst Alice');
  const [isSimulation, setIsSimulation] = useState<boolean>(true);
  const [isConfirmed, setIsConfirmed] = useState<boolean>(false);
  const [formError, setFormError] = useState<string | null>(null);

  // TanStack Query for Analysis-Scoped SOAR Data
  const {
    data: soarData,
    isLoading,
    isError,
    error,
  } = useQuery<SoarResponse>({
    queryKey: ['analysis', currentAnalysisId, 'soar'],
    queryFn: () => fetchAnalysisSoar(currentAnalysisId!),
    enabled: Boolean(currentAnalysisId),
  });

  // Mutation for Analyst Triggered SOAR Action
  const createMutation = useMutation({
    mutationFn: (payload: {
      actionName: string;
      description?: string;
      actionType?: string;
      target?: string;
      status?: string;
      triggeredBy?: string;
      isSimulation?: boolean;
      confirmed?: boolean;
      isConfirmed?: boolean;
    }) => createAnalystSoarAction(currentAnalysisId!, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['analysis', currentAnalysisId, 'soar'] });
      closeModal();
    },
    onError: (err: any) => {
      setFormError(err instanceof Error ? err.message : 'Failed to execute SOAR action');
    },
  });

  const closeModal = () => {
    setIsModalOpen(false);
    setCustomActionName('');
    setTarget('');
    setDescription('');
    setIsConfirmed(false);
    setFormError(null);
  };

  const handlePresetChange = (presetName: string) => {
    setSelectedPreset(presetName);
    const found = PRESET_PLAYBOOKS.find((p) => p.name === presetName);
    if (found) {
      setActionType(found.type);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const finalActionName = selectedPreset === 'Custom' ? customActionName.trim() : selectedPreset;
    
    if (!finalActionName) {
      setFormError('Playbook / Action name is required.');
      return;
    }
    if (!isConfirmed) {
      setFormError('Please confirm the execution notice before proceeding.');
      return;
    }

    createMutation.mutate({
      actionName: finalActionName,
      description: description.trim() || `Analyst-triggered response playbook: ${finalActionName}`,
      actionType,
      target: target.trim() || undefined,
      triggeredBy: triggeredBy.trim() || 'Analyst',
      isSimulation,
      confirmed: true,
      isConfirmed: true,
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
          <div className="h-16 w-16 bg-amber-500/10 border border-amber-500/20 rounded-2xl flex items-center justify-center text-amber-400 mx-auto shadow-inner">
            <Zap className="h-8 w-8" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-slate-100">No Active Analysis Selected</h2>
            <p className="text-xs text-slate-400 mt-2 leading-relaxed">
              Select an active security analysis from the top dropdown or upload a file to view SOAR Playbooks & Actions.
            </p>
          </div>
          <button
            onClick={onOpenUpload}
            className="w-full bg-amber-600 hover:bg-amber-500 text-white font-medium text-xs py-3 rounded-xl transition shadow-lg shadow-amber-600/20 flex items-center justify-center space-x-2"
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
          <div className="h-10 w-10 border-4 border-amber-500/30 border-t-amber-500 rounded-full animate-spin" />
          <p className="text-xs font-mono text-slate-400">Loading SOAR Actions for {currentAnalysisId}...</p>
        </div>
      </div>
    );
  }

  // 3. ERROR STATE
  if (isError || !soarData) {
    return (
      <div
        data-testid="error-state"
        className="flex-1 flex items-center justify-center p-12 bg-[#0a0d14]"
      >
        <div className="bg-rose-500/10 border border-rose-500/20 rounded-2xl p-6 text-center max-w-md text-rose-300 space-y-3">
          <AlertTriangle className="h-8 w-8 text-rose-400 mx-auto" />
          <h3 className="text-sm font-bold">Failed to Load SOAR Data</h3>
          <p className="text-xs">{error instanceof Error ? error.message : 'SOAR execution records could not be retrieved.'}</p>
        </div>
      </div>
    );
  }

  const soarRecords = soarData.soarExecutions || [];

  const getStatusBadge = (status: string) => {
    const s = (status || '').toUpperCase();
    switch (s) {
      case 'COMPLETED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[10px] font-bold uppercase">
            <CheckCircle2 className="h-3 w-3" /> Completed
          </span>
        );
      case 'SIMULATION':
      case 'DRY_RUN':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/20 text-[10px] font-bold uppercase">
            <Zap className="h-3 w-3" /> Simulation (Dry Run)
          </span>
        );
      case 'PENDING_APPROVAL':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-yellow-500/10 text-yellow-400 border border-yellow-500/20 text-[10px] font-bold uppercase">
            <Clock className="h-3 w-3" /> Pending Approval
          </span>
        );
      case 'RECOMMENDED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-purple-500/10 text-purple-400 border border-purple-500/20 text-[10px] font-bold uppercase">
            <HelpCircle className="h-3 w-3" /> Recommended
          </span>
        );
      case 'RUNNING':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-sky-500/10 text-sky-400 border border-sky-500/20 text-[10px] font-bold uppercase">
            <Activity className="h-3 w-3 animate-spin" /> Running
          </span>
        );
      case 'FAILED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-rose-500/10 text-rose-400 border border-rose-500/20 text-[10px] font-bold uppercase">
            <AlertOctagon className="h-3 w-3" /> Failed
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-slate-500/10 text-slate-400 border border-slate-500/20 text-[10px] font-bold uppercase">
            {status || 'Pending'}
          </span>
        );
    }
  };

  return (
    <div data-testid="soar-view" className="flex-1 p-6 md:p-8 bg-[#0a0d14] text-slate-100 overflow-y-auto space-y-6">
      
      {/* Header Bar */}
      <div className="bg-[#111726] border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div className="flex items-center space-x-3">
            <div className="h-10 w-10 bg-amber-500/10 border border-amber-500/20 rounded-xl flex items-center justify-center text-amber-400 shadow-inner">
              <Zap className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white tracking-tight">SOAR Orchestration & Playbooks</h2>
              <p className="text-xs text-slate-400">Analysis-Scoped Response Actions &bull; ID: <span className="font-mono text-slate-300">{currentAnalysisId}</span></p>
            </div>
          </div>

          <div className="flex items-center space-x-3">
            <button
              onClick={() => setIsModalOpen(true)}
              disabled={soarData.totalCount === 0}
              className={`flex items-center space-x-2 text-white font-medium text-xs px-4 py-2 rounded-lg transition shadow-lg ${
                soarData.totalCount === 0
                  ? 'bg-slate-700/60 opacity-50 cursor-not-allowed shadow-none'
                  : 'bg-amber-600 hover:bg-amber-500 shadow-amber-600/20 active:scale-95'
              }`}
            >
              <Play className="h-3.5 w-3.5 fill-current" />
              <span>Execute Playbook</span>
            </button>
            <span className="text-xs font-bold text-amber-400 bg-amber-500/10 border border-amber-500/20 px-3 py-1.5 rounded-lg flex items-center gap-2 font-mono">
              <Shield className="h-4 w-4" />
              <span>{soarData.totalCount} Playbooks</span>
            </span>
          </div>
        </div>

        <div className="text-xs text-slate-400 leading-relaxed bg-slate-900/50 p-3 rounded-xl border border-slate-800/80 flex items-center gap-2">
          <Shield className="h-4 w-4 text-amber-400 shrink-0" />
          <span>
            <strong>Execution Safety Notice:</strong> High risk scores and critical threat levels do <em>not</em> trigger automatic response actions. Response playbooks are strictly analyst-triggered or source-preserved.
          </span>
        </div>
      </div>

      {/* SOAR Actions Table */}
      <div className="bg-[#111726] border border-slate-800 rounded-2xl p-6 shadow-lg space-y-4">
        {soarRecords.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/80 text-slate-400 uppercase text-[10px] font-bold border-b border-slate-800">
                <tr>
                  <th className="p-3">Action / Playbook</th>
                  <th className="p-3">Action Type</th>
                  <th className="p-3">Status</th>
                  <th className="p-3">Origin / Triggered By</th>
                  <th className="p-3">Target Entity</th>
                  <th className="p-3">Result / Execution Audit</th>
                  <th className="p-3">Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono text-slate-300">
                {soarRecords.map((rec) => (
                  <tr key={rec.id} className="hover:bg-slate-800/30 transition">
                    <td className="p-3 font-bold text-slate-100 font-sans">
                      <div>{rec.actionName}</div>
                      {rec.description && <div className="text-[11px] text-slate-400 font-normal mt-0.5">{rec.description}</div>}
                    </td>
                    <td className="p-3 font-sans">
                      <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300 font-medium text-[10px]">
                        {rec.actionType || 'Playbook Action'}
                      </span>
                    </td>
                    <td className="p-3 font-sans">{getStatusBadge(rec.status)}</td>
                    <td className="p-3 font-sans">
                      <div className="flex items-center gap-1.5">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          rec.source === 'Analyst'
                            ? 'bg-sky-500/20 text-sky-400 border border-sky-500/30'
                            : 'bg-indigo-500/20 text-indigo-400 border border-indigo-500/30'
                        }`}>
                          {rec.source || 'Source'}
                        </span>
                        <span className="text-slate-400 text-[11px]">({rec.triggeredBy || 'System'})</span>
                      </div>
                    </td>
                    <td className="p-3 font-sans text-slate-300">{rec.target || 'Not Available'}</td>
                    <td className="p-3 font-sans text-slate-400 max-w-xs truncate" title={rec.executionLog || rec.result || 'Not Available'}>
                      {rec.result || rec.executionLog || 'Not Available'}
                    </td>
                    <td className="p-3 text-slate-400 whitespace-nowrap">
                      {new Date(rec.timestamp).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div data-testid="no-soar-data" className="p-12 text-center text-slate-400 space-y-2">
            <Zap className="h-10 w-10 text-slate-500 mx-auto" />
            <p className="text-sm font-semibold text-slate-200">No SOAR Actions Available</p>
            <p className="text-xs text-slate-500">The currently selected analysis does not contain any SOAR records.</p>
          </div>
        )}
      </div>

      {/* Analyst Playbook Execution Confirmation Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-[#111726] border border-slate-800 rounded-2xl p-6 max-w-lg w-full space-y-5 shadow-2xl">
            <div className="flex justify-between items-center border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <Zap className="h-4 w-4 text-amber-400" />
                Execute Analyst Response Playbook
              </h3>
              <button onClick={closeModal} className="text-slate-400 hover:text-white transition">
                <X className="h-4 w-4" />
              </button>
            </div>

            {formError && (
              <div className="p-3 bg-rose-500/10 border border-rose-500/20 text-rose-300 rounded-xl text-xs">
                {formError}
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-400 font-semibold mb-1">Select Response Playbook</label>
                <select
                  value={selectedPreset}
                  onChange={(e) => handlePresetChange(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 focus:border-amber-500 rounded-xl p-2.5 text-slate-200 focus:outline-none cursor-pointer"
                >
                  {PRESET_PLAYBOOKS.map((p) => (
                    <option key={p.name} value={p.name}>
                      {p.name} ({p.type})
                    </option>
                  ))}
                  <option value="Custom">Custom Action / Playbook</option>
                </select>
              </div>

              {selectedPreset === 'Custom' && (
                <div>
                  <label className="block text-slate-400 font-semibold mb-1">Custom Playbook Name *</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g., Block Hash on EDR Endpoint"
                    value={customActionName}
                    onChange={(e) => setCustomActionName(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-800 focus:border-amber-500 rounded-xl p-2.5 text-slate-200 focus:outline-none"
                  />
                </div>
              )}

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 font-semibold mb-1">Action Type</label>
                  <input
                    type="text"
                    value={actionType}
                    onChange={(e) => setActionType(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-800 focus:border-amber-500 rounded-xl p-2.5 text-slate-200 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 font-semibold mb-1">Target Entity / Host / IP</label>
                  <input
                    type="text"
                    placeholder="e.g. 192.168.1.105 or Host01"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-800 focus:border-amber-500 rounded-xl p-2.5 text-slate-200 focus:outline-none"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-400 font-semibold mb-1">Triggering Analyst</label>
                <input
                  type="text"
                  value={triggeredBy}
                  onChange={(e) => setTriggeredBy(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 focus:border-amber-500 rounded-xl p-2.5 text-slate-200 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-slate-400 font-semibold mb-1">Action Description / Justification</label>
                <textarea
                  placeholder="Reason for triggering playbook response..."
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 focus:border-amber-500 rounded-xl p-2.5 text-slate-200 focus:outline-none h-16"
                />
              </div>

              {/* Execution Confirmation Step & Safety Notice */}
              <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-3.5 space-y-2">
                <div className="flex items-center gap-2 text-amber-300 font-bold">
                  <Shield className="h-4 w-4 text-amber-400 shrink-0" />
                  <span>Confirmation & Safety Verification</span>
                </div>
                <div className="text-[11px] text-amber-200/90 leading-relaxed font-mono bg-slate-950/60 p-2 rounded border border-amber-500/20">
                  <div>Playbook: <span className="text-white font-bold">{selectedPreset === 'Custom' ? customActionName || 'Custom' : selectedPreset}</span></div>
                  <div>Analysis Scope: <span className="text-amber-300">{currentAnalysisId}</span></div>
                  <div>Mode: <span className="text-emerald-400 font-bold">Dry Run / Simulation (Safe Audit Mode)</span></div>
                </div>

                <label className="flex items-start gap-2 pt-1 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={isConfirmed}
                    onChange={(e) => setIsConfirmed(e.target.checked)}
                    className="mt-0.5 rounded border-amber-500 text-amber-600 focus:ring-amber-500"
                  />
                  <span className="text-[11px] text-slate-300">
                    I confirm execution of this response playbook for analysis <strong>{currentAnalysisId}</strong> in dry-run mode.
                  </span>
                </label>
              </div>

              <div className="pt-2 flex justify-end space-x-2">
                <button
                  type="button"
                  onClick={closeModal}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl transition font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createMutation.isPending || !isConfirmed}
                  className="px-4 py-2 bg-amber-600 hover:bg-amber-500 disabled:opacity-50 text-white rounded-xl transition font-medium shadow-lg shadow-amber-600/20 flex items-center gap-1.5"
                >
                  <Play className="h-3.5 w-3.5 fill-current" />
                  <span>{createMutation.isPending ? 'Executing...' : 'Confirm & Execute'}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

    </div>
  );
}
