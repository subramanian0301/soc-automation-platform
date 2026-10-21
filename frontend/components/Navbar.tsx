'use client';

import React from 'react';
import { useAnalysisContext } from '@/context/AnalysisContext';
import { fetchAllAnalyses, UploadResponse } from '@/lib/api';
import { useQuery } from '@tanstack/react-query';
import {
  ShieldAlert,
  Upload,
  FileText,
  ChevronDown,
  Check,
  X,
  LayoutGrid,
  Terminal,
  Layers,
  Zap,
  Server,
  Monitor,
  Bug,
} from 'lucide-react';

export type ActiveTabType =
  | 'dashboard'
  | 'siem'
  | 'iocs'
  | 'threat-intel'
  | 'mitre'
  | 'behavior'
  | 'sandbox'
  | 'incidents'
  | 'cases'
  | 'soar'
  | 'assets'
  | 'endpoints'
  | 'vulnerabilities'
  | 'reports';

interface NavbarProps {
  onOpenUpload: () => void;
  activeTab?: ActiveTabType;
  onTabChange?: (tab: ActiveTabType) => void;
}

export function Navbar({ onOpenUpload, activeTab = 'dashboard', onTabChange }: NavbarProps) {
  const { currentAnalysisId, setCurrentAnalysisId, clearAnalysis } = useAnalysisContext();

  const { data: analysesList = [] } = useQuery<UploadResponse[]>({
    queryKey: ['analyses-list'],
    queryFn: fetchAllAnalyses,
    refetchInterval: 10000,
  });

  const selectedAnalysis = analysesList.find((a) => a.analysisId === currentAnalysisId);

  return (
    <header className="h-16 border-b border-slate-800 bg-[#0d111a] px-6 flex items-center justify-between sticky top-0 z-40 shadow-md">
      {/* Brand Logo */}
      <div className="flex items-center space-x-6">
        <div className="flex items-center space-x-3">
          <div className="h-9 w-9 rounded-lg bg-sky-500/10 border border-sky-500/20 flex items-center justify-center text-sky-400 shadow-inner">
            <ShieldAlert className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-base font-bold text-slate-100 tracking-tight flex items-center gap-2">
              SOC Security Platform
              <span className="text-[10px] font-semibold uppercase px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                Live API
              </span>
            </h1>
            <p className="text-[11px] text-slate-400">Single Backend &bull; Source-of-Truth Engine</p>
          </div>
        </div>

        {/* Module Navigation Tabs */}
        {onTabChange && (
          <nav className="hidden xl:flex items-center space-x-1 bg-slate-900/80 p-1 border border-slate-800 rounded-xl overflow-x-auto">
            <button
              onClick={() => onTabChange('dashboard')}
              className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold transition ${
                activeTab === 'dashboard'
                  ? 'bg-sky-500/20 text-sky-400 border border-sky-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <LayoutGrid className="h-3.5 w-3.5" />
              <span>Dashboard</span>
            </button>
            <button
              onClick={() => onTabChange('siem')}
              className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold transition ${
                activeTab === 'siem'
                  ? 'bg-sky-500/20 text-sky-400 border border-sky-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <Terminal className="h-3.5 w-3.5" />
              <span>SIEM</span>
            </button>
            <button
              onClick={() => onTabChange('iocs')}
              className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold transition ${
                activeTab === 'iocs'
                  ? 'bg-sky-500/20 text-sky-400 border border-sky-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <Layers className="h-3.5 w-3.5" />
              <span>IOC Search</span>
            </button>
            <button
              onClick={() => onTabChange('threat-intel')}
              className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold transition ${
                activeTab === 'threat-intel'
                  ? 'bg-sky-500/20 text-sky-400 border border-sky-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <ShieldAlert className="h-3.5 w-3.5" />
              <span>Threat Intel</span>
            </button>
            <button
              onClick={() => onTabChange('mitre')}
              className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold transition ${
                activeTab === 'mitre'
                  ? 'bg-sky-500/20 text-sky-400 border border-sky-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <span>MITRE</span>
            </button>
            <button
              onClick={() => onTabChange('behavior')}
              className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold transition ${
                activeTab === 'behavior'
                  ? 'bg-sky-500/20 text-sky-400 border border-sky-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <span>Behavior</span>
            </button>
            <button
              onClick={() => onTabChange('sandbox')}
              className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold transition ${
                activeTab === 'sandbox'
                  ? 'bg-sky-500/20 text-sky-400 border border-sky-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <span>Sandbox</span>
            </button>
            <button
              onClick={() => onTabChange('incidents')}
              className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold transition ${
                activeTab === 'incidents'
                  ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <span>Incidents</span>
            </button>
            <button
              onClick={() => onTabChange('cases')}
              className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold transition ${
                activeTab === 'cases'
                  ? 'bg-sky-500/20 text-sky-400 border border-sky-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <span>Cases</span>
            </button>
            <button
              onClick={() => onTabChange('soar')}
              className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold transition ${
                activeTab === 'soar'
                  ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <Zap className="h-3.5 w-3.5 text-amber-400" />
              <span>SOAR</span>
            </button>
            <button
              onClick={() => onTabChange('assets')}
              className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold transition ${
                activeTab === 'assets'
                  ? 'bg-sky-500/20 text-sky-400 border border-sky-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <Server className="h-3.5 w-3.5 text-sky-400" />
              <span>Assets</span>
            </button>
            <button
              onClick={() => onTabChange('endpoints')}
              className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold transition ${
                activeTab === 'endpoints'
                  ? 'bg-sky-500/20 text-sky-400 border border-sky-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <Monitor className="h-3.5 w-3.5 text-sky-400" />
              <span>Endpoints</span>
            </button>
            <button
              onClick={() => onTabChange('vulnerabilities')}
              className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold transition ${
                activeTab === 'vulnerabilities'
                  ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <Bug className="h-3.5 w-3.5 text-rose-400" />
              <span>Vulnerabilities</span>
            </button>
            <button
              onClick={() => onTabChange('reports')}
              className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold transition ${
                activeTab === 'reports'
                  ? 'bg-sky-500/20 text-sky-400 border border-sky-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <FileText className="h-3.5 w-3.5 text-sky-400" />
              <span>Reports</span>
            </button>
          </nav>
        )}
      </div>



      {/* Active Analysis Selector Dropdown & Actions */}
      <div className="flex items-center space-x-4">
        {/* Sample Selector */}
        <div className="relative group">
          <div className="flex items-center space-x-2 bg-[#141b2d] border border-slate-700/60 hover:border-slate-600 px-3 py-1.5 rounded-lg text-xs transition cursor-pointer">
            <FileText className="h-4 w-4 text-sky-400" />
            <div className="flex flex-col text-left max-w-[200px] truncate">
              <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">
                Active Analysis
              </span>
              <span className="font-semibold text-slate-200 truncate">
                {selectedAnalysis ? selectedAnalysis.originalFileName : currentAnalysisId || 'None Selected'}
              </span>
            </div>
            <ChevronDown className="h-4 w-4 text-slate-400 ml-1" />
          </div>

          {/* Dropdown Options */}
          <div className="absolute right-0 top-full mt-2 w-72 bg-[#111726] border border-slate-800 rounded-xl shadow-2xl py-2 hidden group-hover:block z-50">
            <div className="px-3 py-1.5 text-[10px] font-bold text-slate-400 uppercase tracking-wider border-b border-slate-800 flex justify-between items-center">
              <span>Historical Analyses</span>
              <span>{analysesList.length} total</span>
            </div>

            <div className="max-h-60 overflow-y-auto divide-y divide-slate-800/50">
              {analysesList.length === 0 ? (
                <div className="px-4 py-3 text-xs text-slate-400 text-center">
                  No analyses uploaded yet.
                </div>
              ) : (
                analysesList.map((item) => {
                  const isSelected = item.analysisId === currentAnalysisId;
                  return (
                    <button
                      key={item.analysisId}
                      onClick={() => setCurrentAnalysisId(item.analysisId)}
                      className={`w-full text-left px-3 py-2 text-xs flex items-center justify-between hover:bg-slate-800/50 transition ${
                        isSelected ? 'bg-sky-500/10 text-sky-400 font-semibold' : 'text-slate-300'
                      }`}
                    >
                      <div className="flex flex-col truncate pr-2">
                        <span className="truncate">{item.originalFileName}</span>
                        <span className="text-[10px] text-slate-400">
                          {item.fileType} &bull; {new Date(item.uploadedAt).toLocaleTimeString()}
                        </span>
                      </div>
                      {isSelected && <Check className="h-3.5 w-3.5 text-sky-400 shrink-0" />}
                    </button>
                  );
                })
              )}
            </div>

            {currentAnalysisId && (
              <div className="border-t border-slate-800 pt-1 mt-1 px-2">
                <button
                  onClick={clearAnalysis}
                  className="w-full text-left px-2 py-1.5 text-xs text-rose-400 hover:bg-rose-500/10 rounded flex items-center gap-1.5 transition"
                >
                  <X className="h-3.5 w-3.5" />
                  Clear Selection
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Upload Button */}
        <button
          onClick={onOpenUpload}
          className="flex items-center space-x-2 bg-sky-600 hover:bg-sky-500 text-white font-medium text-xs px-4 py-2 rounded-lg transition shadow-lg shadow-sky-600/20 active:scale-95"
        >
          <Upload className="h-4 w-4" />
          <span>Upload File</span>
        </button>
      </div>
    </header>
  );
}

