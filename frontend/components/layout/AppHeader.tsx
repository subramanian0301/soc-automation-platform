'use client';

import React from 'react';
import { useAnalysisContext } from '@/context/AnalysisContext';
import { useTheme } from '@/context/ThemeContext';
import { fetchAllAnalyses, UploadResponse } from '@/lib/api';
import { useQuery } from '@tanstack/react-query';
import { ActiveTabType } from '@/components/Navbar';
import {
  FileText,
  ChevronDown,
  Check,
  X,
  Upload,
  Sun,
  Moon,
} from 'lucide-react';

interface AppHeaderProps {
  activeTab: ActiveTabType;
  onOpenUpload: () => void;
}

const TAB_TITLE_MAP: Record<ActiveTabType, { title: string; category: string }> = {
  dashboard: { title: 'Security Overview', category: 'Workspace' },
  siem: { title: 'SIEM Log Analyzer', category: 'Workspace' },
  iocs: { title: 'IOC Search & Analysis', category: 'Workspace' },
  'threat-intel': { title: 'Threat Intelligence', category: 'Workspace' },
  mitre: { title: 'MITRE ATT&CK Mapping', category: 'Workspace' },
  behavior: { title: 'Behavior Analysis', category: 'Workspace' },
  sandbox: { title: 'Sandbox Execution', category: 'Workspace' },
  incidents: { title: 'Incident Response', category: 'Response' },
  cases: { title: 'Case Management', category: 'Response' },
  soar: { title: 'SOAR Orchestration (Simulated)', category: 'Response' },
  assets: { title: 'Asset Inventory', category: 'Infrastructure' },
  endpoints: { title: 'Endpoint Management', category: 'Infrastructure' },
  vulnerabilities: { title: 'Vulnerability Center', category: 'Infrastructure' },
  reports: { title: 'Reports & Analytics', category: 'Management' },
};

export function AppHeader({ activeTab, onOpenUpload }: AppHeaderProps) {
  const { currentAnalysisId, setCurrentAnalysisId, clearAnalysis } = useAnalysisContext();
  const { theme, toggleTheme } = useTheme();

  const { data: analysesList = [] } = useQuery<UploadResponse[]>({
    queryKey: ['analyses-list'],
    queryFn: fetchAllAnalyses,
    refetchInterval: 10000,
  });

  const selectedAnalysis = analysesList.find((a) => a.analysisId === currentAnalysisId);
  const currentTabMeta = TAB_TITLE_MAP[activeTab] || { title: 'Dashboard', category: 'Workspace' };

  return (
    <header className="h-16 bg-white dark:bg-[#0d111a] border-b border-slate-200 dark:border-slate-800/80 px-6 flex items-center justify-between sticky top-0 z-30 shadow-xs">
      {/* Breadcrumb Navigation */}
      <div className="flex items-center space-x-2 text-xs">
        <span className="font-medium text-slate-400 dark:text-slate-500">
          {currentTabMeta.category}
        </span>
        <span className="text-slate-300 dark:text-slate-700">/</span>
        <span className="font-semibold text-slate-800 dark:text-slate-200">
          {currentTabMeta.title}
        </span>
      </div>

      {/* Header Actions */}
      <div className="flex items-center space-x-3">
        {/* Active Analysis Selector Dropdown */}
        <div className="relative group">
          <div className="flex items-center space-x-2 bg-slate-100 dark:bg-[#141b2d] border border-slate-200 dark:border-slate-700/60 hover:border-slate-300 dark:hover:border-slate-600 px-3 py-1.5 rounded-lg text-xs transition cursor-pointer">
            <FileText className="h-4 w-4 text-indigo-600 dark:text-sky-400" />
            <div className="flex flex-col text-left max-w-[180px] truncate">
              <span className="text-[9px] uppercase font-bold text-slate-400 tracking-wider">
                Active Analysis
              </span>
              <span className="font-semibold text-slate-800 dark:text-slate-200 truncate">
                {selectedAnalysis ? selectedAnalysis.originalFileName : currentAnalysisId || 'None Selected'}
              </span>
            </div>
            <ChevronDown className="h-4 w-4 text-slate-400 ml-1" />
          </div>

          {/* Dropdown Menu */}
          <div className="absolute right-0 top-full mt-2 w-72 bg-white dark:bg-[#111726] border border-slate-200 dark:border-slate-800 rounded-xl shadow-xl py-2 hidden group-hover:block z-50">
            <div className="px-3 py-1.5 text-[10px] font-bold text-slate-400 uppercase tracking-wider border-b border-slate-100 dark:border-slate-800 flex justify-between items-center">
              <span>Historical Analyses</span>
              <span>{analysesList.length} total</span>
            </div>

            <div className="max-h-60 overflow-y-auto divide-y divide-slate-100 dark:divide-slate-800/50">
              {analysesList.length === 0 ? (
                <div className="px-4 py-3 text-xs text-slate-400 text-center">
                  No analyses available.
                </div>
              ) : (
                analysesList.map((item) => {
                  const isSelected = item.analysisId === currentAnalysisId;
                  return (
                    <button
                      key={item.analysisId}
                      onClick={() => setCurrentAnalysisId(item.analysisId)}
                      className={`w-full text-left px-3 py-2 text-xs flex items-center justify-between hover:bg-slate-50 dark:hover:bg-slate-800/50 transition ${
                        isSelected ? 'bg-indigo-50 dark:bg-sky-500/10 text-indigo-600 dark:text-sky-400 font-semibold' : 'text-slate-700 dark:text-slate-300'
                      }`}
                    >
                      <div className="flex flex-col truncate pr-2">
                        <span className="truncate">{item.originalFileName}</span>
                        <span className="text-[10px] text-slate-400">
                          {item.fileType} &bull; {new Date(item.uploadedAt).toLocaleTimeString()}
                        </span>
                      </div>
                      {isSelected && <Check className="h-3.5 w-3.5 text-indigo-600 dark:text-sky-400 shrink-0" />}
                    </button>
                  );
                })
              )}
            </div>

            {currentAnalysisId && (
              <div className="border-t border-slate-100 dark:border-slate-800 pt-1 mt-1 px-2">
                <button
                  onClick={clearAnalysis}
                  className="w-full text-left px-2 py-1.5 text-xs text-rose-600 dark:text-rose-400 hover:bg-rose-50 dark:hover:bg-rose-500/10 rounded flex items-center gap-1.5 transition"
                >
                  <X className="h-3.5 w-3.5" />
                  Clear Active Analysis
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Light / Dark Theme Switcher Button */}
        <button
          onClick={toggleTheme}
          aria-label="Toggle Theme"
          className="p-2 rounded-lg bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700 transition"
          title={`Switch to ${theme === 'light' ? 'Dark' : 'Light'} Mode`}
        >
          {theme === 'light' ? (
            <Moon className="w-4 h-4 text-indigo-600" />
          ) : (
            <Sun className="w-4 h-4 text-amber-400" />
          )}
        </button>

        {/* Upload File CTA */}
        <button
          onClick={onOpenUpload}
          className="flex items-center space-x-2 bg-indigo-600 hover:bg-indigo-700 dark:bg-sky-600 dark:hover:bg-sky-500 text-white font-medium text-xs px-3.5 py-2 rounded-lg transition shadow-sm active:scale-95"
        >
          <Upload className="h-4 w-4" />
          <span>Upload File</span>
        </button>
      </div>
    </header>
  );
}
