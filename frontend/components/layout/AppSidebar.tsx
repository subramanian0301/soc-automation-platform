'use client';

import React, { useState } from 'react';
import { ActiveTabType } from '@/components/Navbar';
import {
  LayoutGrid,
  Terminal,
  Layers,
  ShieldAlert,
  Shield,
  Activity,
  Box,
  AlertTriangle,
  FolderGit2,
  Zap,
  Server,
  Monitor,
  Bug,
  FileText,
  ChevronLeft,
  ChevronRight,
  Menu,
  X,
} from 'lucide-react';

interface AppSidebarProps {
  activeTab: ActiveTabType;
  onTabChange: (tab: ActiveTabType) => void;
}

interface NavItem {
  id: ActiveTabType;
  label: string;
  icon: React.ReactNode;
  badge?: string;
}

interface NavGroup {
  title: string;
  items: NavItem[];
}

export function AppSidebar({ activeTab, onTabChange }: AppSidebarProps) {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  const groups: NavGroup[] = [
    {
      title: 'Workspace',
      items: [
        { id: 'dashboard', label: 'Overview', icon: <LayoutGrid className="w-4 h-4" /> },
        { id: 'siem', label: 'SIEM', icon: <Terminal className="w-4 h-4" /> },
        { id: 'iocs', label: 'IOC Search', icon: <Layers className="w-4 h-4" /> },
        { id: 'threat-intel', label: 'Threat Intel', icon: <ShieldAlert className="w-4 h-4" /> },
        { id: 'mitre', label: 'MITRE ATT&CK', icon: <Shield className="w-4 h-4" /> },
        { id: 'behavior', label: 'Behavior', icon: <Activity className="w-4 h-4" /> },
        { id: 'sandbox', label: 'Sandbox', icon: <Box className="w-4 h-4" /> },
      ],
    },
    {
      title: 'Response',
      items: [
        { id: 'incidents', label: 'Incidents', icon: <AlertTriangle className="w-4 h-4" /> },
        { id: 'cases', label: 'Cases', icon: <FolderGit2 className="w-4 h-4" /> },
        { id: 'soar', label: 'SOAR', icon: <Zap className="w-4 h-4 text-amber-500" /> },
      ],
    },
    {
      title: 'Infrastructure',
      items: [
        { id: 'assets', label: 'Assets', icon: <Server className="w-4 h-4" /> },
        { id: 'endpoints', label: 'Endpoints', icon: <Monitor className="w-4 h-4" /> },
        { id: 'vulnerabilities', label: 'Vulnerabilities', icon: <Bug className="w-4 h-4 text-rose-500" /> },
      ],
    },
    {
      title: 'Management',
      items: [
        { id: 'reports', label: 'Reports', icon: <FileText className="w-4 h-4" /> },
      ],
    },
  ];

  return (
    <>
      {/* Mobile Toggle Button */}
      <button
        onClick={() => setMobileOpen(!mobileOpen)}
        className="lg:hidden fixed bottom-4 right-4 z-50 p-3 rounded-full bg-indigo-600 text-white shadow-xl focus:outline-none"
        aria-label="Toggle Navigation"
      >
        {mobileOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
      </button>

      {/* Mobile Backdrop Overlay */}
      {mobileOpen && (
        <div
          onClick={() => setMobileOpen(false)}
          className="lg:hidden fixed inset-0 bg-slate-900/60 backdrop-blur-sm z-40 transition-opacity"
        />
      )}

      {/* Sidebar Container */}
      <aside
        className={`fixed lg:static top-0 left-0 bottom-0 z-40 bg-white dark:bg-[#0d111a] border-r border-slate-200 dark:border-slate-800/80 transition-all duration-300 flex flex-col ${
          collapsed ? 'w-20' : 'w-64'
        } ${
          mobileOpen ? 'translate-x-0 w-64' : '-translate-x-full lg:translate-x-0'
        }`}
      >
        {/* Brand Header */}
        <div className="h-16 px-4 border-b border-slate-200 dark:border-slate-800/80 flex items-center justify-between">
          <div className="flex items-center space-x-3 overflow-hidden">
            <div className="w-9 h-9 rounded-xl bg-indigo-500/10 dark:bg-sky-500/10 border border-indigo-500/20 dark:border-sky-500/20 flex items-center justify-center text-indigo-600 dark:text-sky-400 shrink-0">
              <ShieldAlert className="w-5 h-5" />
            </div>
            {!collapsed && (
              <div className="flex flex-col truncate">
                <span className="text-sm font-bold text-slate-900 dark:text-slate-100 tracking-tight">
                  SOC Security
                </span>
                <span className="text-[10px] text-slate-500 dark:text-slate-400 uppercase font-semibold">
                  Enterprise v2.0
                </span>
              </div>
            )}
          </div>

          <button
            onClick={() => setCollapsed(!collapsed)}
            className="hidden lg:flex p-1.5 rounded-lg text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition"
            title={collapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
          >
            {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
          </button>
        </div>

        {/* Navigation Group Items */}
        <div className="flex-1 overflow-y-auto py-4 px-3 space-y-6">
          {groups.map((group) => (
            <div key={group.title}>
              {!collapsed && (
                <h2 className="px-3 mb-2 text-[11px] font-bold text-slate-400 dark:text-slate-500 uppercase tracking-wider">
                  {group.title}
                </h2>
              )}
              <div className="space-y-1">
                {group.items.map((item) => {
                  const isActive = activeTab === item.id;
                  return (
                    <button
                      key={item.id}
                      onClick={() => {
                        onTabChange(item.id);
                        setMobileOpen(false);
                      }}
                      title={collapsed ? item.label : undefined}
                      className={`w-full flex items-center space-x-3 px-3 py-2 rounded-xl text-xs font-semibold transition-all duration-150 ${
                        isActive
                          ? 'bg-indigo-600 text-white dark:bg-sky-500/20 dark:text-sky-400 border border-indigo-600 dark:border-sky-500/30 shadow-sm'
                          : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 hover:bg-slate-100 dark:hover:bg-slate-800/60'
                      } ${collapsed ? 'justify-center px-0' : ''}`}
                    >
                      <span className="shrink-0">{item.icon}</span>
                      {!collapsed && <span className="truncate">{item.label}</span>}
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </div>

        {/* Bottom Status Badge */}
        {!collapsed && (
          <div className="p-4 border-t border-slate-200 dark:border-slate-800/80 bg-slate-50/50 dark:bg-slate-900/30">
            <div className="flex items-center space-x-2 text-xs">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              <span className="text-slate-600 dark:text-slate-400 font-medium">Backend Connected</span>
            </div>
          </div>
        )}
      </aside>
    </>
  );
}
