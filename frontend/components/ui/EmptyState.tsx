'use client';

import React from 'react';
import { ShieldAlert } from 'lucide-react';

interface EmptyStateProps {
  icon?: React.ReactNode;
  title: string;
  description: string;
  action?: {
    label: string;
    onClick: () => void;
  };
}

export function EmptyState({ icon, title, description, action }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center p-12 text-center rounded-xl bg-white dark:bg-[#111726] border border-slate-200 dark:border-slate-800/80 shadow-sm">
      <div className="w-14 h-14 rounded-2xl bg-indigo-500/10 dark:bg-sky-500/10 text-indigo-600 dark:text-sky-400 flex items-center justify-center mb-4">
        {icon || <ShieldAlert className="w-7 h-7" />}
      </div>
      <h3 className="text-base font-bold text-slate-900 dark:text-slate-100 mb-1">
        {title}
      </h3>
      <p className="text-xs text-slate-500 dark:text-slate-400 max-w-sm mb-6">
        {description}
      </p>
      {action && (
        <button
          onClick={action.onClick}
          className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-700 dark:bg-sky-600 dark:hover:bg-sky-500 text-white font-medium text-xs shadow-md transition-all active:scale-95"
        >
          {action.label}
        </button>
      )}
    </div>
  );
}
