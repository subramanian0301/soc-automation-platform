'use client';

import React from 'react';

interface PageHeaderProps {
  title: string;
  description?: string;
  badge?: string;
  children?: React.ReactNode;
}

export function PageHeader({ title, description, badge, children }: PageHeaderProps) {
  return (
    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
      <div>
        <div className="flex items-center space-x-3">
          <h1 className="text-xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
            {title}
          </h1>
          {badge && (
            <span className="px-2.5 py-0.5 text-[11px] font-bold rounded-full bg-indigo-500/10 text-indigo-600 dark:bg-sky-500/10 dark:text-sky-400 border border-indigo-500/20 dark:border-sky-500/20">
              {badge}
            </span>
          )}
        </div>
        {description && (
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
            {description}
          </p>
        )}
      </div>

      {children && <div className="flex items-center space-x-3">{children}</div>}
    </div>
  );
}
