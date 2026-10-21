'use client';

import React from 'react';

interface MetricCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon?: React.ReactNode;
  trend?: {
    value: string;
    isPositive?: boolean;
  };
  variant?: 'default' | 'danger' | 'warning' | 'success';
}

export function MetricCard({
  title,
  value,
  subtitle,
  icon,
  trend,
  variant = 'default',
}: MetricCardProps) {
  const getBorderColor = () => {
    switch (variant) {
      case 'danger':
        return 'border-l-4 border-l-rose-500';
      case 'warning':
        return 'border-l-4 border-l-amber-500';
      case 'success':
        return 'border-l-4 border-l-emerald-500';
      default:
        return 'border-l-4 border-l-indigo-500';
    }
  };

  return (
    <div
      className={`bg-white dark:bg-[#111726] border border-slate-200 dark:border-slate-800/80 rounded-xl p-5 shadow-sm hover:shadow-md transition-all duration-200 ${getBorderColor()}`}
    >
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
          {title}
        </span>
        {icon && (
          <div className="p-2 rounded-lg bg-slate-100 dark:bg-slate-800/60 text-indigo-600 dark:text-sky-400">
            {icon}
          </div>
        )}
      </div>

      <div className="mt-3 flex items-baseline justify-between">
        <span className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
          {value}
        </span>
        {trend && (
          <span
            className={`text-xs font-semibold px-2 py-0.5 rounded-full ${
              trend.isPositive
                ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
                : 'bg-rose-500/10 text-rose-600 dark:text-rose-400'
            }`}
          >
            {trend.value}
          </span>
        )}
      </div>

      {subtitle && (
        <p className="mt-1 text-xs text-slate-500 dark:text-slate-400 truncate">
          {subtitle}
        </p>
      )}
    </div>
  );
}
