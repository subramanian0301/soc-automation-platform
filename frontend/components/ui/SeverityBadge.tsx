'use client';

import React from 'react';

interface SeverityBadgeProps {
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | string;
  size?: 'sm' | 'md' | 'lg';
}

export function SeverityBadge({ severity, size = 'sm' }: SeverityBadgeProps) {
  const norm = (severity || 'INFO').toUpperCase();

  const getStyles = () => {
    switch (norm) {
      case 'CRITICAL':
        return 'bg-rose-500/10 text-rose-700 dark:text-rose-400 border-rose-500/30';
      case 'HIGH':
        return 'bg-amber-500/10 text-amber-700 dark:text-amber-400 border-amber-500/30';
      case 'MEDIUM':
        return 'bg-yellow-500/10 text-yellow-700 dark:text-yellow-400 border-yellow-500/30';
      case 'LOW':
        return 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-500/30';
      case 'INFO':
      default:
        return 'bg-blue-500/10 text-blue-700 dark:text-blue-400 border-blue-500/30';
    }
  };

  const sizeClasses =
    size === 'sm'
      ? 'px-2 py-0.5 text-[11px]'
      : size === 'md'
      ? 'px-2.5 py-1 text-xs'
      : 'px-3 py-1 text-sm';

  return (
    <span
      className={`inline-flex items-center font-semibold rounded-md border ${getStyles()} ${sizeClasses}`}
    >
      <span className="w-1.5 h-1.5 rounded-full bg-current mr-1.5 opacity-80" />
      {norm}
    </span>
  );
}
