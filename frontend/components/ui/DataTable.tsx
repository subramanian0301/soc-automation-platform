'use client';

import React, { useState, useMemo } from 'react';
import { Search, ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight } from 'lucide-react';

export interface Column<T> {
  header: string;
  accessorKey?: keyof T;
  cell?: (item: T) => React.ReactNode;
  className?: string;
}

interface DataTableProps<T> {
  data: T[];
  columns: Column<T>[];
  searchPlaceholder?: string;
  searchFilterKeys?: (keyof T)[];
  initialPageSize?: number;
  onRowClick?: (item: T) => void;
  selectedItemId?: string | null;
  getItemId?: (item: T) => string;
}

export function DataTable<T extends Record<string, any>>({
  data,
  columns,
  searchPlaceholder = 'Search records...',
  searchFilterKeys,
  initialPageSize = 10,
  onRowClick,
  selectedItemId,
  getItemId,
}: DataTableProps<T>) {
  const [searchTerm, setSearchTerm] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(initialPageSize);

  const filteredData = useMemo(() => {
    if (!searchTerm.trim()) return data;
    const term = searchTerm.toLowerCase();

    return data.filter((item) => {
      if (searchFilterKeys && searchFilterKeys.length > 0) {
        return searchFilterKeys.some((key) => {
          const val = item[key];
          return val != null && String(val).toLowerCase().includes(term);
        });
      }
      return Object.values(item).some((val) => val != null && String(val).toLowerCase().includes(term));
    });
  }, [data, searchTerm, searchFilterKeys]);

  const totalPages = Math.max(1, Math.ceil(filteredData.length / pageSize));
  const pageIndex = Math.min(currentPage, totalPages);

  const paginatedData = useMemo(() => {
    const start = (pageIndex - 1) * pageSize;
    return filteredData.slice(start, start + pageSize);
  }, [filteredData, pageIndex, pageSize]);

  return (
    <div className="bg-white dark:bg-[#111726] border border-slate-200 dark:border-slate-800/80 rounded-xl overflow-hidden shadow-sm flex flex-col">
      {/* Search Header */}
      <div className="p-4 border-b border-slate-200 dark:border-slate-800/80 flex flex-col sm:flex-row items-center justify-between gap-3">
        <div className="relative w-full sm:w-72">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            placeholder={searchPlaceholder}
            value={searchTerm}
            onChange={(e) => {
              setSearchTerm(e.target.value);
              setCurrentPage(1);
            }}
            className="w-full pl-9 pr-4 py-1.5 text-xs bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg text-slate-900 dark:text-slate-100 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500/50 dark:focus:ring-sky-500/50 transition-all"
          />
        </div>

        <div className="flex items-center text-xs text-slate-500 dark:text-slate-400 space-x-2 w-full sm:w-auto justify-between sm:justify-end">
          <span>
            Showing <strong className="text-slate-800 dark:text-slate-200">{filteredData.length > 0 ? (pageIndex - 1) * pageSize + 1 : 0}</strong> to{' '}
            <strong className="text-slate-800 dark:text-slate-200">{Math.min(pageIndex * pageSize, filteredData.length)}</strong> of{' '}
            <strong className="text-slate-800 dark:text-slate-200">{filteredData.length}</strong>
          </span>
        </div>
      </div>

      {/* Table Content */}
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-slate-50/80 dark:bg-slate-900/60 border-b border-slate-200 dark:border-slate-800/80 text-[11px] font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
              {columns.map((col, idx) => (
                <th key={idx} className={`px-4 py-3 ${col.className || ''}`}>
                  {col.header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-200/80 dark:divide-slate-800/60 text-xs text-slate-700 dark:text-slate-300">
            {paginatedData.length === 0 ? (
              <tr>
                <td colSpan={columns.length} className="px-4 py-8 text-center text-slate-400">
                  No records matching search parameters.
                </td>
              </tr>
            ) : (
              paginatedData.map((item, rowIdx) => {
                const itemId = getItemId ? getItemId(item) : undefined;
                const isSelected = selectedItemId && itemId ? selectedItemId === itemId : false;

                return (
                  <tr
                    key={itemId || rowIdx}
                    onClick={() => onRowClick && onRowClick(item)}
                    className={`transition-colors ${
                      onRowClick ? 'cursor-pointer' : ''
                    } ${
                      isSelected
                        ? 'bg-indigo-50/80 dark:bg-sky-500/10 text-indigo-900 dark:text-sky-300 font-semibold'
                        : 'hover:bg-slate-50 dark:hover:bg-slate-800/40'
                    }`}
                  >
                    {columns.map((col, colIdx) => (
                      <td key={colIdx} className={`px-4 py-3 ${col.className || ''}`}>
                        {col.cell ? col.cell(item) : col.accessorKey ? (item[col.accessorKey] as any) : null}
                      </td>
                    ))}
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      {totalPages > 1 && (
        <div className="p-3 border-t border-slate-200 dark:border-slate-800/80 bg-slate-50/50 dark:bg-slate-900/40 flex items-center justify-between text-xs">
          <div className="flex items-center space-x-2">
            <span className="text-slate-500 dark:text-slate-400">Per page:</span>
            <select
              value={pageSize}
              onChange={(e) => {
                setPageSize(Number(e.target.value));
                setCurrentPage(1);
              }}
              className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded px-2 py-1 text-slate-800 dark:text-slate-200 focus:outline-none"
            >
              <option value={10}>10</option>
              <option value={20}>20</option>
              <option value={50}>50</option>
            </select>
          </div>

          <div className="flex items-center space-x-1">
            <button
              disabled={pageIndex === 1}
              onClick={() => setCurrentPage(1)}
              className="p-1 rounded hover:bg-slate-200 dark:hover:bg-slate-800 disabled:opacity-30 disabled:pointer-events-none text-slate-600 dark:text-slate-400"
            >
              <ChevronsLeft className="w-4 h-4" />
            </button>
            <button
              disabled={pageIndex === 1}
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              className="p-1 rounded hover:bg-slate-200 dark:hover:bg-slate-800 disabled:opacity-30 disabled:pointer-events-none text-slate-600 dark:text-slate-400"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>

            <span className="px-3 font-semibold text-slate-700 dark:text-slate-300">
              Page {pageIndex} of {totalPages}
            </span>

            <button
              disabled={pageIndex === totalPages}
              onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
              className="p-1 rounded hover:bg-slate-200 dark:hover:bg-slate-800 disabled:opacity-30 disabled:pointer-events-none text-slate-600 dark:text-slate-400"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
            <button
              disabled={pageIndex === totalPages}
              onClick={() => setCurrentPage(totalPages)}
              className="p-1 rounded hover:bg-slate-200 dark:hover:bg-slate-800 disabled:opacity-30 disabled:pointer-events-none text-slate-600 dark:text-slate-400"
            >
              <ChevronsRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
