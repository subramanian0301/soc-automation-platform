'use client';

import React from 'react';
import { useAnalysisContext } from '@/context/AnalysisContext';
import { useQuery } from '@tanstack/react-query';
import { fetchAnalysisAssets, AssetsResponse } from '@/lib/api';
import { Server, ShieldAlert, Cpu, HardDrive, Info } from 'lucide-react';

interface AssetsViewProps {
  onOpenUpload?: () => void;
}

export function AssetsView({ onOpenUpload }: AssetsViewProps) {
  const { currentAnalysisId } = useAnalysisContext();

  const { data, isLoading, error } = useQuery<AssetsResponse>({
    queryKey: ['analysis', currentAnalysisId, 'assets'],
    queryFn: () => fetchAnalysisAssets(currentAnalysisId!),
    enabled: Boolean(currentAnalysisId),
  });

  if (!currentAnalysisId) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center p-12 text-center bg-[#0a0d14]">
        <div className="h-16 w-16 rounded-2xl bg-sky-500/10 border border-sky-500/20 flex items-center justify-center text-sky-400 mb-4 shadow-lg">
          <Server className="h-8 w-8" />
        </div>
        <h2 className="text-xl font-bold text-slate-100 mb-2">No Active Analysis Selected</h2>
        <p className="text-sm text-slate-400 max-w-md mb-6">
          Select an active analysis from the header dropdown or upload a new file to inspect associated asset management data.
        </p>
        {onOpenUpload && (
          <button
            onClick={onOpenUpload}
            className="px-4 py-2 bg-sky-600 hover:bg-sky-500 text-white rounded-lg font-medium text-xs transition shadow-md shadow-sky-600/20"
          >
            Upload New Log / File
          </button>
        )}
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="flex-1 flex items-center justify-center p-12 bg-[#0a0d14] text-slate-400">
        <div className="flex items-center space-x-3">
          <div className="w-5 h-5 border-2 border-sky-400 border-t-transparent rounded-full animate-spin" />
          <span className="text-sm font-medium">Loading Asset records...</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex-1 p-8 bg-[#0a0d14]">
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400 text-sm">
          Failed to load asset data: {(error as Error).message}
        </div>
      </div>
    );
  }

  const assets = data?.assets || [];

  return (
    <div className="flex-1 p-8 bg-[#0a0d14] flex flex-col space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div>
          <div className="flex items-center space-x-3 mb-1">
            <div className="h-8 w-8 rounded-lg bg-sky-500/10 border border-sky-500/20 flex items-center justify-center text-sky-400">
              <Server className="h-4 w-4" />
            </div>
            <h1 className="text-xl font-bold text-slate-100 tracking-tight">Asset Management</h1>
            <span className="text-xs font-semibold px-2.5 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700">
              {assets.length} {assets.length === 1 ? 'Asset' : 'Assets'}
            </span>
          </div>
          <p className="text-xs text-slate-400">
            Source-of-truth asset inventory strictly scoped to analysis ID:{' '}
            <span className="font-mono text-sky-400 font-medium">{currentAnalysisId}</span>
          </p>
        </div>
      </div>

      {assets.length === 0 ? (
        <div className="flex-1 flex flex-col items-center justify-center py-16 px-4 text-center border border-dashed border-slate-800 rounded-2xl bg-slate-900/30">
          <div className="h-12 w-12 rounded-xl bg-slate-800/80 flex items-center justify-center text-slate-400 mb-3">
            <HardDrive className="h-6 w-6" />
          </div>
          <h3 className="text-base font-bold text-slate-200 mb-1">No Asset Data Available</h3>
          <p className="text-xs text-slate-400 max-w-sm">
            The uploaded source file did not contain explicit asset records. Assets are never automatically fabricated.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4">
          {assets.map((asset) => (
            <div
              key={asset.id}
              className="bg-[#0f1422] border border-slate-800 rounded-xl p-5 hover:border-slate-700 transition shadow-sm space-y-4"
            >
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/60 pb-3">
                <div className="flex items-center space-x-3">
                  <div className="h-9 w-9 rounded-lg bg-sky-500/10 border border-sky-500/20 flex items-center justify-center text-sky-400 font-bold">
                    <Cpu className="h-5 w-5" />
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                      {asset.assetName}
                      {asset.criticality && (
                        <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">
                          {asset.criticality}
                        </span>
                      )}
                    </h3>
                    <p className="text-[11px] text-slate-400 font-mono">
                      ID: {asset.id}
                    </p>
                  </div>
                </div>
                <div className="flex items-center space-x-2">
                  <span className="text-xs px-2.5 py-1 rounded-md bg-slate-800 text-slate-300 font-medium">
                    Type: {asset.assetType || 'Not Available'}
                  </span>
                  <span className="text-xs px-2.5 py-1 rounded-md bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-medium">
                    Status: {asset.status || 'Not Available'}
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
                <div>
                  <span className="text-slate-500 block text-[11px] font-medium">Hostname</span>
                  <span className="text-slate-200 font-mono font-medium">{asset.hostname || 'Not Available'}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[11px] font-medium">IP Address</span>
                  <span className="text-slate-200 font-mono font-medium">{asset.ipAddress || 'Not Available'}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[11px] font-medium">MAC Address</span>
                  <span className="text-slate-200 font-mono font-medium">{asset.macAddress || 'Not Available'}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[11px] font-medium">Operating System</span>
                  <span className="text-slate-200 font-medium">{asset.operatingSystem || 'Not Available'}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[11px] font-medium">Owner / User</span>
                  <span className="text-slate-200 font-medium">{asset.owner || 'Not Available'}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[11px] font-medium">Source</span>
                  <span className="text-slate-200 font-medium">{asset.source || 'Not Available'}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[11px] font-medium">Created</span>
                  <span className="text-slate-200 font-medium">
                    {asset.createdAt ? new Date(asset.createdAt).toLocaleString() : 'Not Available'}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[11px] font-medium">Updated</span>
                  <span className="text-slate-200 font-medium">
                    {asset.updatedAt ? new Date(asset.updatedAt).toLocaleString() : 'Not Available'}
                  </span>
                </div>
              </div>

              {(asset.description || asset.evidence) && (
                <div className="pt-2 border-t border-slate-800/60 grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                  {asset.description && (
                    <div className="bg-slate-900/60 p-3 rounded-lg border border-slate-800/80">
                      <span className="text-[11px] font-semibold text-slate-400 block mb-1">Description</span>
                      <p className="text-slate-300">{asset.description}</p>
                    </div>
                  )}
                  {asset.evidence && (
                    <div className="bg-slate-900/60 p-3 rounded-lg border border-slate-800/80">
                      <span className="text-[11px] font-semibold text-slate-400 block mb-1">Evidence / Reference</span>
                      <p className="text-slate-300 font-mono text-[11px]">{asset.evidence}</p>
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
