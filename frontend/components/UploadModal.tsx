'use client';

import React, { useState, useRef, useEffect } from 'react';
import { useAnalysisContext } from '@/context/AnalysisContext';
import { uploadAnalysisFile } from '@/lib/api';
import { useQueryClient } from '@tanstack/react-query';
import { Upload, X, FileCode, AlertTriangle, Loader2, CheckCircle2 } from 'lucide-react';

interface UploadModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export function UploadModal({ isOpen, onClose }: UploadModalProps) {
  const { setCurrentAnalysisId } = useAnalysisContext();
  const queryClient = useQueryClient();

  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isUploading, setIsUploading] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const backdropRef = useRef<HTMLDivElement>(null);

  // Reset modal state whenever isOpen changes
  useEffect(() => {
    if (isOpen) {
      setSelectedFile(null);
      setErrorMessage(null);
      setIsUploading(false);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    }
  }, [isOpen]);

  // Handle Escape key to close modal
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen && !isUploading) {
        handleClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, isUploading]);

  if (!isOpen) return null;

  const handleClose = () => {
    if (isUploading) return;
    setSelectedFile(null);
    setErrorMessage(null);
    setIsUploading(false);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
    onClose();
  };

  const handleOpenPicker = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (isUploading) return;
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
      fileInputRef.current.click();
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      setSelectedFile(file);
      setErrorMessage(null);
    }
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    if (isUploading) return;
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      setSelectedFile(file);
      setErrorMessage(null);
    }
  };

  const handleDragOver = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const handleBackdropClick = (e: React.MouseEvent<HTMLDivElement>) => {
    if (e.target === backdropRef.current && !isUploading) {
      handleClose();
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFile) {
      setErrorMessage('Please select a file to upload.');
      return;
    }

    setIsUploading(true);
    setErrorMessage(null);

    try {
      const result = await uploadAnalysisFile(selectedFile);
      if (!result || !result.analysisId) {
        throw new Error('Server returned an invalid analysis response.');
      }
      // Reset selected analysis and clear stale module data across all modules
      queryClient.removeQueries({ queryKey: ['analysis'] });
      setCurrentAnalysisId(result.analysisId);
      await queryClient.invalidateQueries({ queryKey: ['analyses-list'] });
      setIsUploading(false);
      setSelectedFile(null);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
      onClose();
    } catch (err: any) {
      setIsUploading(false);
      let message = 'Failed to upload and parse file.';
      if (err instanceof Error) {
        message = err.message;
        if (message === 'Failed to fetch') {
          message = 'Unable to connect to NestJS backend at http://localhost:4000. Please ensure the backend server is running.';
        }
      }
      setErrorMessage(message);
    }
  };

  return (
    <div
      ref={backdropRef}
      onClick={handleBackdropClick}
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 backdrop-blur-sm p-4 transition-opacity"
    >
      <div className="bg-white dark:bg-[#111726] border border-slate-200 dark:border-slate-800 rounded-2xl w-full max-w-lg shadow-2xl overflow-hidden relative">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Upload className="h-5 w-5 text-indigo-600 dark:text-sky-400" />
            <h2 className="text-base font-bold text-slate-900 dark:text-slate-100">Upload Security Analysis File</h2>
          </div>
          <button
            type="button"
            onClick={handleClose}
            disabled={isUploading}
            className="text-slate-400 hover:text-slate-600 dark:hover:text-white transition p-1 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-50"
            aria-label="Close dialog"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Modal Body */}
        <form onSubmit={handleSubmit} className="p-6 space-y-5">
          {/* Drop Zone */}
          <div
            onDrop={handleDrop}
            onDragOver={handleDragOver}
            onClick={handleOpenPicker}
            className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition flex flex-col items-center justify-center space-y-3 ${
              selectedFile
                ? 'border-indigo-500/50 bg-indigo-50 dark:border-sky-500/50 dark:bg-sky-500/5'
                : 'border-slate-300 dark:border-slate-700/70 hover:border-indigo-400 dark:hover:border-slate-500 bg-slate-50/50 dark:bg-slate-900/40'
            }`}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".log,.txt,.json,.csv"
              onChange={handleFileChange}
              onClick={(e) => e.stopPropagation()}
              className="hidden"
            />

            {selectedFile ? (
              <>
                <FileCode className="h-10 w-10 text-indigo-600 dark:text-sky-400 animate-bounce" />
                <div>
                  <p className="text-sm font-semibold text-slate-900 dark:text-slate-200 truncate max-w-xs">{selectedFile.name}</p>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                    {(selectedFile.size / 1024).toFixed(1)} KB &bull; <span className="text-indigo-600 dark:text-sky-400 underline">Click to change</span>
                  </p>
                </div>
              </>
            ) : (
              <>
                <Upload className="h-10 w-10 text-slate-400" />
                <div>
                  <p className="text-sm font-medium text-slate-700 dark:text-slate-300">
                    Drag and drop file here, or <span className="text-indigo-600 dark:text-sky-400 underline font-semibold">browse</span>
                  </p>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                    Supported formats: <code className="text-indigo-600 dark:text-sky-300 font-mono">.log</code>, <code className="text-indigo-600 dark:text-sky-300 font-mono">.txt</code>, <code className="text-indigo-600 dark:text-sky-300 font-mono">.json</code>, <code className="text-indigo-600 dark:text-sky-300 font-mono">.csv</code>
                  </p>
                </div>
              </>
            )}
          </div>

          {/* Supported Format Badges */}
          <div className="flex items-center justify-center gap-2 text-[11px] text-slate-500 dark:text-slate-400">
            <span className="px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 font-mono">.log</span>
            <span className="px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 font-mono">.txt</span>
            <span className="px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 font-mono">.json</span>
            <span className="px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 font-mono">.csv</span>
          </div>

          {/* Error Message Alert */}
          {errorMessage && (
            <div className="p-3 bg-rose-500/10 border border-rose-500/20 rounded-xl flex items-start space-x-2 text-xs text-rose-700 dark:text-rose-300">
              <AlertTriangle className="h-4 w-4 text-rose-500 shrink-0 mt-0.5" />
              <span>{errorMessage}</span>
            </div>
          )}

          {/* Action Buttons */}
          <div className="flex items-center justify-end space-x-3 pt-2 border-t border-slate-200 dark:border-slate-800">
            <button
              type="button"
              onClick={handleClose}
              disabled={isUploading}
              className="px-4 py-2 text-xs font-medium text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200 transition disabled:opacity-50"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={!selectedFile || isUploading}
              className="px-5 py-2 text-xs font-medium bg-indigo-600 hover:bg-indigo-700 dark:bg-sky-600 dark:hover:bg-sky-500 disabled:opacity-50 text-white rounded-lg transition shadow-md flex items-center space-x-2 active:scale-95"
            >
              {isUploading ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  <span>Parsing & Persisting...</span>
                </>
              ) : (
                <>
                  <CheckCircle2 className="h-4 w-4" />
                  <span>Start Analysis</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
