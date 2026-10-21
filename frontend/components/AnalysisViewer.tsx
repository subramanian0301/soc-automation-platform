'use client';

import React from 'react';
import { Dashboard } from './Dashboard';

interface AnalysisViewerProps {
  onOpenUpload: () => void;
}

export function AnalysisViewer({ onOpenUpload }: AnalysisViewerProps) {
  return <Dashboard onOpenUpload={onOpenUpload} />;
}
