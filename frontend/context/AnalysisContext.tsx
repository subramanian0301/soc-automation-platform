'use client';

import React, { createContext, useContext, useState, ReactNode } from 'react';

interface AnalysisContextType {
  currentAnalysisId: string | null;
  setCurrentAnalysisId: (id: string | null) => void;
  clearAnalysis: () => void;
}

const AnalysisContext = createContext<AnalysisContextType | undefined>(undefined);

export function AnalysisProvider({ children }: { children: ReactNode }) {
  const [currentAnalysisId, setCurrentAnalysisId] = useState<string | null>(null);

  const clearAnalysis = () => {
    setCurrentAnalysisId(null);
  };

  return (
    <AnalysisContext.Provider
      value={{
        currentAnalysisId,
        setCurrentAnalysisId,
        clearAnalysis,
      }}
    >
      {children}
    </AnalysisContext.Provider>
  );
}

export function useAnalysisContext() {
  const context = useContext(AnalysisContext);
  if (!context) {
    throw new Error('useAnalysisContext must be used within an AnalysisProvider');
  }
  return context;
}
