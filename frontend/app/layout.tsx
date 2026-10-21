'use client';

import './globals.css';
import { useState } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AnalysisProvider } from '@/context/AnalysisContext';
import { ThemeProvider } from '@/context/ThemeContext';

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            refetchOnWindowFocus: false,
            retry: 1,
            staleTime: 5 * 60 * 1000,
          },
        },
      }),
  );

  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <title>SOC Security Platform</title>
        <meta name="description" content="Authoritative Enterprise SOC Security Platform" />
      </head>
      <body className="bg-slate-50 text-slate-900 dark:bg-[#0b0f19] dark:text-slate-100 antialiased min-h-screen transition-colors duration-200">
        <QueryClientProvider client={queryClient}>
          <ThemeProvider>
            <AnalysisProvider>{children}</AnalysisProvider>
          </ThemeProvider>
        </QueryClientProvider>
      </body>
    </html>
  );
}

