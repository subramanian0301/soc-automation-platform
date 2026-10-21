'use client';

import React, { useState } from 'react';
import { ActiveTabType } from '@/components/Navbar';
import { AppSidebar } from '@/components/layout/AppSidebar';
import { AppHeader } from '@/components/layout/AppHeader';
import { UploadModal } from '@/components/UploadModal';

import { Dashboard } from '@/components/Dashboard';
import { SiemView } from '@/components/SiemView';
import { IocSearchView } from '@/components/IocSearchView';
import { ThreatIntelView } from '@/components/ThreatIntelView';
import { MitreView } from '@/components/MitreView';
import { BehaviorView } from '@/components/BehaviorView';
import { SandboxView } from '@/components/SandboxView';
import { IncidentsView } from '@/components/IncidentsView';
import { CasesView } from '@/components/CasesView';
import { SoarView } from '@/components/SoarView';
import { AssetsView } from '@/components/AssetsView';
import { EndpointsView } from '@/components/EndpointsView';
import { VulnerabilitiesView } from '@/components/VulnerabilitiesView';
import { ReportsView } from '@/components/ReportsView';

export default function HomePage() {
  const [isUploadOpen, setIsUploadOpen] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<ActiveTabType>('dashboard');

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-[#0a0d14] text-slate-900 dark:text-slate-100 flex flex-col lg:flex-row font-sans transition-colors duration-200">
      {/* Vertical Navigation Sidebar */}
      <AppSidebar activeTab={activeTab} onTabChange={setActiveTab} />

      {/* Main Content Viewport */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top Header Bar */}
        <AppHeader activeTab={activeTab} onOpenUpload={() => setIsUploadOpen(true)} />

        {/* Dynamic Route View */}
        <main className="flex-1 p-6 overflow-y-auto">
          {activeTab === 'dashboard' && <Dashboard onOpenUpload={() => setIsUploadOpen(true)} />}
          {activeTab === 'siem' && <SiemView onOpenUpload={() => setIsUploadOpen(true)} />}
          {activeTab === 'iocs' && <IocSearchView onOpenUpload={() => setIsUploadOpen(true)} />}
          {activeTab === 'threat-intel' && <ThreatIntelView onOpenUpload={() => setIsUploadOpen(true)} />}
          {activeTab === 'mitre' && <MitreView onOpenUpload={() => setIsUploadOpen(true)} />}
          {activeTab === 'behavior' && <BehaviorView onOpenUpload={() => setIsUploadOpen(true)} />}
          {activeTab === 'sandbox' && <SandboxView onOpenUpload={() => setIsUploadOpen(true)} />}
          {activeTab === 'incidents' && <IncidentsView onOpenUpload={() => setIsUploadOpen(true)} />}
          {activeTab === 'cases' && <CasesView onOpenUpload={() => setIsUploadOpen(true)} />}
          {activeTab === 'soar' && <SoarView onOpenUpload={() => setIsUploadOpen(true)} />}
          {activeTab === 'assets' && <AssetsView onOpenUpload={() => setIsUploadOpen(true)} />}
          {activeTab === 'endpoints' && <EndpointsView onOpenUpload={() => setIsUploadOpen(true)} />}
          {activeTab === 'vulnerabilities' && <VulnerabilitiesView onOpenUpload={() => setIsUploadOpen(true)} />}
          {activeTab === 'reports' && <ReportsView onOpenUpload={() => setIsUploadOpen(true)} />}
        </main>
      </div>

      {/* File Upload Modal */}
      <UploadModal isOpen={isUploadOpen} onClose={() => setIsUploadOpen(false)} />
    </div>
  );
}





