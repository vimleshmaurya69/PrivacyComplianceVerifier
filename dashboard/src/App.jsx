import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { OverviewPage } from './pages/OverviewPage';
import { AppListPage } from './pages/AppListPage';
import { AppDetailPage } from './pages/AppDetailPage';
import { PolicyVsTraffic } from './pages/PolicyVsTraffic';
import { RiskSignalsPage } from './pages/RiskSignalsPage';
import { EvidenceExplorer } from './pages/EvidenceExplorer';
import { ExternalValidationPage } from './pages/ExternalValidationPage';
import { AboutPage } from './pages/AboutPage';
import { fetchMasterResults } from './api/dataLoader';

export function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [selectedApp, setSelectedApp] = useState(null);
  const [masterResults, setMasterResults] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(null);

  useEffect(() => {
    fetchMasterResults()
      .then(data => setMasterResults(data))
      .catch(err => setLoadError(err.message || 'Unable to load dashboard data'))
      .finally(() => setLoading(false));
  }, []);

  const handleSelectApp = (appName) => {
    setSelectedApp(appName);
    setActiveTab('detail');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleBackToApps = () => {
    setActiveTab('apps');
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        selectedApp={selectedApp}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {loading ? (
          <div className="flex items-center justify-center p-20 font-mono text-xs text-slate-500">
            Initializing framework evaluation dataset...
          </div>
        ) : loadError ? (
          <div className="max-w-2xl mx-auto mt-12 rounded-xl border border-rose-900/70 bg-rose-950/30 p-6">
            <h2 className="text-sm font-semibold text-rose-300">Dashboard data could not be loaded</h2>
            <p className="mt-2 text-xs text-slate-300">{loadError}</p>
            <p className="mt-2 text-[11px] font-mono text-slate-500">
              Run the dashboard through run_dashboard.py so the generated data directory is available.
            </p>
          </div>
        ) : (
          <>
            {activeTab === 'overview' && (
              <OverviewPage
                masterResults={masterResults}
                onSelectApp={handleSelectApp}
                onNavigate={setActiveTab}
              />
            )}

            {activeTab === 'apps' && (
              <AppListPage
                masterResults={masterResults}
                onSelectApp={handleSelectApp}
              />
            )}

            {activeTab === 'detail' && (
              <AppDetailPage
                appName={selectedApp || 'Truecaller'}
                onBack={handleBackToApps}
                onNavigateToEvidence={() => setActiveTab('evidence')}
              />
            )}

            {activeTab === 'policy' && (
              <PolicyVsTraffic
                selectedApp={selectedApp}
                onSelectApp={setSelectedApp}
              />
            )}

            {activeTab === 'evidence' && (
              <EvidenceExplorer
                selectedApp={selectedApp}
                onSelectApp={setSelectedApp}
              />
            )}

            {activeTab === 'risks' && (
              <RiskSignalsPage
                masterResults={masterResults}
                onSelectApp={handleSelectApp}
              />
            )}

            {activeTab === 'external' && (
              <ExternalValidationPage />
            )}

            {activeTab === 'about' && (
              <AboutPage />
            )}
          </>
        )}
      </main>

      <footer className="border-t border-slate-900 bg-slate-950 py-5 text-center text-xs text-slate-500 font-mono">
        Privacy Compliance Verification Framework &bull; Empirical Policy vs Traffic Analysis &bull; Presentation Dashboard
      </footer>
    </div>
  );
}

export default App;
