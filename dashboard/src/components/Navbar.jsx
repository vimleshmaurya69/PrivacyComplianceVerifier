import React from 'react';
import {
  LayoutDashboard,
  Layers,
  FileCheck2,
  TableProperties,
  AlertTriangle,
  Beaker,
  Info,
  ShieldCheck
} from 'lucide-react';

export function Navbar({ activeTab, setActiveTab, selectedApp }) {
  const navItems = [
    { id: 'overview', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'apps', label: 'Applications', icon: Layers },
    { id: 'policy', label: 'Policy Analysis', icon: FileCheck2 },
    { id: 'evidence', label: 'Evidence Explorer', icon: TableProperties },
    { id: 'risks', label: 'Risk Signals', icon: AlertTriangle },
    { id: 'external', label: 'External Evaluation', icon: Beaker },
    { id: 'about', label: 'About', icon: Info },
  ];

  return (
    <header className="border-b border-slate-800 bg-slate-950/80 sticky top-0 z-40 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo & Research Titles */}
          <div className="flex items-center gap-3 cursor-pointer" onClick={() => setActiveTab('overview')}>
            <div className="w-9 h-9 rounded-lg bg-cyan-950 border border-cyan-800 flex items-center justify-center text-cyan-400 shadow-sm shadow-cyan-950">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <div className="text-sm font-bold tracking-tight text-slate-100 flex items-center gap-2">
                Privacy Compliance Verification Framework
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 font-normal">v2.0</span>
              </div>
              <div className="text-xs text-slate-400 font-mono tracking-tight">
                Network Traffic vs Privacy Policy Analysis
              </div>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="flex items-center gap-1">
            {navItems.map(item => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                    isActive
                      ? 'bg-slate-800 text-cyan-400 border border-slate-700 shadow-inner'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
                  }`}
                >
                  <Icon className="w-3.5 h-3.5" />
                  {item.label}
                </button>
              );
            })}
          </nav>
        </div>
      </div>
    </header>
  );
}
