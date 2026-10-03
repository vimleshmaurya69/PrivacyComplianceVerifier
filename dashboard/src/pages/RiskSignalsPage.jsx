import React, { useState } from 'react';
import { AlertTriangle, ShieldAlert, Key, Globe, Search, ArrowUpRight } from 'lucide-react';
import { RiskBadge } from '../components/RiskBadge';

export function RiskSignalsPage({ masterResults, onSelectApp }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState('ALL');

  // Filter apps with risks
  const appsWithRisks = masterResults.filter(app => {
    if (!app.risk_signals || app.risk_signals === 'None') return false;
    const normalizedSignals = app.risk_signals.toUpperCase();
    const matchesSearch = app.application.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesType =
      filterType === 'ALL' ||
      (filterType === 'CREDENTIAL' && normalizedSignals.includes('CREDENTIAL')) ||
      (filterType === 'PERSONAL' && normalizedSignals.includes('PERSONAL'));
    return matchesSearch && matchesType;
  });

  return (
    <div className="space-y-6">
      {/* Top Banner with Research Explanation */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
        <div className="flex items-start gap-3">
          <div className="p-2 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 mt-0.5">
            <AlertTriangle className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base font-bold text-slate-100">Transmission Channel Risk Signals</h2>
            <p className="text-xs text-slate-300 mt-1 leading-relaxed">
              Risk signals identify sensitive information placed in URL components, where it may be retained or exposed through server logs, analytics, browser history, or referrer handling.
            </p>
            <div className="mt-2 text-[11px] font-mono text-amber-400 bg-amber-950/40 border border-amber-900/50 p-2 rounded">
              <strong>Methodological Distinction:</strong> A risk signal is an operational security finding, NOT an automatic policy disclosure violation. Even if an application policy mentions collecting an identifier, transmitting it inside a URL query parameter constitutes a distinct privacy risk.
            </div>
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="text-xs text-slate-400 font-mono">
            Applications with Active Signals: <strong className="text-rose-400">{appsWithRisks.length}</strong> of {masterResults.length}
          </div>

          <div className="flex items-center gap-3">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search app..."
                value={searchTerm}
                onChange={e => setSearchTerm(e.target.value)}
                className="pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-700 rounded-lg text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 w-44"
              />
            </div>

            <select
              value={filterType}
              onChange={e => setFilterType(e.target.value)}
              className="bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Risk Types</option>
              <option value="CREDENTIAL">Credential in URL</option>
              <option value="PERSONAL">Personal Data in URL</option>
            </select>
          </div>
        </div>
      </div>

      {/* Risk Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {appsWithRisks.map((app, idx) => {
          const rawSignals = (app.risk_signals || '').split(';').filter(Boolean);
          return (
            <div
              key={idx}
              className="bg-slate-900/90 border border-slate-800 hover:border-slate-700 rounded-xl p-4.5 space-y-3 transition"
            >
              <div className="flex items-center justify-between">
                <span className="font-bold text-sm text-slate-100">{app.application}</span>
                <button
                  onClick={() => onSelectApp(app.application)}
                  className="flex items-center gap-1 text-[11px] text-cyan-400 hover:text-cyan-300 font-mono"
                >
                  Inspect <ArrowUpRight className="w-3.5 h-3.5" />
                </button>
              </div>

              <div className="flex flex-wrap gap-1.5">
                {rawSignals.map((s, sIdx) => (
                  <RiskBadge key={sIdx} risk={s.trim()} />
                ))}
              </div>

              <div className="bg-slate-950 p-2.5 rounded border border-slate-800/80 text-[11px] text-slate-400 space-y-1 font-mono">
                <div className="flex justify-between">
                  <span>Sensitive Occurrences:</span>
                  <span className="text-slate-200 font-semibold">{app.sensitive_occurrences}</span>
                </div>
                <div className="flex justify-between">
                  <span>Unique Artifacts:</span>
                  <span className="text-slate-200 font-semibold">{app.unique_sensitive_artifacts}</span>
                </div>
                <div className="flex justify-between">
                  <span>Overall Determination:</span>
                  <span className="text-amber-400">{app.result}</span>
                </div>
              </div>

              <div className="text-[11px] text-slate-400 leading-snug">
                {app.risk_signals.toUpperCase().includes('CREDENTIAL') ? (
                  <span>Authentication token, session cookie, or API key observed in a URL component.</span>
                ) : (
                  <span>Personal information such as a phone number, coordinates, or user ID detected in a request URL.</span>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
