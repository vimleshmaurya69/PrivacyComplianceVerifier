import React from 'react';
import {
  AppWindow,
  Activity,
  ShieldCheck,
  HelpCircle,
  EyeOff,
  AlertTriangle,
  FileCheck,
  Server,
  ArrowUpRight
} from 'lucide-react';
import { ResearchPipeline } from '../components/ResearchPipeline';
import { ResultBadge } from '../components/StatusBadge';
import { RiskBadge } from '../components/RiskBadge';

export function OverviewPage({ masterResults, onSelectApp, onNavigate }) {
  if (!masterResults || masterResults.length === 0) {
    return (
      <div className="flex items-center justify-center p-12 text-slate-500 font-mono text-sm">
        Loading dataset from /data/analysis/master_results.json...
      </div>
    );
  }

  // Calculate actual aggregates strictly from master_results
  const totalApps = masterResults.length;
  const totalRequests = masterResults.reduce((acc, r) => acc + (r.total_requests || 0), 0);
  const sensitiveOccurrences = masterResults.reduce((acc, r) => acc + (r.sensitive_occurrences || 0), 0);
  const infoDisclosed = masterResults.reduce((acc, r) => acc + (r.disclosed_information_type_count || 0), 0);
  const notDisclosed = masterResults.reduce((acc, r) => acc + (r.not_disclosed_information_type_count || 0), 0);
  const declaredNotObserved = masterResults.reduce((acc, r) => acc + (r.declared_not_observed || 0), 0);
  const appsWithRisks = masterResults.filter(r => r.risk_signals && r.risk_signals !== 'None' && r.risk_signals !== '').length;

  // Category aggregates
  const categories = [
    { key: 'personal_information', label: 'Personal Information', color: 'bg-indigo-500' },
    { key: 'authentication', label: 'Authentication', color: 'bg-emerald-500' },
    { key: 'device_identifier', label: 'Device Identifier', color: 'bg-cyan-500' },
    { key: 'location', label: 'Location', color: 'bg-amber-500' },
    { key: 'network_information', label: 'Network Information', color: 'bg-blue-500' },
    { key: 'security', label: 'Security', color: 'bg-purple-500' },
    { key: 'api_credentials', label: 'API Credentials', color: 'bg-rose-500' },
  ];

  const categoryTotals = categories.map(c => ({
    ...c,
    count: masterResults.reduce((acc, r) => acc + (r[c.key] || 0), 0)
  })).sort((a, b) => b.count - a.count);

  const maxCatCount = Math.max(...categoryTotals.map(c => c.count), 1);

  // Result distribution
  const resultCounts = masterResults.reduce((acc, r) => {
    const res = r.result || 'INSUFFICIENT EVIDENCE';
    acc[res] = (acc[res] || 0) + 1;
    return acc;
  }, {});

  // Traffic request distribution
  const appReqs = masterResults.reduce((acc, r) => acc + (r.application_requests || 0), 0);
  const thirdPartyReqs = masterResults.reduce((acc, r) => acc + (r.third_party_requests || 0), 0);
  const androidReqs = masterResults.reduce((acc, r) => acc + (r.android_requests || 0), 0);
  const unknownReqs = masterResults.reduce((acc, r) => acc + (r.unknown_requests || 0), 0);

  return (
    <div className="space-y-6">
      {/* Research Flow Concept */}
      <ResearchPipeline />

      {/* Top-Level Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5">
          <div className="flex items-center gap-1.5 text-slate-400 text-xs mb-1">
            <AppWindow className="w-3.5 h-3.5 text-cyan-400" />
            <span>Applications</span>
          </div>
          <div className="text-2xl font-bold font-mono text-slate-100">{totalApps}</div>
          <div className="text-[11px] text-slate-500 mt-0.5">Analyzed targets</div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5">
          <div className="flex items-center gap-1.5 text-slate-400 text-xs mb-1">
            <Activity className="w-3.5 h-3.5 text-blue-400" />
            <span>Total Requests</span>
          </div>
          <div className="text-2xl font-bold font-mono text-slate-100">{totalRequests.toLocaleString()}</div>
          <div className="text-[11px] text-slate-500 mt-0.5">Observed HAR traffic</div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5">
          <div className="flex items-center gap-1.5 text-slate-400 text-xs mb-1">
            <ShieldCheck className="w-3.5 h-3.5 text-indigo-400" />
            <span>Sensitive Findings</span>
          </div>
          <div className="text-2xl font-bold font-mono text-slate-100">{sensitiveOccurrences.toLocaleString()}</div>
          <div className="text-[11px] text-slate-500 mt-0.5">Detector occurrences</div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5">
          <div className="flex items-center gap-1.5 text-slate-400 text-xs mb-1">
            <FileCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span>In Policy</span>
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400">{infoDisclosed}</div>
          <div className="text-[11px] text-slate-500 mt-0.5">Observed types named in policy</div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5">
          <div className="flex items-center gap-1.5 text-slate-400 text-xs mb-1">
            <HelpCircle className="w-3.5 h-3.5 text-amber-400" />
            <span>Not in Policy</span>
          </div>
          <div className="text-2xl font-bold font-mono text-rose-400">{notDisclosed}</div>
          <div className="text-[11px] text-slate-500 mt-0.5">Absent from reviewed policy</div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5">
          <div className="flex items-center gap-1.5 text-slate-400 text-xs mb-1">
            <EyeOff className="w-3.5 h-3.5 text-slate-400" />
            <span>Not Observed</span>
          </div>
          <div className="text-2xl font-bold font-mono text-slate-300">{declaredNotObserved}</div>
          <div className="text-[11px] text-slate-500 mt-0.5">Declared in policy</div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5">
          <div className="flex items-center gap-1.5 text-slate-400 text-xs mb-1">
            <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
            <span>Risk Signals</span>
          </div>
          <div className="text-2xl font-bold font-mono text-rose-400">{appsWithRisks}</div>
          <div className="text-[11px] text-slate-500 mt-0.5">Apps with URL risk signals</div>
        </div>
      </div>

      {/* Primary Analytics Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Sensitive Data by Privacy Category */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h4 className="text-sm font-semibold text-slate-200">Sensitive Data by Privacy Category</h4>
              <p className="text-xs text-slate-500">Distribution of detected sensitive occurrences</p>
            </div>
            <span className="text-[11px] font-mono text-slate-400">Total: {sensitiveOccurrences.toLocaleString()}</span>
          </div>
          <div className="space-y-3">
            {categoryTotals.map(c => {
              const pct = ((c.count / (sensitiveOccurrences || 1)) * 100).toFixed(1);
              return (
                <div key={c.key} className="space-y-1">
                  <div className="flex justify-between text-xs font-mono">
                    <span className="text-slate-300">{c.label}</span>
                    <span className="text-slate-400">{c.count.toLocaleString()} ({pct}%)</span>
                  </div>
                  <div className="h-2 w-full bg-slate-950 rounded-full overflow-hidden border border-slate-800/80">
                    <div
                      className={`h-full ${c.color} rounded-full transition-all duration-500`}
                      style={{ width: `${Math.max((c.count / maxCatCount) * 100, 1)}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Framework Determination Breakdown */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h4 className="text-sm font-semibold text-slate-200">Policy Comparison Results</h4>
              <p className="text-xs text-slate-500">Observed information compared with reviewed policy text</p>
            </div>
          </div>
          <div className="space-y-3">
            {Object.entries(resultCounts).map(([res, count]) => {
              const pct = ((count / totalApps) * 100).toFixed(0);
              return (
                <div key={res} className="p-3 bg-slate-950/70 border border-slate-800/80 rounded-lg">
                  <div className="flex items-center justify-between mb-1.5">
                    <ResultBadge result={res} size="sm" />
                    <span className="text-xs font-mono font-bold text-slate-200">{count} apps ({pct}%)</span>
                  </div>
                  <div className="text-[11px] text-slate-400">
                    {res === 'POTENTIALLY_NON_COMPLIANT' && 'At least one observed information type is not named in the reviewed policy.'}
                    {res === 'COMPLIANT_WITHIN_CAPTURE_SCOPE' && 'Every observed policy-comparable information type is named in the reviewed policy.'}
                    {res === 'CANNOT_DETERMINE' && 'The policy representation is incomplete, so the comparison cannot be finished.'}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Network Traffic Classification */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h4 className="text-sm font-semibold text-slate-200">Traffic Classification</h4>
              <p className="text-xs text-slate-500">Breakdown of {totalRequests.toLocaleString()} network requests</p>
            </div>
            <Server className="w-4 h-4 text-cyan-400" />
          </div>

          <div className="space-y-4">
            <div className="p-3 bg-slate-950/70 border border-slate-800/80 rounded-lg space-y-2">
              <div className="flex justify-between text-xs">
                <span className="text-slate-300 font-medium">Application-Attributed Traffic</span>
                <span className="font-mono text-cyan-400">{appReqs.toLocaleString()} ({((appReqs / totalRequests) * 100).toFixed(1)}%)</span>
              </div>
              <div className="h-1.5 bg-slate-900 rounded-full overflow-hidden">
                <div className="h-full bg-cyan-500 rounded-full" style={{ width: `${(appReqs / totalRequests) * 100}%` }} />
              </div>
            </div>

            <div className="p-3 bg-slate-950/70 border border-slate-800/80 rounded-lg space-y-2">
              <div className="flex justify-between text-xs">
                <span className="text-slate-300 font-medium">Third-Party & Ad/Analytics</span>
                <span className="font-mono text-indigo-400">{thirdPartyReqs.toLocaleString()} ({((thirdPartyReqs / totalRequests) * 100).toFixed(1)}%)</span>
              </div>
              <div className="h-1.5 bg-slate-900 rounded-full overflow-hidden">
                <div className="h-full bg-indigo-500 rounded-full" style={{ width: `${(thirdPartyReqs / totalRequests) * 100}%` }} />
              </div>
            </div>

            <div className="p-3 bg-slate-950/70 border border-slate-800/80 rounded-lg space-y-2">
              <div className="flex justify-between text-xs">
                <span className="text-slate-300 font-medium">Android System Traffic</span>
                <span className="font-mono text-amber-400">{androidReqs.toLocaleString()} ({((androidReqs / totalRequests) * 100).toFixed(1)}%)</span>
              </div>
              <div className="h-1.5 bg-slate-900 rounded-full overflow-hidden">
                <div className="h-full bg-amber-500 rounded-full" style={{ width: `${(androidReqs / totalRequests) * 100}%` }} />
              </div>
            </div>

            <div className="p-3 bg-slate-950/70 border border-slate-800/80 rounded-lg space-y-2">
              <div className="flex justify-between text-xs">
                <span className="text-slate-300 font-medium">Unknown / Unclassified</span>
                <span className="font-mono text-slate-400">{unknownReqs.toLocaleString()} ({((unknownReqs / totalRequests) * 100).toFixed(1)}%)</span>
              </div>
              <div className="h-1.5 bg-slate-900 rounded-full overflow-hidden">
                <div className="h-full bg-slate-600 rounded-full" style={{ width: `${(unknownReqs / totalRequests) * 100}%` }} />
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Featured Research Applications */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h4 className="text-sm font-semibold text-slate-200">Key Demonstration Applications</h4>
            <p className="text-xs text-slate-500">Representative evaluation targets across different policy disclosure patterns</p>
          </div>
          <button
            onClick={() => onNavigate('apps')}
            className="flex items-center gap-1 text-xs font-semibold text-cyan-400 hover:text-cyan-300 transition"
          >
            View All {totalApps} Applications <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {['Truecaller', 'Instagram', 'Spotify', 'Forecastie'].map(appName => {
            const row = masterResults.find(r => r.application.toLowerCase() === appName.toLowerCase());
            if (!row) return null;
            return (
              <div
                key={appName}
                onClick={() => onSelectApp(row.application)}
                className="bg-slate-950 border border-slate-800 hover:border-cyan-600/60 rounded-lg p-4 cursor-pointer transition group"
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-bold text-slate-200 group-hover:text-cyan-300 transition">{row.application}</span>
                  <ResultBadge result={row.result} size="sm" />
                </div>
                <div className="grid grid-cols-2 gap-2 text-xs font-mono text-slate-400 my-2.5">
                  <div>
                    <span className="text-slate-500 block text-[10px]">Requests</span>
                    <span className="text-slate-200 font-semibold">{row.total_requests}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px]">Sensitive</span>
                    <span className="text-indigo-300 font-semibold">{row.sensitive_occurrences}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px]">In Policy</span>
                    <span className="text-emerald-400 font-semibold">{row.disclosed_information_type_count || 0}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px]">Not in Policy</span>
                    <span className="text-rose-400 font-semibold">{row.not_disclosed_information_type_count || 0}</span>
                  </div>
                </div>
                {row.risk_signals && row.risk_signals !== 'None' ? (
                  <div className="flex flex-wrap gap-1">
                    {row.risk_signals.split(';').filter(Boolean).map((risk, index) => (
                      <RiskBadge key={index} risk={risk.trim()} />
                    ))}
                  </div>
                ) : (
                  <div className="text-[11px] font-mono text-slate-500 bg-slate-900/40 px-2 py-0.5 rounded">
                    No URL risk signals
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
