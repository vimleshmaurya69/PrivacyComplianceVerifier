import React, { useState, useMemo } from 'react';
import { Search, ArrowUpDown, ChevronRight, Info } from 'lucide-react';
import { ResultBadge } from '../components/StatusBadge';
import { RiskBadge } from '../components/RiskBadge';

export function AppListPage({ masterResults, onSelectApp }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [resultFilter, setResultFilter] = useState('ALL');
  const [riskFilter, setRiskFilter] = useState('ALL');
  const [sortField, setSortField] = useState('total_requests');
  const [sortDirection, setSortDirection] = useState('desc');

  const filteredApps = useMemo(() => {
    return masterResults.filter(app => {
      const matchesSearch = app.application.toLowerCase().includes(searchTerm.toLowerCase());
      const matchesResult = resultFilter === 'ALL' || app.result === resultFilter;
      const matchesRisk =
        riskFilter === 'ALL' ||
        (riskFilter === 'WITH_RISK' && app.risk_signals && app.risk_signals !== 'None') ||
        (riskFilter === 'NO_RISK' && (!app.risk_signals || app.risk_signals === 'None'));
      return matchesSearch && matchesResult && matchesRisk;
    }).sort((a, b) => {
      let aVal = a[sortField];
      let bVal = b[sortField];
      if (typeof aVal === 'string') {
        aVal = aVal.toLowerCase();
        bVal = bVal.toLowerCase();
      }
      if (aVal < bVal) return sortDirection === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortDirection === 'asc' ? 1 : -1;
      return 0;
    });
  }, [masterResults, searchTerm, resultFilter, riskFilter, sortField, sortDirection]);

  const handleSort = (field) => {
    if (sortField === field) {
      setSortDirection(prev => prev === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('desc');
    }
  };

  return (
    <div className="space-y-5">
      {/* Header and Filter Controls */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h2 className="text-base font-bold text-slate-100">Analyzed Applications</h2>
            <p className="text-xs text-slate-400">
              Showing {filteredApps.length} of {masterResults.length} applications from empirical dataset
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            {/* Search Input */}
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search application..."
                value={searchTerm}
                onChange={e => setSearchTerm(e.target.value)}
                className="pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-700/80 rounded-lg text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 w-48 lg:w-64"
              />
            </div>

            {/* Result Filter */}
            <select
              value={resultFilter}
              onChange={e => setResultFilter(e.target.value)}
              className="bg-slate-950 border border-slate-700/80 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Policy Results</option>
              <option value="COMPLIANT_WITHIN_CAPTURE_SCOPE">All Comparable Types Disclosed</option>
              <option value="POTENTIALLY_NON_COMPLIANT">Potentially Non-Compliant</option>
              <option value="CANNOT_DETERMINE">Policy Check Incomplete</option>
            </select>

            {/* Risk Filter */}
            <select
              value={riskFilter}
              onChange={e => setRiskFilter(e.target.value)}
              className="bg-slate-950 border border-slate-700/80 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Risk States</option>
              <option value="WITH_RISK">Has Risk Signals</option>
              <option value="NO_RISK">No Risk Signals</option>
            </select>
          </div>
        </div>
      </div>

      <div className="bg-cyan-950/20 border border-cyan-900/50 rounded-xl px-4 py-3 flex items-start gap-2.5 text-xs text-slate-300">
        <Info className="w-4 h-4 text-cyan-400 mt-0.5 shrink-0" />
        <p>
          <strong>In Policy / Not in Policy count comparable personal-data types</strong>, not raw occurrences or
          broad categories. Authorization tokens and session cookies remain visible as technical authentication
          evidence but do not create a policy gap. URL risk signals are checked separately.
        </p>
      </div>

      {/* Applications Table */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-slate-950/80 border-b border-slate-800 text-slate-400 font-mono text-[11px]">
                <th className="py-3 px-4 font-semibold cursor-pointer hover:text-slate-200" onClick={() => handleSort('application')}>
                  <div className="flex items-center gap-1.5">
                    <span>Application</span>
                    <ArrowUpDown className="w-3 h-3" />
                  </div>
                </th>
                <th className="py-3 px-3 font-semibold text-right cursor-pointer hover:text-slate-200" onClick={() => handleSort('total_requests')}>
                  <div className="flex items-center justify-end gap-1.5">
                    <span>Requests</span>
                    <ArrowUpDown className="w-3 h-3" />
                  </div>
                </th>
                <th className="py-3 px-3 font-semibold text-right cursor-pointer hover:text-slate-200" onClick={() => handleSort('sensitive_occurrences')}>
                  <div className="flex items-center justify-end gap-1.5">
                    <span>Sensitive</span>
                    <ArrowUpDown className="w-3 h-3" />
                  </div>
                </th>
                <th className="py-3 px-3 font-semibold text-right cursor-pointer hover:text-slate-200" onClick={() => handleSort('unique_sensitive_artifacts')}>
                  <div className="flex items-center justify-end gap-1.5">
                    <span>Artifacts</span>
                    <ArrowUpDown className="w-3 h-3" />
                  </div>
                </th>
                <th className="py-3 px-3 font-semibold text-right cursor-pointer hover:text-slate-200" onClick={() => handleSort('disclosed_information_type_count')}>
                  <div className="flex items-center justify-end gap-1.5">
                    <span>In Policy</span>
                    <ArrowUpDown className="w-3 h-3" />
                  </div>
                </th>
                <th className="py-3 px-3 font-semibold text-right cursor-pointer hover:text-slate-200" onClick={() => handleSort('not_disclosed_information_type_count')}>
                  <div className="flex items-center justify-end gap-1.5">
                    <span>Not in Policy</span>
                    <ArrowUpDown className="w-3 h-3" />
                  </div>
                </th>
                <th className="py-3 px-3 font-semibold text-right cursor-pointer hover:text-slate-200" onClick={() => handleSort('policy_review_incomplete_type_count')}>
                  <div className="flex items-center justify-end gap-1.5">
                    <span>Policy Unclear</span>
                    <ArrowUpDown className="w-3 h-3" />
                  </div>
                </th>
                <th className="py-3 px-4 font-semibold">Risk Signals</th>
                <th className="py-3 px-4 font-semibold">Policy Result</th>
                <th className="py-3 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {filteredApps.map((app, idx) => {
                const risks = (app.risk_signals || '').split(';').filter(Boolean);
                return (
                  <tr
                    key={idx}
                    onClick={() => onSelectApp(app.application)}
                    className="hover:bg-slate-800/40 cursor-pointer transition group"
                  >
                    <td className="py-3 px-4 font-semibold text-slate-200 group-hover:text-cyan-400 transition">
                      {app.application}
                    </td>
                    <td className="py-3 px-3 text-right font-mono text-slate-300">
                      {app.total_requests.toLocaleString()}
                    </td>
                    <td className="py-3 px-3 text-right font-mono text-indigo-300 font-medium">
                      {app.sensitive_occurrences.toLocaleString()}
                    </td>
                    <td className="py-3 px-3 text-right font-mono text-slate-300">
                      {app.unique_sensitive_artifacts}
                    </td>
                    <td className="py-3 px-3 text-right font-mono text-emerald-400 font-semibold">
                      {app.disclosed_information_type_count || 0}
                    </td>
                    <td className="py-3 px-3 text-right font-mono text-amber-400 font-semibold">
                      {app.not_disclosed_information_type_count || 0}
                    </td>
                    <td className="py-3 px-3 text-right font-mono text-slate-400">
                      {app.policy_review_incomplete_type_count || 0}
                    </td>
                    <td className="py-3 px-4">
                      {risks.length > 0 ? (
                        <div className="flex flex-wrap gap-1">
                          {risks.map((r, rIdx) => (
                            <RiskBadge key={rIdx} risk={r.trim()} />
                          ))}
                        </div>
                      ) : (
                        <span className="text-[11px] text-slate-500 font-mono">No URL risk</span>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      <ResultBadge result={app.result} size="sm" />
                    </td>
                    <td className="py-3 px-3 text-right text-slate-500 group-hover:text-cyan-400 transition">
                      <ChevronRight className="w-4 h-4 ml-auto" />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
