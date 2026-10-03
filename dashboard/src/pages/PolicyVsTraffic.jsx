import React, { useState, useEffect } from 'react';
import { fetchAppDetail, getManifest, STATUS_CONFIG } from '../api/dataLoader';
import { StatusBadge } from '../components/StatusBadge';
import { FileCheck, ChevronDown, ChevronRight, Search, ShieldCheck } from 'lucide-react';

export function PolicyVsTraffic({ selectedApp, onSelectApp }) {
  const manifest = getManifest();
  const [currentApp, setCurrentApp] = useState(selectedApp || 'Truecaller');
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [expandedRow, setExpandedRow] = useState(null);

  useEffect(() => {
    let isMounted = true;
    setLoading(true);
    fetchAppDetail(currentApp).then(res => {
      if (isMounted) {
        setData(res);
        setLoading(false);
      }
    });
    return () => { isMounted = false; };
  }, [currentApp]);

  const handleAppChange = (e) => {
    setCurrentApp(e.target.value);
    if (onSelectApp) onSelectApp(e.target.value);
  };

  const results = data?.simpleReport?.information_type_results || [];

  return (
    <div className="space-y-6">
      {/* Header and Application Selector */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <FileCheck className="w-5 h-5 text-cyan-400" />
              What the Policy Says vs. What Traffic Shows
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              One row per information type: whether it was observed and whether the reviewed policy names it.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400 font-mono">Select App:</span>
            <select
              value={currentApp}
              onChange={handleAppChange}
              className="bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-medium"
            >
              {manifest.primary_apps.map(a => (
                <option key={a.id} value={a.id}>{a.app_name}</option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {loading ? (
        <div className="p-12 text-center text-slate-500 font-mono text-xs">
          Loading comparison data for {currentApp}...
        </div>
      ) : results.length === 0 ? (
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-8 text-center text-slate-400 text-xs">
          No structured policy comparison records found for {data?.appName || currentApp}.
        </div>
      ) : (
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-slate-950 border-b border-slate-800 text-slate-400 font-mono text-[11px]">
                  <th className="py-3 px-4 font-semibold">Information Type</th>
                  <th className="py-3 px-3 font-semibold">Category</th>
                  <th className="py-3 px-3 font-semibold text-center">Declared in Policy</th>
                  <th className="py-3 px-3 font-semibold text-center">Observed in Traffic</th>
                  <th className="py-3 px-4 font-semibold">Comparison Result</th>
                  <th className="py-3 px-4 font-semibold">Destination / Action</th>
                  <th className="py-3 px-3 text-right">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-sans">
                {results.map((r, idx) => {
                  const isExpanded = expandedRow === idx;
                  const isDeclaredNotObserved = r.status === 'DECLARED_NOT_OBSERVED_IN_CAPTURE' || r.status === 'NOT_ASSESSABLE_FROM_HAR';
                  const isDeclared = (r.policy_evidence?.length > 0 || isDeclaredNotObserved);
                  const isObserved = (r.occurrences || 0) > 0;
                  const isTechnicalAuthentication = r.status === 'TECHNICAL_AUTHENTICATION_ARTIFACT';

                  return (
                    <React.Fragment key={idx}>
                      <tr
                        onClick={() => setExpandedRow(isExpanded ? null : idx)}
                        className="hover:bg-slate-800/40 cursor-pointer transition"
                      >
                        <td className="py-3 px-4 font-mono font-bold text-slate-200">
                          {r.artifact_type || r.artifact_types?.join(', ') || 'General Type'}
                        </td>
                        <td className="py-3 px-3 text-slate-400">
                          {r.privacy_categories?.join(', ') || r.privacy_category || 'Uncategorized'}
                        </td>
                        <td className="py-3 px-3 text-center">
                          {isTechnicalAuthentication ? (
                            <span className="px-2 py-0.5 rounded font-mono text-[10px] font-semibold bg-sky-950 text-sky-400 border border-sky-800">
                              NOT REQUIRED
                            </span>
                          ) : isDeclared ? (
                            <span className="px-2 py-0.5 rounded font-mono text-[10px] font-semibold bg-emerald-950 text-emerald-400 border border-emerald-800">
                              YES
                            </span>
                          ) : r.status === 'NOT_DISCLOSED_IN_REVIEWED_POLICY' ? (
                            <span className="px-2 py-0.5 rounded font-mono text-[10px] font-semibold bg-rose-950 text-rose-400 border border-rose-800">
                              NO
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded font-mono text-[10px] font-semibold bg-amber-950 text-amber-400 border border-amber-800">
                              REVIEW INCOMPLETE
                            </span>
                          )}
                        </td>
                        <td className="py-3 px-3 text-center">
                          {isObserved ? (
                            <span className="px-2 py-0.5 rounded font-mono text-[10px] font-semibold bg-blue-950 text-blue-400 border border-blue-800">
                              YES ({r.occurrences || 1})
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded font-mono text-[10px] font-semibold bg-slate-900 text-slate-500 border border-slate-800">
                              NO
                            </span>
                          )}
                        </td>
                        <td className="py-3 px-4">
                          <StatusBadge status={r.status} />
                        </td>
                        <td className="py-3 px-4 font-mono text-slate-400 truncate max-w-xs text-[11px]">
                          {r.destinations?.length ? (
                            <span>transmit &rarr; <span className="text-cyan-400">{r.destinations.join(', ')}</span></span>
                          ) : (
                            <span className="text-slate-500">Not observed on network</span>
                          )}
                        </td>
                        <td className="py-3 px-3 text-right text-slate-500">
                          {isExpanded ? <ChevronDown className="w-4 h-4 ml-auto" /> : <ChevronRight className="w-4 h-4 ml-auto" />}
                        </td>
                      </tr>

                      {/* Expandable Evidence Card */}
                      {isExpanded && (
                        <tr className="bg-slate-950/90">
                          <td colSpan="7" className="p-4 border-b border-slate-800">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                              {/* Left: Decision explanation */}
                              <div className="space-y-2">
                                <span className="font-semibold text-slate-300 block">Comparator Explanation:</span>
                                <div className="p-3 bg-slate-900 rounded border border-slate-800 text-slate-300 leading-relaxed">
                                  {STATUS_CONFIG[r.status]?.description || r.reason_code}
                                </div>
                                <div className="text-[11px] font-mono text-slate-500">
                                  Reason Code: {r.reason_code}
                                </div>
                              </div>

                              {/* Right: Policy text snippet */}
                              <div className="space-y-2">
                                <span className="font-semibold text-slate-300 block">Matched Policy Evidence / Reviewed Summary:</span>
                                {r.policy_evidence?.length > 0 ? (
                                  <div className="space-y-2">
                                    {r.policy_evidence.map((p, pIdx) => (
                                      <div key={pIdx} className="p-3 bg-slate-900 rounded border border-slate-800 text-[11px] space-y-1">
                                        <div className="flex justify-between font-mono text-cyan-400">
                                          <span>ID: {p.practice_id}</span>
                                          <span>{p.reviewed_at || 'Review date unavailable'}</span>
                                        </div>
                                        {p.locator && (
                                          <div className="text-slate-400 font-mono">
                                            Locator: {p.locator}
                                          </div>
                                        )}
                                        {p.statement && (
                                          <div className="text-slate-200 italic bg-slate-950 p-2 rounded border border-slate-800/80">
                                            {Array.isArray(p.statement) ? p.statement.join(', ') : p.statement}
                                          </div>
                                        )}
                                      </div>
                                    ))}
                                  </div>
                                ) : (
                                  <div className="p-3 bg-slate-900 rounded border border-slate-800 text-slate-500 italic text-[11px]">
                                    {isTechnicalAuthentication
                                      ? 'Routine authentication artifact retained as technical evidence; no dashboard policy match is required.'
                                      : 'No explicit artifact-level statement found in policy for this information type.'}
                                  </div>
                                )}
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
