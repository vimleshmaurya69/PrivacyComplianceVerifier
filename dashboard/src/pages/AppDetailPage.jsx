import React, { useState, useEffect } from 'react';
import {
  ArrowLeft,
  Server,
  ShieldAlert,
  FileText,
  Radio,
  ExternalLink,
  ChevronDown,
  ChevronRight,
  Globe,
  Key,
  AlertTriangle,
  Info
} from 'lucide-react';
import { fetchAppDetail, findAppInManifest, STATUS_CONFIG } from '../api/dataLoader';
import { StatusBadge, ResultBadge } from '../components/StatusBadge';
import { RiskBadge } from '../components/RiskBadge';

export function AppDetailPage({ appName, onBack, onNavigateToEvidence }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [expandedSection, setExpandedSection] = useState(null);
  const [activeTab, setActiveTab] = useState('policy'); // 'policy', 'traffic', 'artifacts', 'destinations'

  useEffect(() => {
    let isMounted = true;
    setLoading(true);
    fetchAppDetail(appName).then(res => {
      if (isMounted) {
        setData(res);
        setLoading(false);
      }
    });
    return () => { isMounted = false; };
  }, [appName]);

  if (loading) {
    return (
      <div className="flex items-center justify-center p-20 text-slate-400 font-mono text-xs">
        Loading evaluation artifacts for {appName}...
      </div>
    );
  }

  if (!data || !data.statistics) {
    return (
      <div className="p-8 text-center bg-slate-900 border border-slate-800 rounded-xl space-y-4">
        <p className="text-sm text-slate-400">No output directory found for application: {appName}</p>
        <button onClick={onBack} className="px-4 py-2 bg-slate-800 text-xs rounded-lg text-slate-200">
          Back to Applications
        </button>
      </div>
    );
  }

  const { statistics, compliance, artifacts, simpleReport, appId } = data;
  const results = simpleReport?.information_type_results || [];
  const practiceRisks = compliance.practice_risks || [];
  const declaredTypes = simpleReport?.policy_declares?.information_types || [];

  // Grouped results by status
  const groupedResults = results.reduce((acc, r) => {
    const st = r.status || 'OTHER';
    if (!acc[st]) acc[st] = [];
    acc[st].push(r);
    return acc;
  }, {});

  // Extract unique destinations
  const destinationMap = {};
  artifacts.forEach(art => {
    (art.domains || []).forEach(dom => {
      if (!destinationMap[dom]) {
        destinationMap[dom] = { occurrences: 0, artifacts: new Set(), trafficType: art.traffic_types?.[0] || 'Unknown' };
      }
      destinationMap[dom].occurrences += (art.occurrences || 1);
      destinationMap[dom].artifacts.add(art.type);
    });
  });

  const destinationsList = Object.entries(destinationMap).map(([domain, info]) => ({
    domain,
    occurrences: info.occurrences,
    artifacts: Array.from(info.artifacts),
    trafficType: info.trafficType
  })).sort((a, b) => b.occurrences - a.occurrences);

  return (
    <div className="space-y-6">
      {/* Top Breadcrumb & Header */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
        <button
          onClick={onBack}
          className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 mb-3 transition"
        >
          <ArrowLeft className="w-3.5 h-3.5" /> Back to Applications List
        </button>

        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-xl font-bold text-slate-100">{data.appName}</h1>
              <span className="text-xs font-mono text-slate-400 bg-slate-800 px-2.5 py-0.5 rounded">
                ID: {appId}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Observed network information compared with explicit statements in the reviewed privacy policy.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <ResultBadge result={simpleReport?.result || statistics.overall_status} size="lg" />
          </div>
        </div>

        {simpleReport?.raw_framework_result && simpleReport.raw_framework_result !== simpleReport.result && (
          <div className="mt-3 text-[11px] text-slate-400 font-mono">
            Dashboard presentation excludes routine technical authentication artifacts from policy-gap counts.
            {' '}Raw framework result: {simpleReport.raw_framework_result}
          </div>
        )}
      </div>

      <div className="bg-cyan-950/20 border border-cyan-900/50 rounded-xl p-4 text-xs text-slate-300 flex items-start gap-2.5">
        <Info className="w-4 h-4 text-cyan-400 mt-0.5 shrink-0" />
        <p>
          <strong>The policy result and risk signals answer different questions.</strong> The policy result checks
          comparable personal-data types. Authorization tokens and session cookies are shown as technical
          authentication evidence and do not create a policy gap; unsafe placement such as a credential in a URL
          remains a separate risk signal.
        </p>
      </div>

      {/* Grid: Network Overview & Sensitive Data Ledger */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Network Overview */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <Server className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-slate-200">Network Traffic Overview</h3>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
            <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800/80">
              <span className="text-[11px] text-slate-400 block">Total Requests</span>
              <span className="text-lg font-bold font-mono text-slate-100">{(statistics.total_requests || 0).toLocaleString()}</span>
            </div>
            <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800/80">
              <span className="text-[11px] text-slate-400 block">Application-Attributed</span>
              <span className="text-lg font-bold font-mono text-cyan-400">{(statistics.application_requests || 0).toLocaleString()}</span>
            </div>
            <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800/80">
              <span className="text-[11px] text-slate-400 block">Third-Party & Ads</span>
              <span className="text-lg font-bold font-mono text-indigo-400">{(statistics.third_party_requests || 0).toLocaleString()}</span>
            </div>
            <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800/80">
              <span className="text-[11px] text-slate-400 block">Android System</span>
              <span className="text-lg font-bold font-mono text-amber-400">{(statistics.android_requests || 0).toLocaleString()}</span>
            </div>
            <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800/80">
              <span className="text-[11px] text-slate-400 block">Unknown / Unclassified</span>
              <span className="text-lg font-bold font-mono text-slate-400">{(statistics.unknown_requests || 0).toLocaleString()}</span>
            </div>
            <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800/80">
              <span className="text-[11px] text-slate-400 block">Attributable Ratio</span>
              <span className="text-lg font-bold font-mono text-emerald-400">
                {statistics.total_requests ? (((statistics.application_requests + statistics.third_party_requests) / statistics.total_requests) * 100).toFixed(0) : 0}%
              </span>
            </div>
          </div>
        </div>

        {/* Sensitive-Data Overview & Attributability Ledger */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <ShieldAlert className="w-4 h-4 text-indigo-400" />
            <h3 className="text-sm font-semibold text-slate-200">Sensitive-Data & Attributability Ledger</h3>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
            <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800/80">
              <span className="text-[11px] text-slate-400 block">Sensitive Occurrences</span>
              <span className="text-lg font-bold font-mono text-indigo-300">{(statistics.sensitive_data_occurrences || 0).toLocaleString()}</span>
            </div>
            <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800/80">
              <span className="text-[11px] text-slate-400 block">Comparable Outbound</span>
              <span className="text-lg font-bold font-mono text-emerald-400">{(statistics.comparison_outbound_occurrences || 0).toLocaleString()}</span>
            </div>
            <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800/80">
              <span className="text-[11px] text-slate-400 block">Attributable Inbound</span>
              <span className="text-lg font-bold font-mono text-sky-400">{(statistics.attributable_inbound_occurrences || 0).toLocaleString()}</span>
            </div>
            <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800/80">
              <span className="text-[11px] text-slate-400 block">Excluded Technical</span>
              <span className="text-lg font-bold font-mono text-slate-400">{(statistics.excluded_technical_occurrences || 0).toLocaleString()}</span>
            </div>
            <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800/80">
              <span className="text-[11px] text-slate-400 block">Non-Attributable</span>
              <span className="text-lg font-bold font-mono text-slate-400">{(statistics.non_attributable_occurrences || 0).toLocaleString()}</span>
            </div>
            <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800/80">
              <span className="text-[11px] text-slate-400 block">Unique Artifact Types</span>
              <span className="text-lg font-bold font-mono text-cyan-400">{(statistics.unique_sensitive_artifacts || 0).toLocaleString()}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Risk Signals Section (Separated from Policy Comparison) */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-400" />
            <h3 className="text-sm font-semibold text-slate-200">Transmission Channel Risk Signals</h3>
          </div>
          <span className="text-[11px] text-slate-400 italic">
            Risk signals are independent of whether an information type appears in the policy.
          </span>
        </div>

        {practiceRisks.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {practiceRisks.map((risk, idx) => (
              <div key={idx} className="bg-slate-950 border border-rose-900/40 rounded-lg p-3.5 space-y-1.5">
                <div className="flex items-center justify-between">
                  <RiskBadge risk={risk.type} />
                  <span className="text-[10px] font-mono text-rose-400 bg-rose-950/60 px-2 py-0.5 rounded border border-rose-800/50">
                    Severity: {risk.severity || 'MEDIUM'}
                  </span>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed mt-1">
                  {risk.explanation || 'Personal data, credential, or identifier was observed in an unencrypted or URL query parameter channel.'}
                </p>
                <div className="text-[11px] text-slate-500 font-mono">
                  Evidence instances: {(risk.evidence || []).length}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="bg-slate-950/50 border border-slate-800 rounded-lg p-3 text-xs text-slate-400 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-500" />
            No URL transmission risk was detected. This does not mean every observed information type was disclosed in the policy.
          </div>
        )}
      </div>

      {/* Tabs: Policy vs Traffic, Detected Artifacts, Destinations */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
          <button
            onClick={() => setActiveTab('policy')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
              activeTab === 'policy' ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Policy & Traffic Result ({results.length})
          </button>
          <button
            onClick={() => setActiveTab('artifacts')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
              activeTab === 'artifacts' ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Detected Sensitive Artifacts ({artifacts.length})
          </button>
          <button
            onClick={() => setActiveTab('destinations')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
              activeTab === 'destinations' ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Observed Destinations ({destinationsList.length})
          </button>
        </div>

        {/* TAB 1: POLICY VS TRAFFIC RESULT */}
        {activeTab === 'policy' && (
          <div className="space-y-4">
            {/* Policy Declarations Summary */}
            <div className="bg-slate-950 p-3.5 rounded-lg border border-slate-800/80 text-xs">
              <span className="text-slate-400 font-semibold block mb-1">
                Information Types Explicitly Named in the Reviewed Policy ({declaredTypes.length}) — {simpleReport?.policy_review?.status || 'UNKNOWN'}:
              </span>
              <div className="flex flex-wrap gap-1.5">
                {declaredTypes.length > 0 ? (
                  declaredTypes.map((cat, i) => (
                    <span key={i} className="px-2 py-0.5 bg-slate-900 border border-slate-800 text-slate-300 rounded text-[11px] font-mono">
                      {cat}
                    </span>
                  ))
                ) : (
                  <span className="text-slate-500 italic">No explicit information types recorded</span>
                )}
              </div>
            </div>

            {/* Decision Records by Status */}
            {results.length > 0 ? (
              <div className="space-y-3">
                {results.map((r, idx) => {
                  const isExpanded = expandedSection === idx;
                  const policyEvidence = r.policy_evidence || [];
                  const evidenceList = (r.locations || []).map((source, evidenceIndex) => ({
                    source,
                    key: (r.keys || [])[evidenceIndex] || (r.keys || [])[0],
                    domain: (r.destinations || [])[evidenceIndex] || (r.destinations || [])[0]
                  }));

                  return (
                    <div key={idx} className="bg-slate-950 border border-slate-800 rounded-lg p-4 space-y-3">
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <StatusBadge status={r.status} />
                          <span className="text-xs font-bold text-slate-200 font-mono">
                            {r.artifact_type || 'General Type'}
                          </span>
                          <span className="text-[11px] text-slate-400">
                            ({r.privacy_categories?.join(', ') || r.privacy_category || 'Uncategorized'})
                          </span>
                        </div>
                        <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
                          <span>Occurrences: {r.occurrences || 0}</span>
                          <button
                            onClick={() => setExpandedSection(isExpanded ? null : idx)}
                            className="p-1 hover:text-slate-200"
                          >
                            {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                          </button>
                        </div>
                      </div>

                      {/* Explanation */}
                      <p className="text-xs text-slate-300 leading-relaxed">
                        {STATUS_CONFIG[r.status]?.description || r.reason_code}
                      </p>

                      {/* Key details */}
                      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs font-mono bg-slate-900/60 p-2.5 rounded border border-slate-800/60">
                        <div>
                          <span className="text-slate-500 block text-[10px]">Action</span>
                          <span className="text-slate-200">{r.occurrences ? 'transmit (outbound)' : 'not observed'}</span>
                        </div>
                        <div>
                          <span className="text-slate-500 block text-[10px]">Destination Domain</span>
                          <span className="text-cyan-400 truncate block">{r.destinations?.join(', ') || 'Not observed'}</span>
                        </div>
                        <div>
                          <span className="text-slate-500 block text-[10px]">Request Location</span>
                          <span className="text-slate-200">{r.locations?.join(', ') || 'Not observed'}</span>
                        </div>
                      </div>

                      {/* Expandable policy evidence and traffic findings */}
                      {isExpanded && (
                        <div className="pt-3 border-t border-slate-800 space-y-3 text-xs">
                          {/* Policy Evidence */}
                          <div>
                            <span className="text-slate-400 font-semibold block mb-1">Corroborating Policy Evidence / Reviewed Summary:</span>
                            {policyEvidence.length > 0 ? (
                              <div className="space-y-2">
                                {policyEvidence.map((p, pIdx) => (
                                  <div key={pIdx} className="bg-slate-900/90 border border-slate-800 p-2.5 rounded text-[11px] space-y-1">
                                    <div className="flex justify-between font-mono text-slate-400">
                                      <span className="text-cyan-400">Practice ID: {p.practice_id}</span>
                                      <span>{p.reviewed_at || 'Review date unavailable'}</span>
                                    </div>
                                    {p.locator && (
                                      <div className="text-slate-400 font-mono">
                                        Location: {p.locator}
                                      </div>
                                    )}
                                    {p.statement && (
                                      <div className="text-slate-200 bg-slate-950 p-2 rounded border border-slate-800 italic">
                                        {Array.isArray(p.statement) ? p.statement.join(', ') : p.statement}
                                      </div>
                                    )}
                                  </div>
                                ))}
                              </div>
                            ) : (
                              <div className="text-slate-500 italic text-[11px]">
                                {r.status === 'TECHNICAL_AUTHENTICATION_ARTIFACT'
                                  ? 'No policy match is required for this dashboard technical-evidence classification.'
                                  : 'No explicit policy practice matched this observed transmission.'}
                              </div>
                            )}
                          </div>

                          {/* Observed Traffic Details */}
                          <div>
                            <span className="text-slate-400 font-semibold block mb-1">Observed Network Evidence Samples:</span>
                            <div className="space-y-1 font-mono text-[11px]">
                              {evidenceList.slice(0, 3).map((ev, eIdx) => (
                                <div key={eIdx} className="bg-slate-900/70 p-2 rounded flex justify-between">
                                  <span className="text-slate-300">{ev.source}: <strong className="text-slate-100">{ev.key}</strong></span>
                                  <span className="text-cyan-400">{ev.domain}</span>
                                </div>
                              ))}
                              {evidenceList.length > 3 && (
                                <div className="text-slate-500 text-[10px] pt-1">
                                  + {evidenceList.length - 3} additional evidence items in inventory
                                </div>
                              )}
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="text-center py-8 text-slate-500 text-xs">
                No policy comparison records generated for this application.
              </div>
            )}
          </div>
        )}

        {/* TAB 2: DETECTED ARTIFACTS */}
        {activeTab === 'artifacts' && (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-slate-950 border-b border-slate-800 text-slate-400 font-mono text-[11px]">
                  <th className="py-2.5 px-3">Artifact Type</th>
                  <th className="py-2.5 px-3">Category</th>
                  <th className="py-2.5 px-3">Redacted Sample</th>
                  <th className="py-2.5 px-3 text-right">Occurrences</th>
                  <th className="py-2.5 px-3">Location / Key</th>
                  <th className="py-2.5 px-3">Domains</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {artifacts.map((art, idx) => (
                  <tr key={idx} className="hover:bg-slate-800/30">
                    <td className="py-2.5 px-3 font-semibold text-slate-200 font-mono">{art.type}</td>
                    <td className="py-2.5 px-3 text-slate-400">{art.privacy_category}</td>
                    <td className="py-2.5 px-3 font-mono text-cyan-400 bg-slate-950/60 px-2 py-0.5 rounded">
                      {art.value_redacted || 'Redacted'}
                    </td>
                    <td className="py-2.5 px-3 text-right font-mono text-indigo-300 font-medium">
                      {(art.occurrences || 1).toLocaleString()}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-slate-400 text-[11px] truncate max-w-xs">
                      {art.sources?.join(', ')} ({art.keys?.slice(0, 2).join(', ')})
                    </td>
                    <td className="py-2.5 px-3 font-mono text-slate-400 text-[11px] truncate max-w-xs">
                      {art.domains?.join(', ')}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* TAB 3: OBSERVED DESTINATIONS */}
        {activeTab === 'destinations' && (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-slate-950 border-b border-slate-800 text-slate-400 font-mono text-[11px]">
                  <th className="py-2.5 px-3">Destination Domain</th>
                  <th className="py-2.5 px-3">Classification</th>
                  <th className="py-2.5 px-3 text-right">Sensitive Findings</th>
                  <th className="py-2.5 px-3">Artifacts Received</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {destinationsList.map((d, idx) => (
                  <tr key={idx} className="hover:bg-slate-800/30">
                    <td className="py-2.5 px-3 text-cyan-400 font-medium">{d.domain}</td>
                    <td className="py-2.5 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] ${
                        d.trafficType === 'Application' ? 'bg-cyan-950 text-cyan-400 border border-cyan-800' :
                        d.trafficType === 'Third Party' ? 'bg-indigo-950 text-indigo-400 border border-indigo-800' :
                        'bg-slate-900 text-slate-400'
                      }`}>
                        {d.trafficType}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-right text-indigo-300 font-semibold">{d.occurrences}</td>
                    <td className="py-2.5 px-3 text-slate-300 text-[11px]">{d.artifacts.join(', ')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
