import React, { useState, useEffect } from 'react';
import { getManifest, fetchExternalAppDetail } from '../api/dataLoader';
import { Beaker, ShieldCheck, AlertCircle, FileText, ChevronRight, ArrowLeft } from 'lucide-react';

export function ExternalValidationPage() {
  const manifest = getManifest();
  const externalApps = manifest.external_apps || [];
  const [selectedAppId, setSelectedAppId] = useState(null);
  const [appDetail, setAppDetail] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!selectedAppId) {
      setAppDetail(null);
      return;
    }
    let isMounted = true;
    setLoading(true);
    fetchExternalAppDetail(selectedAppId).then(res => {
      if (isMounted) {
        setAppDetail(res);
        setLoading(false);
      }
    });
    return () => { isMounted = false; };
  }, [selectedAppId]);

  return (
    <div className="space-y-6">
      {/* Disclaimer and Research Scope Banner */}
      <div className="bg-slate-900/80 border border-cyan-900/40 rounded-xl p-5 space-y-2">
        <div className="flex items-center gap-2">
          <Beaker className="w-5 h-5 text-cyan-400" />
          <h2 className="text-base font-bold text-slate-100">External Dataset Evaluation</h2>
          <span className="text-[10px] font-mono uppercase tracking-wider px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
            Cross-Dataset Evaluation
          </span>
        </div>
        <p className="text-xs text-slate-300 leading-relaxed">
          To evaluate detector generalization across distinct network capture pipelines, the framework was executed against public benchmarks from <strong>AntShield</strong>, <strong>PARROT</strong>, and <strong>OVRseen</strong> (VR ecosystem).
        </p>
        <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-[11px] font-mono text-amber-300/90 flex items-center gap-2">
          <AlertCircle className="w-4 h-4 text-amber-400 shrink-0" />
          <span>These detector runs are kept separate from the primary 30-app capture dataset. Public-dataset labels are comparative evidence, not absolute ground truth.</span>
        </div>
      </div>

      {/* Detail or Table View */}
      {selectedAppId && appDetail ? (
        <div className="space-y-5">
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
            <button
              onClick={() => setSelectedAppId(null)}
              className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 mb-3 transition"
            >
              <ArrowLeft className="w-3.5 h-3.5" /> Back to External Benchmarks List
            </button>
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-lg font-bold text-slate-100">{appDetail.app_name}</h3>
                <span className="text-xs font-mono text-cyan-400">Dataset Source: {appDetail.dataset}</span>
              </div>
              <span className="text-xs font-mono text-slate-400 bg-slate-800 px-3 py-1 rounded">
                Target: {selectedAppId}
              </span>
            </div>
          </div>

          {/* Quick Metrics */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
            <div className="bg-slate-900 p-4 rounded-xl border border-slate-800">
              <span className="text-xs text-slate-400 block">Total Requests</span>
              <span className="text-xl font-bold font-mono text-slate-100">{appDetail.total_requests}</span>
            </div>
            <div className="bg-slate-900 p-4 rounded-xl border border-slate-800">
              <span className="text-xs text-slate-400 block">Sensitive Occurrences</span>
              <span className="text-xl font-bold font-mono text-indigo-300">{appDetail.sensitive_occurrences}</span>
            </div>
            <div className="bg-slate-900 p-4 rounded-xl border border-slate-800">
              <span className="text-xs text-slate-400 block">Unique Artifact Types</span>
              <span className="text-xl font-bold font-mono text-cyan-400">{appDetail.unique_artifacts}</span>
            </div>
            <div className="bg-slate-900 p-4 rounded-xl border border-slate-800">
              <span className="text-xs text-slate-400 block">Benchmark Role</span>
              <span className="text-sm font-semibold text-slate-200 mt-1 block">Cross-Platform Test</span>
            </div>
          </div>

          {/* Details / Artifacts Table */}
          {appDetail.artifacts && appDetail.artifacts.length > 0 && (
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-3">
              <h4 className="text-sm font-semibold text-slate-200">Detected Sensitive Artifacts in Benchmark</h4>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse font-mono">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400 text-[11px]">
                      <th className="py-2.5 px-3">Artifact</th>
                      <th className="py-2.5 px-3">Category</th>
                      <th className="py-2.5 px-3 text-right">Occurrences</th>
                      <th className="py-2.5 px-3">Sources</th>
                      <th className="py-2.5 px-3">Domains</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {appDetail.artifacts.map((a, i) => (
                      <tr key={i} className="hover:bg-slate-800/30">
                        <td className="py-2.5 px-3 text-slate-200 font-bold">{a.type}</td>
                        <td className="py-2.5 px-3 text-slate-400">{a.privacy_category}</td>
                        <td className="py-2.5 px-3 text-right text-indigo-300 font-semibold">{a.occurrences}</td>
                        <td className="py-2.5 px-3 text-slate-400 text-[11px]">{a.sources?.join(', ')}</td>
                        <td className="py-2.5 px-3 text-cyan-400 text-[11px] truncate max-w-xs">{a.domains?.join(', ')}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* OVRseen summary if applicable */}
          {appDetail.summary && (
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-3">
              <h4 className="text-sm font-semibold text-slate-200">OVRseen Benchmark Summary</h4>
              <pre className="p-4 bg-slate-950 rounded-lg border border-slate-800 font-mono text-xs text-slate-300 overflow-x-auto">
                {JSON.stringify(appDetail.summary, null, 2)}
              </pre>
            </div>
          )}
        </div>
      ) : (
        /* Benchmark Applications Table */
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-slate-950 border-b border-slate-800 text-slate-400 font-mono text-[11px]">
                  <th className="py-3 px-4 font-semibold">Benchmark Dataset</th>
                  <th className="py-3 px-4 font-semibold">Application Target</th>
                  <th className="py-3 px-3 font-semibold text-right">Network Requests</th>
                  <th className="py-3 px-3 font-semibold text-right">Sensitive Findings</th>
                  <th className="py-3 px-3 font-semibold text-right">Unique Artifacts</th>
                  <th className="py-3 px-4 font-semibold">Evaluation Role</th>
                  <th className="py-3 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-sans">
                {externalApps.map((item, idx) => (
                  <tr
                    key={idx}
                    onClick={() => setSelectedAppId(item.id)}
                    className="hover:bg-slate-800/40 cursor-pointer transition group"
                  >
                    <td className="py-3 px-4">
                      <span className={`px-2 py-0.5 rounded text-[11px] font-mono font-semibold ${
                        item.dataset === 'AntShield' ? 'bg-amber-950 text-amber-400 border border-amber-800' :
                        item.dataset === 'OVRseen' ? 'bg-purple-950 text-purple-400 border border-purple-800' :
                        'bg-blue-950 text-blue-400 border border-blue-800'
                      }`}>
                        {item.dataset}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-bold text-slate-200 group-hover:text-cyan-400 transition font-mono">
                      {item.app_name}
                    </td>
                    <td className="py-3 px-3 text-right font-mono text-slate-300">
                      {item.total_requests.toLocaleString()}
                    </td>
                    <td className="py-3 px-3 text-right font-mono text-indigo-300 font-semibold">
                      {item.sensitive_occurrences.toLocaleString()}
                    </td>
                    <td className="py-3 px-3 text-right font-mono text-slate-300">
                      {item.unique_artifacts}
                    </td>
                    <td className="py-3 px-4 text-slate-400 text-xs">
                      {item.id.includes('roblox') ? (
                        <span className="text-cyan-400 font-semibold">Roblox Client Dataset Evaluation</span>
                      ) : item.dataset === 'OVRseen' ? (
                        <span>VR Network Reconstruction Test</span>
                      ) : (
                        <span>Android HAR Replay Test</span>
                      )}
                    </td>
                    <td className="py-3 px-3 text-right text-slate-500 group-hover:text-cyan-400 transition">
                      <ChevronRight className="w-4 h-4 ml-auto" />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
