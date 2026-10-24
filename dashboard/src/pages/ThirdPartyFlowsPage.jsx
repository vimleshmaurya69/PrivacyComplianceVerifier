import React, { useEffect, useMemo, useState } from 'react';
import { ArrowUpRight, Network, Search } from 'lucide-react';
import { fetchThirdPartyFlows, STATUS_CONFIG } from '../api/dataLoader';

const RISK_STYLES = {
  HIGH: 'bg-rose-500/10 text-rose-300 border-rose-500/30',
  MEDIUM: 'bg-amber-500/10 text-amber-300 border-amber-500/30',
  INFORMATIONAL: 'bg-slate-500/10 text-slate-400 border-slate-500/30'
};

export function ThirdPartyFlowsPage({ onSelectApp }) {
  const [flows, setFlows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [risk, setRisk] = useState('ALL');

  useEffect(() => {
    fetchThirdPartyFlows().then(setFlows).finally(() => setLoading(false));
  }, []);

  const filtered = useMemo(() => flows.filter(flow => {
    const haystack = `${flow.appName} ${flow.domain} ${flow.provider} ${flow.service}`.toLowerCase();
    return haystack.includes(search.toLowerCase()) && (risk === 'ALL' || flow.riskLevel === risk);
  }), [flows, search, risk]);

  const appCount = new Set(flows.map(flow => flow.appId)).size;
  const highCount = flows.filter(flow => flow.riskLevel === 'HIGH').length;

  return (
    <div className="space-y-5">
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
        <div className="flex items-start gap-3">
          <div className="p-2 rounded-lg bg-indigo-500/10 border border-indigo-500/30 text-indigo-300"><Network className="w-5 h-5" /></div>
          <div>
            <h2 className="text-base font-bold text-slate-100">Third-Party Data Flows</h2>
            <p className="text-xs text-slate-300 mt-1">Sensitive evidence observed in outbound traffic classified as third party, grouped by application and destination.</p>
            <p className="text-[11px] text-amber-300 mt-2 font-mono">A third-party flow is a privacy-review signal, not automatic proof of a policy violation. Counts are observed occurrences, not unique people or values.</p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-3">
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4"><div className="text-xs text-slate-400">Applications</div><div className="text-2xl font-mono font-bold">{appCount}</div></div>
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4"><div className="text-xs text-slate-400">Destination flows</div><div className="text-2xl font-mono font-bold">{flows.length}</div></div>
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4"><div className="text-xs text-slate-400">High-review flows</div><div className="text-2xl font-mono font-bold text-rose-300">{highCount}</div></div>
      </div>

      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 flex flex-wrap justify-between gap-3">
        <div className="relative"><Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-500" /><input value={search} onChange={event => setSearch(event.target.value)} placeholder="Search app, provider, domain..." className="w-72 pl-9 pr-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-xs" /></div>
        <select value={risk} onChange={event => setRisk(event.target.value)} className="bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs"><option value="ALL">All review levels</option><option value="HIGH">High</option><option value="MEDIUM">Medium</option><option value="INFORMATIONAL">Informational</option></select>
      </div>

      <div className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden">
        {loading ? <div className="p-10 text-center text-xs text-slate-500 font-mono">Loading third-party evidence...</div> : (
          <div className="overflow-x-auto"><table className="w-full text-xs"><thead className="bg-slate-950 text-slate-400 font-mono"><tr><th className="text-left p-3">Application</th><th className="text-left p-3">Recipient</th><th className="text-left p-3">Observed information</th><th className="text-right p-3">Occurrences</th><th className="text-left p-3">Review level</th><th className="p-3"></th></tr></thead><tbody className="divide-y divide-slate-800/70">
            {filtered.map(flow => <tr key={`${flow.appId}:${flow.domain}`} className="align-top hover:bg-slate-800/30"><td className="p-3 font-semibold text-slate-200">{flow.appName}</td><td className="p-3"><div className="text-slate-200">{flow.provider}</div><div className="text-[10px] text-slate-500">{flow.service}</div><div className="text-[10px] text-cyan-400 font-mono break-all mt-1">{flow.domain}</div></td><td className="p-3"><div className="flex flex-wrap gap-1.5">{flow.artifactTypes.map(item => { const status = STATUS_CONFIG[item.policyStatus]; return <span key={item.type} className="px-2 py-1 rounded border border-slate-700 bg-slate-950 text-slate-300"><span>{item.type} <strong className="text-cyan-300">{item.occurrences}</strong></span><span className="block text-[9px] text-slate-500 mt-0.5">{status?.label || 'TECHNICAL / NOT COMPARABLE'}</span></span>; })}</div></td><td className="p-3 text-right font-mono text-slate-200">{flow.occurrences.toLocaleString()}</td><td className="p-3"><span className={`px-2 py-1 rounded border font-mono text-[10px] ${RISK_STYLES[flow.riskLevel]}`}>{flow.riskLevel}</span></td><td className="p-3"><button onClick={() => onSelectApp(flow.appName)} className="text-cyan-400 hover:text-cyan-300"><ArrowUpRight className="w-4 h-4" /></button></td></tr>)}
          </tbody></table></div>
        )}
      </div>
    </div>
  );
}
