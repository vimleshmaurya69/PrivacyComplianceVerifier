import React, { useState, useEffect, useMemo } from 'react';
import { fetchAppDetail, getManifest } from '../api/dataLoader';
import { Search, Filter, Database, Shield, Globe } from 'lucide-react';
import { RiskBadge } from '../components/RiskBadge';

export function EvidenceExplorer({ selectedApp, onSelectApp }) {
  const manifest = getManifest();
  const [currentApp, setCurrentApp] = useState(selectedApp || 'Truecaller');
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  // Filters
  const [searchTerm, setSearchTerm] = useState('');
  const [catFilter, setCatFilter] = useState('ALL');
  const [locFilter, setLocFilter] = useState('ALL');

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

  // Aggregate evidence findings from inventory and artifacts
  const evidenceList = useMemo(() => {
    if (!data?.artifacts) return [];
    return data.artifacts.map((art, idx) => ({
      id: idx,
      artifact: art.type,
      category: art.privacy_category,
      occurrences: art.occurrences || 1,
      domains: art.domains || [],
      sources: art.sources || [],
      directions: art.directions || ['outbound'],
      keys: art.keys || [],
      trafficTypes: art.traffic_types || ['Application'],
      valueRedacted: art.value_redacted || 'Redacted'
    }));
  }, [data]);

  // Unique categories & locations for filter dropdowns
  const categories = useMemo(() => {
    return Array.from(new Set(evidenceList.map(e => e.category))).sort();
  }, [evidenceList]);

  const locations = useMemo(() => {
    return Array.from(new Set(evidenceList.flatMap(e => e.sources))).sort();
  }, [evidenceList]);

  const filteredEvidence = useMemo(() => {
    return evidenceList.filter(item => {
      const matchSearch =
        item.artifact.toLowerCase().includes(searchTerm.toLowerCase()) ||
        item.keys.some(k => k.toLowerCase().includes(searchTerm.toLowerCase())) ||
        item.domains.some(d => d.toLowerCase().includes(searchTerm.toLowerCase()));
      const matchCat = catFilter === 'ALL' || item.category === catFilter;
      const matchLoc = locFilter === 'ALL' || item.sources.includes(locFilter);
      return matchSearch && matchCat && matchLoc;
    });
  }, [evidenceList, searchTerm, catFilter, locFilter]);

  return (
    <div className="space-y-6">
      {/* Header and Controls */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <Database className="w-5 h-5 text-cyan-400" />
              Traffic Evidence Metadata Explorer
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Inspect granular sensitive data findings extracted across headers, query parameters, request bodies, and gRPC streams.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs text-slate-400 font-mono">App:</span>
            <select
              value={currentApp}
              onChange={e => {
                setCurrentApp(e.target.value);
                if (onSelectApp) onSelectApp(e.target.value);
              }}
              className="bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-medium"
            >
              {manifest.primary_apps.map(a => (
                <option key={a.id} value={a.id}>{a.app_name}</option>
              ))}
            </select>
          </div>
        </div>

        {/* Filter Toolbar */}
        <div className="mt-4 pt-4 border-t border-slate-800/80 flex flex-wrap items-center gap-3">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search key, artifact, or domain..."
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
              className="pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-700 rounded-lg text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 w-64"
            />
          </div>

          <select
            value={catFilter}
            onChange={e => setCatFilter(e.target.value)}
            className="bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Categories</option>
            {categories.map((c, i) => (
              <option key={i} value={c}>{c}</option>
            ))}
          </select>

          <select
            value={locFilter}
            onChange={e => setLocFilter(e.target.value)}
            className="bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Request Locations</option>
            {locations.map((loc, i) => (
              <option key={i} value={loc}>{loc}</option>
            ))}
          </select>

          <span className="text-[11px] text-slate-500 font-mono ml-auto">
            Showing {filteredEvidence.length} of {evidenceList.length} artifact records
          </span>
        </div>
      </div>

      {/* Evidence Table */}
      {loading ? (
        <div className="p-12 text-center text-slate-500 font-mono text-xs">
          Loading evidence inventory for {currentApp}...
        </div>
      ) : filteredEvidence.length === 0 ? (
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-8 text-center text-slate-400 text-xs">
          No matching evidence findings found for the selected filters.
        </div>
      ) : (
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-slate-950 border-b border-slate-800 text-slate-400 font-mono text-[11px]">
                  <th className="py-3 px-4 font-semibold">Artifact Type</th>
                  <th className="py-3 px-3 font-semibold">Privacy Category</th>
                  <th className="py-3 px-3 font-semibold">Location (Source)</th>
                  <th className="py-3 px-3 font-semibold">Parameter / Key</th>
                  <th className="py-3 px-3 font-semibold text-right">Occurrences</th>
                  <th className="py-3 px-3 font-semibold">Direction</th>
                  <th className="py-3 px-4 font-semibold">Destination Domains</th>
                  <th className="py-3 px-3 font-semibold">Value Preview</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-sans">
                {filteredEvidence.map((row, idx) => (
                  <tr key={idx} className="hover:bg-slate-800/30 transition">
                    <td className="py-3 px-4 font-mono font-bold text-slate-200">
                      {row.artifact}
                    </td>
                    <td className="py-3 px-3 text-slate-400">
                      {row.category}
                    </td>
                    <td className="py-3 px-3 font-mono text-slate-300">
                      {row.sources.join(', ') || 'Header'}
                    </td>
                    <td className="py-3 px-3 font-mono text-cyan-400 truncate max-w-xs">
                      {row.keys.join(', ') || 'N/A'}
                    </td>
                    <td className="py-3 px-3 text-right font-mono text-indigo-300 font-semibold">
                      {row.occurrences.toLocaleString()}
                    </td>
                    <td className="py-3 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono ${
                        row.directions.includes('outbound')
                          ? 'bg-rose-950/60 text-rose-300 border border-rose-800/60'
                          : 'bg-sky-950/60 text-sky-300 border border-sky-800/60'
                      }`}>
                        {row.directions.join(', ')}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-400 text-[11px] truncate max-w-xs">
                      {row.domains.join(', ')}
                    </td>
                    <td className="py-3 px-3">
                      <span className="font-mono text-[10px] text-slate-400 bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                        {row.valueRedacted}
                      </span>
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
