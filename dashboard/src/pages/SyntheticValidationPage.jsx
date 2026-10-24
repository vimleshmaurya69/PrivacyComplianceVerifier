import React, { useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  Beaker,
  CheckCircle2,
  Database,
  FileCheck2,
  FlaskConical,
  ShieldCheck
} from 'lucide-react';
import {
  fetchSyntheticAppDetail,
  getManifest,
  RESULT_CONFIG,
  STATUS_CONFIG
} from '../api/dataLoader';

const FALLBACK_RESULT = {
  label: 'CANNOT DETERMINE',
  color: 'bg-slate-500/15 text-slate-300 border-slate-500/40'
};

function FlowStep({ number, title, subtitle, active, onClick, icon: Icon }) {
  return (
    <button
      onClick={onClick}
      className={`text-left rounded-xl border p-4 transition w-full ${
        active
          ? 'border-cyan-700 bg-cyan-950/30'
          : 'border-slate-800 bg-slate-900/70 hover:border-slate-700'
      }`}
    >
      <div className="flex items-center gap-3">
        <div className={`w-8 h-8 rounded-lg flex items-center justify-center border ${
          active
            ? 'border-cyan-700 bg-cyan-950 text-cyan-400'
            : 'border-slate-700 bg-slate-950 text-slate-400'
        }`}>
          <Icon className="w-4 h-4" />
        </div>
        <div>
          <div className="text-[10px] uppercase tracking-widest font-mono text-slate-500">
            Step {number}
          </div>
          <div className="text-sm font-semibold text-slate-100">{title}</div>
          <div className="text-[11px] text-slate-400 mt-0.5">{subtitle}</div>
        </div>
      </div>
    </button>
  );
}

function CaseCard({ detail }) {
  const report = detail.simpleReport;
  const resultConfig = RESULT_CONFIG[report.result] || FALLBACK_RESULT;
  const expectedMatches = report.result === detail.expected_result;
  const observed = report.traffic_transmits || [];
  const comparisons = report.information_type_results || [];
  const risks = report.risk_signals || [];

  return (
    <article className="rounded-xl border border-slate-800 bg-slate-900/80 overflow-hidden">
      <div className="p-5 border-b border-slate-800 flex flex-col lg:flex-row lg:items-start lg:justify-between gap-3">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <FlaskConical className="w-4 h-4 text-cyan-400" />
            <span className="text-[10px] uppercase tracking-widest font-mono text-cyan-400">
              {detail.scenario}
            </span>
          </div>
          <h3 className="text-base font-bold text-slate-100">{detail.app_name}</h3>
          <p className="text-xs text-slate-400 mt-1 max-w-3xl">{detail.expected_explanation}</p>
        </div>
        <div className="flex flex-col items-start lg:items-end gap-1">
          <span className={`px-2.5 py-1 rounded border text-[11px] font-mono font-bold ${resultConfig.color}`}>
            {resultConfig.label}
          </span>
          <span className={`text-[10px] font-mono flex items-center gap-1 ${
            expectedMatches ? 'text-emerald-400' : 'text-rose-400'
          }`}>
            {expectedMatches ? <CheckCircle2 className="w-3 h-3" /> : <AlertTriangle className="w-3 h-3" />}
            {expectedMatches ? 'Expected result reproduced' : 'Result differs from fixture expectation'}
          </span>
        </div>
      </div>

      <div className="p-5 space-y-4">
        <div className="grid grid-cols-3 gap-3">
          <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
            <div className="text-[10px] text-slate-500 uppercase tracking-wide">Requests</div>
            <div className="text-lg font-mono font-bold text-slate-200">{detail.total_requests}</div>
          </div>
          <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
            <div className="text-[10px] text-slate-500 uppercase tracking-wide">Findings</div>
            <div className="text-lg font-mono font-bold text-indigo-300">{detail.sensitive_occurrences}</div>
          </div>
          <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
            <div className="text-[10px] text-slate-500 uppercase tracking-wide">Artifacts</div>
            <div className="text-lg font-mono font-bold text-cyan-400">{detail.unique_artifacts}</div>
          </div>
        </div>

        {comparisons.length > 0 ? (
          <div className="space-y-2">
            <div className="text-[10px] uppercase tracking-wider text-slate-500 font-mono">Information comparison</div>
            <div className="flex flex-wrap gap-2">
              {comparisons.map(item => {
                const status = STATUS_CONFIG[item.status] || {
                  label: item.status,
                  color: 'bg-slate-800 text-slate-300 border-slate-700'
                };
                return (
                  <span key={`${item.artifact_type}-${item.status}`} className={`px-2 py-1 rounded border text-[11px] font-mono ${status.color}`}>
                    {item.artifact_type}: {status.label}
                  </span>
                );
              })}
            </div>
          </div>
        ) : (
          <div className="text-xs text-slate-500 border border-dashed border-slate-800 rounded-lg p-3">
            No comparable outbound information was present in this capture.
          </div>
        )}

        {observed.length > 0 && (
          <div className="text-xs text-slate-400">
            <span className="text-slate-500">Observed:</span>{' '}
            {observed.map(item => `${item.artifact_type} (${item.locations?.join(', ') || 'unknown location'})`).join('; ')}
          </div>
        )}

        {risks.length > 0 && (
          <div className="rounded-lg border border-amber-800/60 bg-amber-950/20 p-3 flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-400 mt-0.5 shrink-0" />
            <div>
              <div className="text-xs font-semibold text-amber-300">Separate risk signal</div>
              <div className="text-[11px] text-slate-300 mt-0.5">
                {risks.map(risk => `${risk.title} (${risk.evidence_count} evidence item${risk.evidence_count === 1 ? '' : 's'})`).join('; ')}
              </div>
            </div>
          </div>
        )}
      </div>
    </article>
  );
}

export function SyntheticValidationPage({ onNavigate }) {
  const manifest = getManifest();
  const syntheticApps = manifest.synthetic_apps || [];
  const [details, setDetails] = useState([]);
  const [loadError, setLoadError] = useState(null);

  useEffect(() => {
    let mounted = true;
    Promise.all(syntheticApps.map(item => fetchSyntheticAppDetail(item.id)))
      .then(items => {
        if (mounted) setDetails(items.filter(Boolean));
      })
      .catch(error => {
        if (mounted) setLoadError(error.message || 'Unable to load controlled validation cases');
      });
    return () => { mounted = false; };
  }, []);

  const reproduced = useMemo(
    () => details.filter(item => item.simpleReport.result === item.expected_result).length,
    [details]
  );

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <FlowStep
          number="1"
          title="Controlled Validation"
          subtitle="Known synthetic inputs and expected outcomes"
          active
          icon={FlaskConical}
          onClick={() => onNavigate('validation')}
        />
        <FlowStep
          number="2"
          title="External Public Datasets"
          subtitle="Cross-dataset detector evaluation"
          icon={Database}
          onClick={() => onNavigate('external')}
        />
        <FlowStep
          number="3"
          title="Original 30-App Dataset"
          subtitle="Captured application traffic and policies"
          icon={ShieldCheck}
          onClick={() => onNavigate('apps')}
        />
      </div>

      <section className="rounded-xl border border-cyan-900/50 bg-slate-900/80 p-5">
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <Beaker className="w-5 h-5 text-cyan-400" />
              <h1 className="text-base font-bold text-slate-100">Controlled Framework Validation</h1>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-cyan-800 bg-cyan-950 text-cyan-400">
                SYNTHETIC — NOT EMPIRICAL
              </span>
            </div>
            <p className="text-xs text-slate-300 mt-2 max-w-4xl leading-relaxed">
              These fixtures use deliberately constructed HAR traffic and policies to verify that each framework decision can be reproduced. They are excluded from the 30-app aggregate and must not be presented as observations about real applications.
            </p>
          </div>
          <div className="shrink-0 text-right">
            <div className="text-2xl font-mono font-bold text-emerald-400">{reproduced}/{syntheticApps.length}</div>
            <div className="text-[10px] uppercase tracking-wider text-slate-500">Expected outcomes reproduced</div>
          </div>
        </div>
      </section>

      {loadError ? (
        <div className="rounded-xl border border-rose-900 bg-rose-950/20 p-5 text-sm text-rose-300">
          {loadError}
        </div>
      ) : details.length === 0 ? (
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-10 text-center text-xs font-mono text-slate-500">
          Loading controlled validation outputs...
        </div>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          {details.map(detail => <CaseCard key={detail.id} detail={detail} />)}
        </div>
      )}

      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4 flex items-center justify-between gap-3">
        <div className="flex items-center gap-2 text-xs text-slate-300">
          <FileCheck2 className="w-4 h-4 text-indigo-400" />
          Next, demonstrate generalization using public datasets before opening the original 30-app results.
        </div>
        <button
          onClick={() => onNavigate('external')}
          className="px-3 py-1.5 rounded-lg border border-cyan-800 bg-cyan-950 text-cyan-300 text-xs font-semibold flex items-center gap-1.5 hover:bg-cyan-900/70 transition"
        >
          Continue to External Data <ArrowRight className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  );
}
