import React from 'react';
import { ArrowRight, Radio, Search, FileText, Scale, AlertCircle } from 'lucide-react';

export function ResearchPipeline() {
  const steps = [
    {
      icon: Radio,
      title: 'Observed Traffic',
      subtitle: 'HAR Network Captures',
      desc: 'Extracted HTTP/S & gRPC requests'
    },
    {
      icon: Search,
      title: 'Sensitive Detection',
      subtitle: 'Multimodal Detector',
      desc: 'Keys, values, entropy, regex, protobuf'
    },
    {
      icon: FileText,
      title: 'Policy Evidence',
      subtitle: 'Declared Artifacts',
      desc: 'Structured policy disclosures'
    },
    {
      icon: Scale,
      title: 'Policy vs Traffic',
      subtitle: 'Information-Type Comparator',
      desc: 'Explicit type disclosure matching'
    },
    {
      icon: AlertCircle,
      title: 'Review Signals',
      subtitle: 'Capture-Scoped Result',
      desc: 'Disclosures, gaps, separate URL risks'
    }
  ];

  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 mb-8 backdrop-blur-sm">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-400">Research Hypothesis & Evaluation Flow</h3>
          <p className="text-xs text-slate-500 mt-0.5">Empirical verification of observed runtime data practices against explicit privacy policy statements.</p>
        </div>
        <span className="text-[11px] font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-800/60 px-2.5 py-1 rounded">
          Attributed Policy Verification
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-5 gap-3 relative">
        {steps.map((s, idx) => {
          const Icon = s.icon;
          return (
            <div key={idx} className="relative flex items-center">
              <div className="w-full bg-slate-950/70 border border-slate-800/80 rounded-lg p-3 hover:border-slate-700 transition">
                <div className="flex items-center gap-2 mb-1.5">
                  <div className="w-6 h-6 rounded bg-slate-800/80 flex items-center justify-center text-cyan-400">
                    <Icon className="w-3.5 h-3.5" />
                  </div>
                  <span className="text-xs font-semibold text-slate-200">{s.title}</span>
                </div>
                <div className="text-[11px] font-mono text-cyan-400/90">{s.subtitle}</div>
                <div className="text-[11px] text-slate-400 mt-1 leading-snug">{s.desc}</div>
              </div>
              {idx < steps.length - 1 && (
                <div className="hidden md:flex absolute -right-2 z-10 text-slate-600">
                  <ArrowRight className="w-3.5 h-3.5" />
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
