import React from 'react';
import { ShieldCheck, BookOpen, Layers, CheckCircle2, AlertTriangle, FileCode } from 'lucide-react';
import { STATUS_CONFIG, RESULT_CONFIG } from '../api/dataLoader';

export function AboutPage() {
  const simpleStatuses = [
    'DISCLOSED',
    'NOT_DISCLOSED_IN_REVIEWED_POLICY',
    'POLICY_REVIEW_INCOMPLETE',
    'DECLARED_NOT_OBSERVED_IN_CAPTURE',
    'NOT_ASSESSABLE_FROM_HAR'
  ];
  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      {/* Title */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6 space-y-3">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-cyan-950 border border-cyan-800 flex items-center justify-center text-cyan-400">
            <ShieldCheck className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-slate-100">About PrivacyComplianceVerifier</h1>
            <p className="text-xs text-slate-400 font-mono">Academic Research & Demonstration Framework</p>
          </div>
        </div>
        <p className="text-xs text-slate-300 leading-relaxed pt-2 border-t border-slate-800">
          PrivacyComplianceVerifier is a research platform that investigates the <em>say-do gap</em> in mobile and consumer web applications. It analyzes empirical network traffic (HTTP/S and gRPC), extracts sensitive-data evidence using pattern and structure detectors, and compares observed practices with explicit statements represented from the application's published privacy policy.
        </p>
      </div>

      {/* Evaluation States Reference */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6 space-y-4">
        <h2 className="text-sm font-bold text-slate-200 flex items-center gap-2">
          <BookOpen className="w-4 h-4 text-cyan-400" />
          Capture-Scoped Result Semantics
        </h2>
        <p className="text-xs text-slate-400">
          Each distinct outbound information type is checked against explicit statements in the reviewed policy representation. The project-facing result uses five clear states:
        </p>

        <div className="space-y-3">
          {simpleStatuses.map(status => {
            const conf = STATUS_CONFIG[status];
            return (
            <div key={status} className="p-3 bg-slate-950 rounded-lg border border-slate-800/80 space-y-1">
              <div className="flex items-center gap-2">
                <span className={`px-2 py-0.5 rounded text-[11px] font-mono font-semibold border ${conf.color}`}>
                  {conf.label}
                </span>
              </div>
              <p className="text-xs text-slate-300 mt-1">{conf.description}</p>
            </div>
          );})}
        </div>
        <p className="text-[11px] text-amber-300 font-mono">
          COMPLIANT WITHIN CAPTURE SCOPE is a project-defined result, not a legal compliance judgment. The exported compliance determination remains NOT DETERMINED.
        </p>
        <p className="text-[11px] text-slate-500">
          REVIEWED COMPLETE means the repository's structured policy summary has a source, review date, and recorded practices; it does not claim that the publisher's legal policy is complete in every respect.
        </p>
      </div>

      {/* Attribution & Limitations */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6 space-y-3">
        <h2 className="text-sm font-bold text-slate-200 flex items-center gap-2">
          <Layers className="w-4 h-4 text-indigo-400" />
          Methodology & Attributability Ledger
        </h2>
        <p className="text-xs text-slate-300 leading-relaxed">
          Network evidence is separated by observed traffic ownership. This traffic classification does not automatically establish the policy-level recipient scope.
        </p>
        <ul className="text-xs text-slate-400 space-y-2 list-disc list-inside">
          <li><strong>Comparable Outbound:</strong> Outbound findings in traffic classified as Application or Third Party by the framework.</li>
          <li><strong>Attributable Inbound:</strong> Sensitive data received in responses (e.g. user profiles, server data).</li>
          <li><strong>Non-Attributable / System:</strong> Background Android OS telemetry (e.g. checkin, gstatic) is separated from the application policy comparison.</li>
        </ul>
      </div>
    </div>
  );
}
