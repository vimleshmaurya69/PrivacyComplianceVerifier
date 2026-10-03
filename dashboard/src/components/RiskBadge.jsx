import React from 'react';
import { AlertTriangle, ShieldAlert } from 'lucide-react';

export function RiskBadge({ risk }) {
  if (!risk) return null;

  const isPersonalData = risk.includes('PERSONAL_DATA') || risk.includes('Personal data');
  const isCredential = risk.includes('CREDENTIAL') || risk.includes('Credential');

  const colorClass = isCredential
    ? 'bg-rose-500/15 text-rose-400 border-rose-500/30'
    : isPersonalData
    ? 'bg-amber-500/15 text-amber-400 border-amber-500/30'
    : 'bg-purple-500/15 text-purple-400 border-purple-500/30';

  const shortName = isCredential
    ? 'Credential in URL'
    : isPersonalData
    ? 'Personal Data in URL'
    : risk;

  return (
    <span className={`inline-flex items-center gap-1 font-mono text-[10px] font-medium px-2 py-0.5 rounded border ${colorClass}`}>
      <AlertTriangle className="w-3 h-3" />
      {shortName}
    </span>
  );
}
