import React from 'react';
import { AlertTriangle, ShieldAlert } from 'lucide-react';

export function RiskBadge({ risk }) {
  if (!risk) return null;

  const isPersonalData = risk.includes('PERSONAL_DATA') || risk.includes('Personal data');
  const isCredential = risk.includes('CREDENTIAL') || risk.includes('Credential');
  const isInstalledApps = risk.includes('INSTALLED_APP') || risk.includes('Installed application');
  const isThirdPartySearch = risk.includes('SEARCH_ACTIVITY_SHARED') || risk.includes('Search activity shared');
  const isThirdPartyLocation = risk.includes('PRECISE_LOCATION_SHARED') || risk.includes('Precise location shared');
  const isThirdPartyPersonal = risk.includes('PERSONAL_DATA_SHARED') || risk.includes('Personal data shared');
  const isThirdPartyIdentifier = risk.includes('PERSISTENT_IDENTIFIER_SHARED') || risk.includes('Persistent identifier shared');
  const isSearch = risk.includes('SEARCH_ACTIVITY') || risk.includes('Search activity');

  const colorClass = isCredential
    ? 'bg-rose-500/15 text-rose-400 border-rose-500/30'
    : isThirdPartySearch || isThirdPartyLocation
    ? 'bg-rose-500/15 text-rose-400 border-rose-500/30'
    : isInstalledApps
    ? 'bg-purple-500/15 text-purple-400 border-purple-500/30'
    : isSearch
    ? 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30'
    : isThirdPartyPersonal || isThirdPartyIdentifier || isPersonalData
    ? 'bg-amber-500/15 text-amber-400 border-amber-500/30'
    : 'bg-purple-500/15 text-purple-400 border-purple-500/30';

  const shortName = isCredential
    ? 'Credential in URL'
    : isThirdPartySearch
    ? 'Search Shared with Third Party'
    : isThirdPartyLocation
    ? 'Location Shared with Third Party'
    : isThirdPartyPersonal
    ? 'Personal Data Shared with Third Party'
    : isThirdPartyIdentifier
    ? 'Identifier Shared with Third Party'
    : isInstalledApps
    ? 'Installed Apps Transmitted'
    : isSearch
    ? 'Search Activity in URL'
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
