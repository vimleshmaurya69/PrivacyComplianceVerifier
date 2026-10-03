import manifest from '../data/app_manifest.json';
import { applyDashboardPresentationToRow, buildDashboardPresentation } from './presentationRules';

// Status color and label definitions matching the framework
export const STATUS_CONFIG = {
  'DISCLOSED': {
    label: 'IN POLICY',
    color: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
    badge: 'bg-emerald-500',
    description: 'The reviewed policy explicitly names this information type.'
  },
  'NOT_DISCLOSED_IN_REVIEWED_POLICY': {
    label: 'NOT IN POLICY',
    color: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
    badge: 'bg-rose-500',
    description: 'The observed information type was absent from the reviewed policy representation.'
  },
  'POLICY_REVIEW_INCOMPLETE': {
    label: 'POLICY CHECK INCOMPLETE',
    color: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
    badge: 'bg-amber-500',
    description: 'The local policy representation is incomplete, so absence is not treated as non-disclosure.'
  },
  'DECLARED_NOT_OBSERVED_IN_CAPTURE': {
    label: 'IN POLICY — NOT OBSERVED',
    color: 'bg-slate-500/10 text-slate-400 border-slate-500/30',
    badge: 'bg-slate-400',
    description: 'The policy names this type, but it was not observed in this capture.'
  },
  'NOT_ASSESSABLE_FROM_HAR': {
    label: 'NOT ASSESSABLE FROM HAR',
    color: 'bg-purple-500/10 text-purple-400 border-purple-500/30',
    badge: 'bg-purple-400',
    description: 'HAR traffic cannot reliably assess this declared type.'
  },
  'TECHNICAL_AUTHENTICATION_ARTIFACT': {
    label: 'TECHNICAL AUTHENTICATION EVIDENCE',
    color: 'bg-sky-500/10 text-sky-400 border-sky-500/30',
    badge: 'bg-sky-400',
    description: 'Authorization tokens and session cookies remain technical evidence but do not create a privacy-policy gap on the dashboard.'
  },
  'PRACTICE DISCLOSED': {
    label: 'PRACTICE DISCLOSED',
    color: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
    badge: 'bg-emerald-500',
    description: 'Matches observed information type, action, and verified recipient.'
  },
  'INFORMATION TYPE DISCLOSED': {
    label: 'INFORMATION TYPE DISCLOSED',
    color: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
    badge: 'bg-blue-500',
    description: 'Policy explicitly identifies this information type.'
  },
  'POTENTIAL NON-DISCLOSURE': {
    label: 'POTENTIAL NON-DISCLOSURE',
    color: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
    badge: 'bg-rose-500',
    description: 'No matching policy practice found within complete comparison scope.'
  },
  'POLICY DETAIL INSUFFICIENT': {
    label: 'POLICY DETAIL INSUFFICIENT',
    color: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
    badge: 'bg-amber-500',
    description: 'Policy evidence is not specific enough for this observed type.'
  },
  'DECLARED - NOT OBSERVED IN CAPTURE': {
    label: 'DECLARED - NOT OBSERVED',
    color: 'bg-slate-500/10 text-slate-400 border-slate-500/30',
    badge: 'bg-slate-400',
    description: 'Policy declares this type, but not observed in capture.'
  },
  'NOT ASSESSABLE FROM HAR': {
    label: 'NOT ASSESSABLE FROM HAR',
    color: 'bg-purple-500/10 text-purple-400 border-purple-500/30',
    badge: 'bg-purple-400',
    description: 'Declared practice cannot be evaluated from network traffic alone.'
  }
};

const STATUS_ALIASES = {
  'INFORMATION DISCLOSED': 'INFORMATION TYPE DISCLOSED',
  'INSUFFICIENT POLICY DETAIL': 'POLICY DETAIL INSUFFICIENT',
  'NOT OBSERVED IN CAPTURE': 'DECLARED - NOT OBSERVED IN CAPTURE'
};

export function normalizeStatus(status) {
  return STATUS_ALIASES[status] || status;
}

export const RESULT_CONFIG = {
  'COMPLIANT_WITHIN_CAPTURE_SCOPE': {
    label: 'ALL COMPARABLE TYPES DISCLOSED',
    color: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/40',
    indicator: 'emerald'
  },
  'POTENTIALLY_NON_COMPLIANT': {
    label: 'POTENTIALLY NON-COMPLIANT',
    color: 'bg-rose-500/15 text-rose-400 border-rose-500/40',
    indicator: 'rose'
  },
  'CANNOT_DETERMINE': {
    label: 'POLICY CHECK INCOMPLETE',
    color: 'bg-amber-500/15 text-amber-400 border-amber-500/40',
    indicator: 'amber'
  },
  'POLICY-TRAFFIC REVIEW REQUIRED': {
    label: 'POLICY-TRAFFIC REVIEW REQUIRED',
    color: 'bg-amber-500/15 text-amber-400 border-amber-500/40',
    indicator: 'amber'
  },
  'POLICY DETAIL INSUFFICIENT': {
    label: 'POLICY DETAIL INSUFFICIENT',
    color: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/40',
    indicator: 'yellow'
  },
  'POLICY-TRAFFIC MATCHES FOUND': {
    label: 'POLICY-TRAFFIC MATCHES FOUND',
    color: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/40',
    indicator: 'emerald'
  },
  'TRAFFIC OBSERVED - POLICY COMPARISON LIMITED': {
    label: 'TRAFFIC OBSERVED - POLICY COMPARISON LIMITED',
    color: 'bg-sky-500/15 text-sky-400 border-sky-500/40',
    indicator: 'sky'
  },
  'INSUFFICIENT EVIDENCE': {
    label: 'INSUFFICIENT EVIDENCE',
    color: 'bg-slate-500/15 text-slate-400 border-slate-500/40',
    indicator: 'slate'
  }
};

export function getManifest() {
  return manifest;
}

export function findAppInManifest(appIdentifier) {
  if (!appIdentifier) return null;
  const lower = appIdentifier.toLowerCase();
  return manifest.primary_apps.find(
    a => a.id.toLowerCase() === lower || a.app_name.toLowerCase() === lower
  ) || null;
}

export async function fetchMasterResults() {
  const res = await fetch('/data/analysis/master_results.json');
  if (!res.ok) {
    throw new Error(`Unable to load master results (HTTP ${res.status})`);
  }

  const data = await res.json();
  if (!Array.isArray(data)) {
    throw new Error('Master results must be a JSON array');
  }

  // The manifest defines the primary empirical dataset. Synthetic fixtures may
  // exist in master_results.json for regression testing, but must not affect
  // presentation totals.
  const primaryNames = new Set(
    manifest.primary_apps.flatMap(app => [app.id, app.app_name].map(value => value.toLowerCase()))
  );
  const primaryResults = data.filter(row =>
    typeof row?.application === 'string' && primaryNames.has(row.application.toLowerCase())
  );

  if (primaryResults.length !== manifest.primary_apps.length) {
    throw new Error(
      `Primary result set is incomplete: expected ${manifest.primary_apps.length}, loaded ${primaryResults.length}`
    );
  }

  return Promise.all(primaryResults.map(async row => {
    const appInfo = findAppInManifest(row.application);
    if (!appInfo) return row;
    try {
      const response = await fetch(`/data/output/${appInfo.id}/compliance_results.json`);
      if (!response.ok) return row;
      const compliance = await response.json();
      return applyDashboardPresentationToRow(row, compliance?.simple_report);
    } catch {
      return row;
    }
  }));
}

export async function fetchAppDetail(appId) {
  // Find in manifest to ensure correct casing for folder
  const appInfo = findAppInManifest(appId);
  const folder = appInfo ? appInfo.id : appId;

  const [statsRes, compRes, artRes, invRes] = await Promise.allSettled([
    fetch(`/data/output/${folder}/statistics.json`).then(r => r.ok ? r.json() : null),
    fetch(`/data/output/${folder}/compliance_results.json`).then(r => r.ok ? r.json() : null),
    fetch(`/data/output/${folder}/sensitive_artifacts.json`).then(r => r.ok ? r.json() : null),
    fetch(`/data/output/${folder}/privacy_inventory.json`).then(r => r.ok ? r.json() : null)
  ]);

  const statistics = statsRes.status === 'fulfilled' ? statsRes.value : null;
  const compliance = compRes.status === 'fulfilled' ? compRes.value : null;
  const artifacts = artRes.status === 'fulfilled' ? artRes.value : [];
  const inventory = invRes.status === 'fulfilled' ? invRes.value : {};

  // Standardize simple report if not baked into compliance_results
  const rawSimpleReport = compliance?.simple_report || deriveSimpleReport(compliance, inventory);
  const simpleReport = buildDashboardPresentation(rawSimpleReport);

  return {
    appId: folder,
    appName: statistics?.app_name || appInfo?.app_name || folder,
    statistics: statistics || {},
    compliance: compliance || {},
    artifacts: Array.isArray(artifacts) ? artifacts : [],
    inventory: inventory || {},
    simpleReport: simpleReport
  };
}

// Fallback logic matching aggregate_results.py _simple_presentation
function deriveSimpleReport(compliance, inventory) {
  if (!compliance) {
    return {
      policy_declares: { categories: [], information_types: [] },
      traffic_transmits: [],
      comparison: [],
      risk_signals: [],
      result: 'INSUFFICIENT EVIDENCE'
    };
  }

  const results = compliance.results || [];
  const declaredCategories = compliance.declared_categories || [];
  const declaredPractices = compliance.policy_practices || [];

  const declaredInfoTypes = Array.from(new Set(
    declaredPractices.flatMap(p => p.artifact_types || [])
  )).sort();

  // Transmissions from inventory
  const transmissions = [];
  const attributableTypes = new Set(['Application', 'Third Party']);
  const grouped = new Map();

  for (const [trafficType, section] of Object.entries(inventory || {})) {
    if (!section || !Array.isArray(section.evidence)) continue;
    for (const item of section.evidence) {
      if (item.direction !== 'outbound' || !attributableTypes.has(trafficType)) continue;
      const key = `${item.privacy_category || 'Unknown'}::${item.type || 'Unknown'}`;
      if (!grouped.has(key)) {
        grouped.set(key, {
          privacy_category: item.privacy_category || 'Unknown',
          artifact_type: item.type || 'Unknown',
          occurrences: 0,
          destinations: new Set(),
          locations: new Set(),
          traffic_types: new Set()
        });
      }
      const g = grouped.get(key);
      g.occurrences++;
      if (item.domain) g.destinations.add(item.domain);
      if (item.source) g.locations.add(item.source);
      g.traffic_types.add(trafficType);
    }
  }

  for (const g of grouped.values()) {
    transmissions.push({
      privacy_category: g.privacy_category,
      artifact_type: g.artifact_type,
      occurrences: g.occurrences,
      destinations: Array.from(g.destinations).sort(),
      locations: Array.from(g.locations).sort(),
      traffic_types: Array.from(g.traffic_types).sort()
    });
  }

  // Comparisons
  const statusMap = {
    'PRACTICE DISCLOSED': 'PRACTICE DISCLOSED',
    'INFORMATION DISCLOSED': 'INFORMATION TYPE DISCLOSED',
    'INFORMATION TYPE DISCLOSED': 'INFORMATION TYPE DISCLOSED',
    'POTENTIAL NON-DISCLOSURE': 'POTENTIAL NON-DISCLOSURE',
    'INSUFFICIENT POLICY DETAIL': 'POLICY DETAIL INSUFFICIENT',
    'NOT OBSERVED IN CAPTURE': 'DECLARED - NOT OBSERVED IN CAPTURE',
    'NOT ASSESSABLE FROM HAR': 'NOT ASSESSABLE FROM HAR'
  };

  const compGroups = {};
  for (const r of results) {
    const canonical = statusMap[r.status];
    if (!canonical) continue;
    if (!compGroups[canonical]) {
      compGroups[canonical] = {
        result: canonical,
        information_types: new Set(),
        decision_record_count: 0,
        meaning: STATUS_CONFIG[canonical]?.description || ''
      };
    }
    compGroups[canonical].decision_record_count++;
    if (r.artifact_type) compGroups[canonical].information_types.add(r.artifact_type);
    for (const it of (r.artifact_types || [])) {
      if (it) compGroups[canonical].information_types.add(it);
    }
  }

  const comparison = Object.values(compGroups).map(g => ({
    result: g.result,
    information_types: Array.from(g.information_types).sort(),
    information_type_count: g.information_types.size,
    decision_record_count: g.decision_record_count,
    meaning: g.meaning
  }));

  // Risk signals
  const risks = (compliance.practice_risks || []).map(r => ({
    type: r.type,
    title: r.type === 'CREDENTIAL_IN_URL' ? 'Credential observed in URL' :
           r.type === 'PERSONAL_DATA_IN_URL' ? 'Personal data observed in URL' : (r.type || 'Review signal'),
    severity: r.severity || 'MEDIUM',
    explanation: r.explanation || '',
    evidence_count: (r.evidence || []).length
  }));

  // Overall result
  let result = 'INSUFFICIENT EVIDENCE';
  const hasPotential = comparison.some(c => c.result === 'POTENTIAL NON-DISCLOSURE');
  const hasInsufficient = comparison.some(c => c.result === 'POLICY DETAIL INSUFFICIENT');
  const hasDisclosed = comparison.some(c => c.result === 'PRACTICE DISCLOSED' || c.result === 'INFORMATION TYPE DISCLOSED');

  if (hasPotential || risks.length > 0) {
    result = 'POLICY-TRAFFIC REVIEW REQUIRED';
  } else if (hasInsufficient) {
    result = 'POLICY DETAIL INSUFFICIENT';
  } else if (hasDisclosed) {
    result = 'POLICY-TRAFFIC MATCHES FOUND';
  } else if (transmissions.length > 0) {
    result = 'TRAFFIC OBSERVED - POLICY COMPARISON LIMITED';
  }

  return {
    policy_declares: {
      categories: declaredCategories,
      information_types: declaredInfoTypes
    },
    traffic_transmits: transmissions,
    comparison,
    risk_signals: risks,
    result,
    methodology_note: 'Results compare observed outbound network transmissions with explicit statements in policy evidence.'
  };
}

export async function fetchExternalAppDetail(appId) {
  const extInfo = manifest.external_apps.find(a => a.id === appId);
  if (!extInfo) return null;

  try {
    if (extInfo.dataset === 'OVRseen') {
      const res = await fetch(`${extInfo.output_dir}/summary.json`);
      const summary = res.ok ? await res.json() : {};
      const invRes = await fetch(`${extInfo.output_dir}/privacy_inventory.json`);
      const inventory = invRes.ok ? await invRes.json() : {};
      return {
        ...extInfo,
        summary,
        inventory
      };
    } else {
      const statsRes = await fetch(`${extInfo.output_dir}/statistics.json`);
      const stats = statsRes.ok ? await statsRes.json() : {};
      const artRes = await fetch(`${extInfo.output_dir}/sensitive_artifacts.json`);
      const artifacts = artRes.ok ? await artRes.json() : [];
      const invRes = await fetch(`${extInfo.output_dir}/privacy_inventory.json`);
      const inventory = invRes.ok ? await invRes.json() : {};
      return {
        ...extInfo,
        statistics: stats,
        artifacts,
        inventory
      };
    }
  } catch (err) {
    console.error('Failed to load external app:', err);
    return extInfo;
  }
}
