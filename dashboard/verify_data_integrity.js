import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildDashboardPresentation } from './src/api/presentationRules.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Test 1: Verify the manifest-defined primary dataset against master_results.json
const masterPath = path.resolve(__dirname, '../data/analysis/master_results.json');
const rawMasterData = JSON.parse(fs.readFileSync(masterPath, 'utf8'));
const manifestPath = path.resolve(__dirname, 'src/data/app_manifest.json');
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
const primaryNames = new Set(
  manifest.primary_apps.flatMap(app => [app.id, app.app_name].map(value => value.toLowerCase()))
);
const masterData = rawMasterData.filter(row => primaryNames.has(row.application.toLowerCase()));

if (masterData.length !== manifest.primary_apps.length) {
  throw new Error(`Expected ${manifest.primary_apps.length} primary results, found ${masterData.length}`);
}
if (masterData.some(row => row.application.toLowerCase().includes('dummy test app'))) {
  throw new Error('Synthetic dummy app must not be included in primary dashboard results');
}

for (const app of manifest.primary_apps) {
  const row = masterData.find(item =>
    item.application.toLowerCase() === app.app_name.toLowerCase() ||
    item.application.toLowerCase() === app.id.toLowerCase()
  );
  if (!row) throw new Error(`Missing master result for ${app.app_name}`);
  if (row.total_requests !== app.total_requests) {
    throw new Error(`${app.app_name}: manifest/master request count mismatch`);
  }
  if (row.sensitive_occurrences !== app.sensitive_occurrences) {
    throw new Error(`${app.app_name}: manifest/master sensitive count mismatch`);
  }

  const outputDir = path.resolve(__dirname, '..', 'data', 'output', app.id);
  for (const requiredFile of ['statistics.json', 'compliance_results.json', 'privacy_inventory.json', 'sensitive_artifacts.json']) {
    if (!fs.existsSync(path.join(outputDir, requiredFile))) {
      throw new Error(`${app.app_name}: missing ${requiredFile}`);
    }
  }
}

console.log(`[PASS] Verified all ${masterData.length} manifest-defined primary applications.`);

// Controlled synthetic fixtures are intentionally separate from the empirical
// 30-app aggregate. Each fixture must reproduce its declared expected result.
const syntheticApps = manifest.synthetic_apps || [];
for (const app of syntheticApps) {
  const outputDir = path.resolve(__dirname, '..', 'data', 'output', app.id);
  const stats = JSON.parse(fs.readFileSync(path.join(outputDir, 'statistics.json'), 'utf8'));
  const compliance = JSON.parse(fs.readFileSync(path.join(outputDir, 'compliance_results.json'), 'utf8'));
  const dashboardResult = buildDashboardPresentation(compliance.simple_report);

  if (stats.total_requests !== app.total_requests) {
    throw new Error(`${app.app_name}: synthetic request count mismatch`);
  }
  if (stats.sensitive_data_occurrences !== app.sensitive_occurrences) {
    throw new Error(`${app.app_name}: synthetic sensitive count mismatch`);
  }
  if (stats.unique_sensitive_artifacts !== app.unique_artifacts) {
    throw new Error(`${app.app_name}: synthetic artifact count mismatch`);
  }
  if (dashboardResult.result !== app.expected_result) {
    throw new Error(
      `${app.app_name}: expected ${app.expected_result}, got ${dashboardResult.result}`
    );
  }
}
console.log(`[PASS] Verified ${syntheticApps.length} controlled validation cases.`);

// Test 2: Verify Truecaller
const tc = masterData.find(a => a.application.toLowerCase() === 'truecaller');
if (!tc) throw new Error('Truecaller not found in master_results');
console.log(`[PASS] Truecaller in master: reqs=${tc.total_requests}, sens=${tc.sensitive_occurrences}, result=${tc.result}, risks=${tc.risk_signals}`);

if (tc.total_requests !== 184) throw new Error(`Expected Truecaller requests 184, got ${tc.total_requests}`);
if (tc.sensitive_occurrences !== 220) throw new Error(`Expected Truecaller sensitive 220, got ${tc.sensitive_occurrences}`);
if (!tc.risk_signals.includes('Personal data observed in URL') && !tc.risk_signals.includes('PERSONAL_DATA_IN_URL')) {
  throw new Error(`Expected Truecaller risk signal for personal data in URL`);
}
if (!tc.risk_signals.includes('Search activity observed in URL')) {
  throw new Error('Expected Truecaller search-activity URL risk signal');
}

// Test 3: Verify Truecaller detailed compliance results
const tcCompPath = path.resolve(__dirname, '../data/output/Truecaller/compliance_results.json');
const tcComp = JSON.parse(fs.readFileSync(tcCompPath, 'utf8'));
const tcSimple = tcComp.simple_report;
if (!tcSimple) throw new Error('Truecaller simple_report missing');

console.log('[PASS] Truecaller simple_report verified:');
console.log('   Result:', tcSimple.result);
console.log('   Observed outbound:', tcSimple.traffic_transmits.map(t => t.artifact_type));
console.log('   Comparison:', tcSimple.comparison.map(c => `${c.result}: ${c.information_types.join(', ')}`));
console.log('   Risk signals:', tcSimple.risk_signals.map(r => r.title));

// Check exact expected information-type comparison
const disclosedGroup = tcSimple.comparison.find(c => c.result === 'DISCLOSED');
if (!disclosedGroup || !disclosedGroup.information_types.includes('Phone') || !disclosedGroup.information_types.includes('Email')) {
  throw new Error('Expected explicit Phone and Email disclosure for Truecaller');
}

const notDisclosedGroup = tcSimple.comparison.find(c => c.result === 'NOT_DISCLOSED_IN_REVIEWED_POLICY');
if (!notDisclosedGroup || !notDisclosedGroup.information_types.includes('Authorization Token')) {
  throw new Error('Expected Authorization Token to be absent from reviewed Truecaller policy');
}
if (!notDisclosedGroup.information_types.includes('Search Query')) {
  throw new Error('Expected observed Truecaller Search Query to be absent from the reviewed policy representation');
}
if (tcSimple.result !== 'POTENTIALLY_NON_COMPLIANT') throw new Error(`Unexpected Truecaller result: ${tcSimple.result}`);
if (tcSimple.compliance_determination !== 'NOT DETERMINED') throw new Error('Legal compliance determination must remain NOT DETERMINED');

// Dashboard presentation keeps the raw result intact and excludes the
// technical Authorization Token, while preserving the independent Search
// Query disclosure gap.
const tcDashboard = buildDashboardPresentation(tcSimple);
const tcToken = tcDashboard.information_type_results.find(r => r.artifact_type === 'Authorization Token');
if (tcToken?.status !== 'TECHNICAL_AUTHENTICATION_ARTIFACT') {
  throw new Error('Dashboard must present Authorization Token as technical authentication evidence');
}
if (tcDashboard.result !== 'POTENTIALLY_NON_COMPLIANT') {
  throw new Error(`Unexpected dashboard-only Truecaller result: ${tcDashboard.result}`);
}
if (tcDashboard.raw_framework_result !== 'POTENTIALLY_NON_COMPLIANT') {
  throw new Error('Dashboard presentation must preserve the raw framework result for traceability');
}
console.log('[PASS] Dashboard-only authorization-token interpretation verified.');

const sessionCookieDashboard = buildDashboardPresentation({
  result: 'POTENTIALLY_NON_COMPLIANT',
  information_type_results: [
    {
      artifact_type: 'Email',
      occurrences: 1,
      status: 'DISCLOSED',
      policy_evidence: [{}]
    },
    {
      artifact_type: 'Session Cookie',
      occurrences: 3,
      status: 'NOT_DISCLOSED_IN_REVIEWED_POLICY',
      policy_evidence: []
    }
  ]
});
const sessionCookie = sessionCookieDashboard.information_type_results.find(
  result => result.artifact_type === 'Session Cookie'
);
if (sessionCookie?.status !== 'TECHNICAL_AUTHENTICATION_ARTIFACT') {
  throw new Error('Dashboard must present Session Cookie as technical authentication evidence');
}
if (sessionCookieDashboard.result !== 'COMPLIANT_WITHIN_CAPTURE_SCOPE') {
  throw new Error('Session Cookie must not create a dashboard privacy-policy gap');
}
console.log('[PASS] Dashboard-only session-cookie interpretation verified.');

const broadPolicyDashboard = buildDashboardPresentation({
  result: 'COMPLIANT_WITHIN_CAPTURE_SCOPE',
  information_type_results: [
    {
      artifact_type: 'Latitude',
      occurrences: 2,
      status: 'COVERED_BY_BROAD_POLICY_TERM',
      policy_evidence: [{ privacy_category: 'Location' }]
    },
    {
      artifact_type: 'User ID',
      occurrences: 4,
      status: 'COVERED_BY_BROAD_POLICY_TERM',
      policy_evidence: [{ privacy_category: 'Personal Information' }]
    }
  ]
});
if (broadPolicyDashboard.result !== 'COMPLIANT_WITHIN_CAPTURE_SCOPE') {
  throw new Error('Approved broader policy terms must not create a disclosure gap');
}
if (broadPolicyDashboard.dashboard_summary.broadly_covered_information_type_count !== 2) {
  throw new Error('Dashboard must count broadly covered information types separately');
}
console.log('[PASS] Approved broad-policy coverage verified.');

// Test 4: Verify Forecastie
const fc = masterData.find(a => a.application.toLowerCase() === 'forecastie');
if (!fc) throw new Error('Forecastie not found');
console.log(`[PASS] Forecastie: reqs=${fc.total_requests}, sens=${fc.sensitive_occurrences}, result=${fc.result}`);
if (fc.total_requests !== 295) throw new Error(`Expected Forecastie requests 295, got ${fc.total_requests}`);
if (fc.sensitive_occurrences !== 88) throw new Error(`Expected Forecastie sensitive 88, got ${fc.sensitive_occurrences}`);

// Test 5: Verify Instagram
const ig = masterData.find(a => a.application.toLowerCase() === 'instagram');
if (!ig) throw new Error('Instagram not found');
console.log(`[PASS] Instagram: reqs=${ig.total_requests}, sens=${ig.sensitive_occurrences}, result=${ig.result}`);
if (ig.total_requests !== 936) throw new Error(`Expected Instagram requests 936, got ${ig.total_requests}`);
if (ig.sensitive_occurrences !== 4440) throw new Error(`Expected Instagram sensitive 4440, got ${ig.sensitive_occurrences}`);

// Test 6: Verify Spotify
const sp = masterData.find(a => a.application.toLowerCase() === 'spotify');
if (!sp) throw new Error('Spotify not found');
console.log(`[PASS] Spotify: reqs=${sp.total_requests}, sens=${sp.sensitive_occurrences}, result=${sp.result}`);
if (sp.total_requests !== 811) throw new Error(`Expected Spotify requests 811, got ${sp.total_requests}`);
if (sp.sensitive_occurrences !== 358) throw new Error(`Expected Spotify sensitive 358, got ${sp.sensitive_occurrences}`);

// Test 7: Verify Roblox external validation
const robloxStatsPath = path.resolve(__dirname, '../data/output/external_validation/results/antshield_roblox_test/statistics.json');
const robloxStats = JSON.parse(fs.readFileSync(robloxStatsPath, 'utf8'));
console.log(`[PASS] Roblox External: app=${robloxStats.app_name}, reqs=${robloxStats.total_requests}, sens=${robloxStats.sensitive_data_occurrences}, artifacts=${robloxStats.unique_sensitive_artifacts}`);
if (robloxStats.total_requests !== 1251) throw new Error(`Expected Roblox requests 1251, got ${robloxStats.total_requests}`);
if (robloxStats.sensitive_data_occurrences !== 1284) throw new Error(`Expected Roblox sensitive 1284, got ${robloxStats.sensitive_data_occurrences}`);
if (robloxStats.unique_sensitive_artifacts !== 15) throw new Error(`Expected Roblox unique artifacts 15, got ${robloxStats.unique_sensitive_artifacts}`);

console.log('\n======================================================');
console.log('ALL CONFIGURED DASHBOARD INTEGRITY CHECKS PASSED');
console.log('======================================================');
