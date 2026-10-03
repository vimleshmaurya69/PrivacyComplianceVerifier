const TECHNICAL_AUTHENTICATION_TYPES = new Set([
  'Authorization Token',
  'Session Cookie'
]);

export const TECHNICAL_AUTHENTICATION_STATUS = 'TECHNICAL_AUTHENTICATION_ARTIFACT';

export function isTechnicalAuthenticationArtifact(result) {
  return TECHNICAL_AUTHENTICATION_TYPES.has(result?.artifact_type);
}

export function buildDashboardPresentation(simpleReport = {}) {
  const rawResults = simpleReport.information_type_results || [];
  const results = rawResults.map(result => {
    if (!isTechnicalAuthenticationArtifact(result)) return result;
    return {
      ...result,
      status: TECHNICAL_AUTHENTICATION_STATUS,
      reason_code: 'TECHNICAL_AUTHENTICATION_ARTIFACT_EXCLUDED_FROM_POLICY_GAP'
    };
  });

  const observedComparable = results.filter(
    result => (result.occurrences || 0) > 0 && result.status !== TECHNICAL_AUTHENTICATION_STATUS
  );
  const disclosed = observedComparable.filter(result => result.status === 'DISCLOSED').length;
  const notDisclosed = observedComparable.filter(
    result => result.status === 'NOT_DISCLOSED_IN_REVIEWED_POLICY'
  ).length;
  const reviewIncomplete = observedComparable.filter(
    result => result.status === 'POLICY_REVIEW_INCOMPLETE'
  ).length;
  const unclassifiedComparable = observedComparable.length - disclosed - notDisclosed - reviewIncomplete;
  const technicalEvidence = results.filter(
    result => result.status === TECHNICAL_AUTHENTICATION_STATUS && (result.occurrences || 0) > 0
  );

  let result = 'CANNOT_DETERMINE';
  if (notDisclosed > 0) {
    result = 'POTENTIALLY_NON_COMPLIANT';
  } else if (observedComparable.length > 0 && reviewIncomplete === 0 && unclassifiedComparable === 0) {
    result = 'COMPLIANT_WITHIN_CAPTURE_SCOPE';
  }

  return {
    ...simpleReport,
    raw_framework_result: simpleReport.result || simpleReport.capture_scoped_result,
    information_type_results: results,
    result,
    dashboard_summary: {
      disclosed_information_type_count: disclosed,
      not_disclosed_information_type_count: notDisclosed,
      policy_review_incomplete_type_count: reviewIncomplete + unclassifiedComparable,
      technical_authentication_artifact_count: technicalEvidence.length
    },
    technical_authentication_evidence: technicalEvidence
  };
}

export function applyDashboardPresentationToRow(row, simpleReport) {
  if (!simpleReport) return row;
  const presentation = buildDashboardPresentation(simpleReport);
  return {
    ...row,
    raw_framework_result: row.result,
    result: presentation.result,
    ...presentation.dashboard_summary
  };
}
