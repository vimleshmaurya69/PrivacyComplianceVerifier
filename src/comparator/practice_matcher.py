"""Exact, evidence-bounded matching of observed and declared practices."""

from src.comparator.semantic_category_mapping import EXACT_CATEGORY_MAPPINGS
from src.policy.policy_models import (
    is_specific_verified_practice,
    is_verified_information_type_practice,
)
from src.policy.policy_artifact_semantics import (
    artifact_matches,
    policy_artifacts,
)


COMPARABLE_POLICY_CATEGORIES = set(EXACT_CATEGORY_MAPPINGS.values())
OUTBOUND_POLICY_ACTIONS = {"transmit", "share", "disclose"}


def _domain_matches(domain, declarations):
    if not domain or not declarations:
        return False

    def normalize(value):
        value = str(value or "").strip().lower().rstrip(".")
        wildcard = value.startswith("*.")
        if wildcard:
            value = value[2:]
        if value.startswith("[") and "]" in value:
            closing = value.find("]")
            host = value[1:closing]
            suffix = value[closing + 1:]
            if not suffix or (suffix.startswith(":") and suffix[1:].isdigit()):
                value = host
        elif value.count(":") == 1:
            host, port = value.rsplit(":", 1)
            if port.isdigit():
                value = host
        return value, wildcard

    normalized, _ = normalize(domain)

    for declaration in declarations:
        if not isinstance(declaration, dict):
            continue
        expected = declaration.get("domain")
        if not expected:
            continue
        expected, wildcard = normalize(expected)
        if normalized == expected:
            return True
        if (
            (declaration.get("include_subdomains") is True or wildcard)
            and normalized.endswith("." + expected)
        ):
            return True
    return False


def _recipient_scope_matches(observed, policy_record):
    """Match only explicit observed scope justification or policy domains.

    Traffic attribution (``application``/``third_party``) remains separate
    from policy recipient scope. Ownership labels alone do not establish the
    policy relationship described as first party, service provider, or third
    party.
    """
    policy_scope = policy_record.get("recipient_scope")
    observed_scope = observed.get("policy_recipient_scope", "unknown")
    domains = policy_record.get("recipient_domains", [])

    if domains:
        return _domain_matches(observed.get("recipient_domain"), domains)
    if observed_scope != "unknown":
        return observed_scope == policy_scope
    return False


def _policy_action_matches_observed(policy_action, observed_action):
    """Bridge explicit policy sharing language to outbound network evidence.

    Collection is deliberately excluded: naming collected information can
    support information-type disclosure, but cannot by itself establish a
    complete transmission or recipient practice.
    """
    if policy_action == observed_action:
        return True
    return (
        observed_action == "transmit"
        and policy_action in {"share", "disclose"}
    )


def _practice_matches(observed, declared):
    reasons = []
    if not is_specific_verified_practice(declared):
        reasons.append("POLICY_PRACTICE_NOT_SPECIFIC_AND_VERIFIED")
        return False, reasons
    if observed.get("privacy_category") != declared.get("privacy_category"):
        reasons.append("PRIVACY_CATEGORY_DIFFERS")
    if not artifact_matches(observed.get("artifact_type"), declared):
        reasons.append("ARTIFACT_TYPE_DIFFERS")
    if not _policy_action_matches_observed(
        declared.get("action"), observed.get("action")
    ):
        reasons.append("ACTION_DIFFERS")
    if not _recipient_scope_matches(observed, declared):
        if observed.get("policy_recipient_scope") == "unknown" and not declared.get(
            "recipient_domains"
        ):
            reasons.append("OBSERVED_POLICY_RECIPIENT_SCOPE_UNRESOLVED")
        else:
            reasons.append("RECIPIENT_SCOPE_OR_DOMAIN_DIFFERS")
    return not reasons, reasons


def _canonical_artifact_evidence(practice):
    provenance = practice.get("provenance", {})
    return bool(
        not practice.get("legacy")
        and practice.get("artifact_types")
        and practice.get("verification", {}).get("state") == "VERIFIED"
        and provenance.get("source_ids")
        and provenance.get("locator")
        and provenance.get("evidence")
        and provenance.get("reviewed_at")
    )


def _information_type_match(observed, declared):
    """Return evidence for an information-level policy match, if supported."""
    if observed.get("action") != "transmit":
        return None
    if observed.get("privacy_category") != declared.get("privacy_category"):
        return None

    matched_artifact = artifact_matches(
        observed.get("artifact_type"), declared
    )
    if not matched_artifact:
        return None

    if is_verified_information_type_practice(declared):
        policy_action = declared.get("action")
        if policy_action in {"collect", "receive"}:
            reason_code = "POLICY_COLLECTION_MATCHES_OBSERVED_TRANSMISSION"
        else:
            reason_code = "POLICY_INFORMATION_TYPE_MATCH"
        confidence = "HIGH"
    elif (
        _canonical_artifact_evidence(declared)
        and declared.get("action") == "unknown"
    ):
        reason_code = "POLICY_ARTIFACT_MATCH_ACTION_UNSPECIFIED"
        confidence = "MEDIUM"
    else:
        # Legacy ``declared_practices`` contain manually summarized free text,
        # but no source-backed normalized action.  A matching phrase can show
        # that a data type was mentioned; it cannot establish that collection,
        # use, or transmission was affirmatively disclosed.  Keep it available
        # as candidate policy evidence without promoting it to a disclosure.
        return None

    qualifiers = []
    if (
        declared.get("recipient_scope") == "unknown"
        and not declared.get("recipient_domains")
    ):
        qualifiers.append("POLICY_RECIPIENT_NOT_SPECIFIED")
    if (
        observed.get("traffic_recipient_scope") == "third_party"
        and declared.get("action") not in {"share", "disclose", "transmit"}
    ):
        qualifiers.append("THIRD_PARTY_SHARING_NOT_ESTABLISHED")

    return {
        "practice": declared,
        "matched_policy_artifact": matched_artifact,
        "reason_code": reason_code,
        "confidence": confidence,
        "qualifiers": qualifiers,
    }


def _coverage_applies(observed, coverage):
    if coverage.get("state") != "VERIFIED_COMPLETE":
        return False
    if coverage.get("privacy_category") not in {
        "*", observed.get("privacy_category")
    }:
        return False
    if not _policy_action_matches_observed(
        coverage.get("action"), observed.get("action")
    ):
        return False
    artifacts = coverage.get("artifact_types", [])
    if artifacts and not artifact_matches(observed.get("artifact_type"), coverage):
        return False
    return _recipient_scope_matches(observed, coverage)


class PracticeMatcher:
    def __init__(self, policy_document):
        self.policy = policy_document

    def compare(self, observed_practices):
        declared_practices = self.policy.get("policy_practices", [])
        coverage_records = self.policy.get("comparison_coverage", [])
        results = []
        matched_policy_ids = set()

        for observed in observed_practices:
            category_candidates = [
                practice
                for practice in declared_practices
                if practice.get("privacy_category")
                == observed.get("privacy_category")
            ]

            matches = []
            information_matches = []
            candidate_failures = []
            for candidate in category_candidates:
                matched, reasons = _practice_matches(observed, candidate)
                if matched:
                    matches.append(candidate)
                    matched_policy_ids.add(candidate.get("practice_id"))
                else:
                    candidate_failures.append({
                        "practice_id": candidate.get("practice_id"),
                        "reasons": reasons,
                    })
                    information_match = _information_type_match(
                        observed, candidate
                    )
                    if information_match:
                        information_matches.append(information_match)
                        matched_policy_ids.add(candidate.get("practice_id"))

            applicable_coverage = [
                record
                for record in coverage_records
                if _coverage_applies(observed, record)
            ]

            if matches:
                status = "PRACTICE DISCLOSED"
                selected_policy = matches[0]
                matched_policy_artifact = artifact_matches(
                    observed.get("artifact_type"), selected_policy
                )
                confidence = "HIGH"
                reason_code = (
                    "POLICY_PRACTICE_MATCHES_OBSERVED_TRANSMISSION"
                )
                qualifiers = []
                explanation = (
                    "A verified policy practice matches the observed category, "
                    "artifact type, sharing action, and attributable recipient "
                    "scope or verified recipient domain."
                )
            elif applicable_coverage:
                # Verified-complete coverage is scoped to the observed
                # category, artifact, action, and justified recipient.  A
                # weaker information-type mention cannot override the absence
                # of a matching practice inside that explicitly complete
                # scope.
                status = "POTENTIAL NON-DISCLOSURE"
                selected_policy = None
                matched_policy_artifact = None
                confidence = "HIGH"
                reason_code = (
                    "OBSERVED_INFORMATION_NOT_DISCLOSED_WITHIN_VERIFIED_COVERAGE"
                )
                qualifiers = []
                explanation = (
                    "No matching policy practice was found within a scope "
                    "whose extraction is explicitly marked "
                    "VERIFIED_COMPLETE."
                )
            elif information_matches:
                information_matches.sort(
                    key=lambda item: (
                        item["confidence"] != "HIGH",
                        item["practice"].get("legacy") is True,
                    )
                )
                selected = information_matches[0]
                selected_policy = selected["practice"]
                matched_policy_artifact = selected[
                    "matched_policy_artifact"
                ]
                confidence = selected["confidence"]
                reason_code = selected["reason_code"]
                qualifiers = list(selected["qualifiers"])
                status = "INFORMATION DISCLOSED"
                explanation = (
                    "Policy evidence explicitly identifies the observed "
                    "information type. The network observation establishes "
                    "transmission; recipient or channel details remain "
                    "qualified unless the policy explicitly states them."
                )
            else:
                status = "INSUFFICIENT POLICY DETAIL"
                selected_policy = None
                matched_policy_artifact = None
                confidence = "LOW"
                reason_code = (
                    "NO_ARTIFACT_LEVEL_POLICY_MATCH_AND_COVERAGE_INCOMPLETE"
                )
                qualifiers = ["POLICY_COVERAGE_INCOMPLETE"]
                explanation = (
                    "No artifact-level policy evidence matches the observed "
                    "information, and policy coverage is not sufficiently "
                    "complete to support a non-disclosure finding."
                )

            information_type_practices = [
                item["practice"] for item in information_matches
            ]
            decision_trace = {
                "observed_category": observed.get("privacy_category"),
                "observed_artifact_type": observed.get("artifact_type"),
                "observed_action": observed.get("action"),
                "observed_recipient_scope": observed.get(
                    "traffic_recipient_scope"
                ),
                "matched_policy_practice_id": (
                    selected_policy.get("practice_id")
                    if selected_policy else None
                ),
                "matched_policy_category": (
                    selected_policy.get("privacy_category")
                    if selected_policy else None
                ),
                "matched_policy_artifact_type": matched_policy_artifact,
                "matched_policy_action": (
                    selected_policy.get("action")
                    if selected_policy else None
                ),
                "decision": status,
                "confidence": confidence,
                "reason": explanation,
                "reason_code": reason_code,
                "qualifiers": qualifiers,
            }

            results.append({
                "result_type": "observed_practice",
                "practice_id": observed.get("practice_id"),
                "privacy_category": observed.get("privacy_category"),
                "artifact_type": observed.get("artifact_type"),
                "action": observed.get("action"),
                "traffic_recipient_scope": observed.get(
                    "traffic_recipient_scope"
                ),
                "policy_recipient_scope": observed.get(
                    "policy_recipient_scope"
                ),
                "recipient_domain": observed.get("recipient_domain"),
                "request_location": observed.get("request_location"),
                "status": status,
                "decision": status,
                "confidence": confidence,
                "reason_code": reason_code,
                "explanation": explanation,
                "decision_trace": decision_trace,
                "risk_flags": list(observed.get("risk_flags", [])),
                "occurrence_count": observed.get("occurrence_count", 0),
                "observed_evidence": list(observed.get("evidence", [])),
                "matching_policy_practices": matches,
                "information_type_policy_practices": information_type_practices,
                "applicable_coverage": applicable_coverage,
                "candidate_failures": candidate_failures,
            })

        results.extend(
            self._unobserved_policy_results(
                declared_practices, matched_policy_ids, observed_practices
            )
        )
        return results

    @staticmethod
    def _unobserved_policy_results(
        declared_practices, matched_policy_ids, observed_practices
    ):
        results = []
        for declared in declared_practices:
            if declared.get("practice_id") in matched_policy_ids:
                continue
            if not (
                is_specific_verified_practice(declared)
                or is_verified_information_type_practice(declared)
                or _canonical_artifact_evidence(declared)
            ):
                continue

            category = declared.get("privacy_category")
            if category not in COMPARABLE_POLICY_CATEGORIES:
                status = "NOT ASSESSABLE FROM HAR"
                explanation = (
                    "The verified policy practice has no approved exact HAR "
                    "category mapping."
                )
            else:
                comparable_observed = [
                    item
                    for item in observed_practices
                    if item.get("privacy_category") == category
                    and artifact_matches(item.get("artifact_type"), declared)
                ]

            if category in COMPARABLE_POLICY_CATEGORIES and not comparable_observed:
                status = "NOT OBSERVED IN CAPTURE"
                explanation = (
                    "The policy discloses this information type, but it was "
                    "not observed in the available capture. This is not "
                    "evidence that the practice never occurs."
                )
            elif (
                category in COMPARABLE_POLICY_CATEGORIES
                and declared.get("action") in OUTBOUND_POLICY_ACTIONS
                and not declared.get("recipient_domains")
                and declared.get("recipient_scope") == "unknown"
            ):
                status = "NOT ASSESSABLE FROM HAR"
                explanation = (
                    "Related information was observed, but the recipient "
                    "evidence needed to assess this sharing practice is not "
                    "available."
                )
            elif category in COMPARABLE_POLICY_CATEGORIES:
                # A related observed result already carries the decision trace.
                continue

            results.append({
                "result_type": "declared_practice",
                "practice_id": declared.get("practice_id"),
                "privacy_category": category,
                "artifact_type": None,
                "artifact_types": list(declared.get("artifact_types", [])),
                "action": declared.get("action"),
                "traffic_recipient_scope": None,
                "policy_recipient_scope": declared.get("recipient_scope"),
                "recipient_domain": None,
                "request_location": None,
                "status": status,
                "decision": status,
                "confidence": "HIGH",
                "reason_code": (
                    "POLICY_INFORMATION_NOT_OBSERVED_IN_CAPTURE"
                    if status == "NOT OBSERVED IN CAPTURE"
                    else "PRACTICE_NOT_ASSESSABLE_FROM_AVAILABLE_EVIDENCE"
                ),
                "explanation": explanation,
                "decision_trace": None,
                "risk_flags": [],
                "occurrence_count": 0,
                "observed_evidence": [],
                "matching_policy_practices": [declared],
                "information_type_policy_practices": [],
                "applicable_coverage": [],
                "candidate_failures": [],
            })
        return results
