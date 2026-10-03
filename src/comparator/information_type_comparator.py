"""Capture-scoped comparison of observed and policy-declared information types.

This intentionally simpler view complements, rather than replaces, the
practice-level comparator.  It never uses a broad privacy category as proof
that a concrete information type was disclosed.
"""

from collections import defaultdict
import re

from src.comparator.semantic_category_mapping import (
    policy_category_for_observed,
)
from src.policy.policy_artifact_semantics import policy_artifacts
from src.utils.privacy_taxonomy import PRIVACY_CATEGORY_MAP


ATTRIBUTABLE_TRAFFIC_TYPES = {"Application", "Third Party"}
REVIEWED_COMPLETE = "REVIEWED_COMPLETE"
REVIEW_INCOMPLETE = "REVIEW_INCOMPLETE"
POLICY_UNAVAILABLE = "POLICY_UNAVAILABLE"

DISCLOSED = "DISCLOSED"
NOT_DISCLOSED = "NOT_DISCLOSED_IN_REVIEWED_POLICY"
POLICY_REVIEW_INCOMPLETE = "POLICY_REVIEW_INCOMPLETE"
DECLARED_NOT_OBSERVED = "DECLARED_NOT_OBSERVED_IN_CAPTURE"
NOT_ASSESSABLE = "NOT_ASSESSABLE_FROM_HAR"

RESULT_COMPLIANT = "COMPLIANT_WITHIN_CAPTURE_SCOPE"
RESULT_POTENTIAL = "POTENTIALLY_NON_COMPLIANT"
RESULT_UNKNOWN = "CANNOT_DETERMINE"

ASSESSABLE_ARTIFACTS = set(PRIVACY_CATEGORY_MAP)


def _sorted_unique(values):
    return sorted({value for value in values if value})


def _document_sources(policy):
    return [
        {
            "source_id": source.get("source_id"),
            "title": source.get("title"),
            "url": source.get("url") or source.get("source"),
        }
        for source in policy.get("sources", [])
        if isinstance(source, dict)
    ]


def determine_policy_review(policy):
    """Determine whether the local reviewed representation is complete enough.

    REVIEWED_COMPLETE is a project data-quality state, not a statement that a
    publisher's policy is legally complete.  Existing curated policy summaries
    qualify only when they have a source, a review date, and structured
    practices.  Empty/unreviewed representations remain incomplete.
    """
    explicit = policy.get("information_type_review")
    if isinstance(explicit, dict):
        requested = str(explicit.get("status") or "").upper()
        if requested in {REVIEWED_COMPLETE, REVIEW_INCOMPLETE, POLICY_UNAVAILABLE}:
            return {
                "status": requested,
                "basis": explicit.get("basis") or "EXPLICIT_POLICY_METADATA",
                "reviewed_at": explicit.get("reviewed_at") or policy.get("last_verified"),
                "sources": _document_sources(policy),
            }

    if policy.get("policy_available") is False:
        status = POLICY_UNAVAILABLE
        basis = "POLICY_MARKED_UNAVAILABLE"
    elif (
        policy.get("sources")
        and policy.get("last_verified")
        and policy.get("policy_practices")
    ):
        status = REVIEWED_COMPLETE
        basis = "CURATED_POLICY_SUMMARY_WITH_SOURCE_AND_REVIEW_DATE"
    else:
        status = REVIEW_INCOMPLETE
        basis = "MISSING_STRUCTURED_PRACTICES_OR_REVIEW_METADATA"

    return {
        "status": status,
        "basis": basis,
        "reviewed_at": policy.get("last_verified"),
        "sources": _document_sources(policy),
    }


def _coordinate_artifacts(text):
    text = str(text or "").lower()
    artifacts = []
    if re.search(r"\blatitude\b|\bcoordinates?\b|\bgps coordinates?\b", text):
        artifacts.append("Latitude")
    if re.search(r"\blongitude\b|\bcoordinates?\b|\bgps coordinates?\b", text):
        artifacts.append("Longitude")
    return artifacts


def _effective_artifact(artifact):
    # A clearly named device identifier is the policy-side equivalent of the
    # detector's generic Device ID.  Device Information is never mapped here.
    if artifact == "Device Identifier":
        return "Device ID"
    return artifact


def extract_policy_declarations(policy):
    """Return deduplicated explicit information declarations with provenance."""
    grouped = defaultdict(list)
    sources = _document_sources(policy)
    for practice in policy.get("policy_practices", []):
        if not isinstance(practice, dict):
            continue
        artifacts = list(policy_artifacts(practice))
        evidence = practice.get("provenance", {}).get("evidence")
        legacy_text = practice.get("legacy_evidence", {}).get("data_type")
        coordinate_text = " ".join(
            str(value) for value in (evidence, legacy_text) if value
        )
        artifacts.extend(_coordinate_artifacts(coordinate_text))

        for raw_artifact in artifacts:
            artifact = _effective_artifact(raw_artifact)
            record = {
                "artifact_type": artifact,
                "declared_as": raw_artifact,
                "privacy_category": practice.get("privacy_category"),
                "practice_id": practice.get("practice_id"),
                "statement": evidence or legacy_text,
                "locator": practice.get("provenance", {}).get("locator"),
                "source_ids": practice.get("provenance", {}).get("source_ids", []),
                "source_label": practice.get("provenance", {}).get("legacy_source"),
                "sources": sources,
                "reviewed_at": practice.get("provenance", {}).get("reviewed_at"),
            }
            signature = (
                record["practice_id"], record["statement"], record["locator"]
            )
            if not any(
                (item["practice_id"], item["statement"], item["locator"])
                == signature
                for item in grouped[artifact]
            ):
                grouped[artifact].append(record)
    return dict(grouped)


def build_observed_information_types(privacy_inventory):
    """Collapse occurrences to distinct information types without losing counts."""
    grouped = defaultdict(lambda: {
        "occurrences": 0,
        "privacy_categories": set(),
        "destinations": set(),
        "locations": set(),
        "keys": set(),
        "traffic_types": set(),
    })
    excluded = defaultdict(int)

    for traffic_type, section in (privacy_inventory or {}).items():
        if not isinstance(section, dict):
            continue
        for finding in section.get("evidence", []):
            if not isinstance(finding, dict) or finding.get("direction") != "outbound":
                continue
            category = finding.get("privacy_category") or "Unknown"
            artifact = finding.get("type") or "Unknown"
            if traffic_type not in ATTRIBUTABLE_TRAFFIC_TYPES:
                excluded[("NON_ATTRIBUTABLE_TRAFFIC", category, artifact)] += 1
                continue
            if policy_category_for_observed(category) is None:
                excluded[("NOT_COMPARABLE_CATEGORY", category, artifact)] += 1
                continue
            group = grouped[artifact]
            group["occurrences"] += 1
            group["privacy_categories"].add(category)
            group["destinations"].add(finding.get("domain"))
            group["locations"].add(finding.get("source"))
            group["keys"].add(finding.get("key"))
            group["traffic_types"].add(traffic_type)

    observed = []
    for artifact, details in sorted(grouped.items()):
        observed.append({
            "artifact_type": artifact,
            "privacy_categories": _sorted_unique(details["privacy_categories"]),
            "occurrences": details["occurrences"],
            "destinations": _sorted_unique(details["destinations"]),
            "locations": _sorted_unique(details["locations"]),
            "keys": _sorted_unique(details["keys"]),
            "traffic_types": _sorted_unique(details["traffic_types"]),
        })
    excluded_records = [
        {
            "privacy_category": category,
            "artifact_type": artifact,
            "occurrences": count,
            "reason": reason,
        }
        for (reason, category, artifact), count in sorted(excluded.items())
    ]
    return observed, excluded_records


def compare_information_types(privacy_inventory, policy):
    """Compare unique observed types against explicit reviewed declarations."""
    review = determine_policy_review(policy)
    declarations = extract_policy_declarations(policy)
    observed, excluded = build_observed_information_types(privacy_inventory)
    observed_types = {item["artifact_type"] for item in observed}
    results = []

    for item in observed:
        artifact = item["artifact_type"]
        matches = declarations.get(artifact, [])
        if matches:
            status = DISCLOSED
            reason = "EXPLICIT_INFORMATION_TYPE_FOUND"
        elif review["status"] == REVIEWED_COMPLETE:
            status = NOT_DISCLOSED
            reason = "ABSENT_FROM_REVIEWED_POLICY_SUMMARY"
        else:
            status = POLICY_REVIEW_INCOMPLETE
            reason = "POLICY_REPRESENTATION_NOT_COMPLETE_FOR_ABSENCE_DECISION"
        results.append({
            **item,
            "status": status,
            "reason_code": reason,
            "policy_evidence": matches,
        })

    for artifact, evidence in sorted(declarations.items()):
        if artifact in observed_types:
            continue
        assessable = artifact in ASSESSABLE_ARTIFACTS
        results.append({
            "artifact_type": artifact,
            "privacy_categories": _sorted_unique(
                item.get("privacy_category") for item in evidence
            ),
            "occurrences": 0,
            "destinations": [],
            "locations": [],
            "keys": [],
            "traffic_types": [],
            "status": DECLARED_NOT_OBSERVED if assessable else NOT_ASSESSABLE,
            "reason_code": (
                "DECLARED_TYPE_NOT_OBSERVED_IN_CAPTURE"
                if assessable
                else "DECLARED_TYPE_NOT_RELIABLY_ASSESSABLE_FROM_HAR"
            ),
            "policy_evidence": evidence,
        })

    observed_results = [item for item in results if item["occurrences"]]
    if any(item["status"] == NOT_DISCLOSED for item in observed_results):
        capture_result = RESULT_POTENTIAL
    elif (
        observed_results
        and review["status"] == REVIEWED_COMPLETE
        and all(item["status"] == DISCLOSED for item in observed_results)
    ):
        capture_result = RESULT_COMPLIANT
    else:
        capture_result = RESULT_UNKNOWN

    return {
        "policy_review": review,
        "policy_declarations": declarations,
        "observed_information_types": observed,
        "information_type_results": results,
        "excluded_evidence": excluded,
        "capture_scoped_result": capture_result,
    }
