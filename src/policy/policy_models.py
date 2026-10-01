"""Canonical, conservative policy-evidence normalization.

The policy files in this project were collected over time and use several
closely related JSON shapes.  This module converts those shapes into one
comparison model without inventing missing action, artifact, recipient, or
coverage information.
"""

from copy import deepcopy
from urllib.parse import urlsplit


POLICY_SCHEMA_VERSION = 2

COVERAGE_STATES = {"VERIFIED_COMPLETE", "PARTIAL", "UNKNOWN"}
PRACTICE_VERIFICATION_STATES = {"VERIFIED", "UNVERIFIED"}
PRACTICE_COVERAGE_STATES = {"VERIFIED", "PARTIAL", "UNKNOWN"}
POLICY_ACTIONS = {
    # Policy-perspective actions.
    "collect",
    "share",
    "disclose",
    "use",
    "retain",
    "receive",
    "local_access",
    "unknown",
    # Retained for backward compatibility with existing schema-v2 policies.
    "transmit",
}
POLICY_RECIPIENT_SCOPES = {
    "first_party",
    "third_party",
    "service_provider",
    "unknown",
}


SOURCE_FIELDS = (
    ("source", "privacy_policy"),
    ("policy_source", "privacy_policy"),
    ("policy_sources", "privacy_policy"),
    ("privacy_summary_source", "privacy_summary"),
    ("website_source", "website"),
    ("cookie_source", "cookie_policy"),
    ("additional_source", "additional"),
    ("additional_sources", "additional"),
)


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _clean_string(value):
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def _normalize_enum(value, allowed, default):
    value = _clean_string(value)
    if not value:
        return default
    value = value.lower().replace("-", "_").replace(" ", "_")
    return value if value in allowed else default


def _normalize_url(value):
    value = _clean_string(value)
    if not value:
        return None
    try:
        parsed = urlsplit(value)
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return None
    return value


def normalize_sources(policy):
    """Collect all supported provenance fields into a deduplicated list."""
    candidates = []

    for item in _as_list(policy.get("sources")):
        candidates.append((item, "privacy_policy"))

    for field, source_type in SOURCE_FIELDS:
        for item in _as_list(policy.get(field)):
            candidates.append((item, source_type))

    sources = []
    seen = set()
    for item, default_type in candidates:
        if isinstance(item, str):
            url = _normalize_url(item)
            if not url:
                continue
            normalized = {
                "source_id": None,
                "type": default_type,
                "url": url,
                "title": None,
            }
        elif isinstance(item, dict):
            source_value = item.get("source")
            url = _normalize_url(
                item.get("url")
                or item.get("href")
                or item.get("source_url")
                or source_value
            )
            if not url:
                continue
            source_title = (
                source_value
                if isinstance(source_value, str)
                and _normalize_url(source_value) is None
                else None
            )
            normalized = {
                "source_id": _clean_string(item.get("source_id")),
                "type": _clean_string(item.get("type")) or default_type,
                "url": url,
                "title": (
                    _clean_string(item.get("title"))
                    or _clean_string(source_title)
                ),
                "metadata": {
                    key: deepcopy(value)
                    for key, value in item.items()
                    if key not in {
                        "source_id", "type", "url", "href",
                        "source_url", "source", "title",
                    }
                },
            }
        else:
            continue

        identity = normalized["url"].lower()
        if identity in seen:
            continue
        seen.add(identity)
        if not normalized["source_id"]:
            normalized["source_id"] = f"source-{len(sources) + 1}"
        normalized.setdefault("metadata", {})
        sources.append(normalized)

    return sources


def _normalize_artifact_types(value):
    artifacts = []
    for item in _as_list(value):
        item = _clean_string(item)
        if item and item not in artifacts:
            artifacts.append(item)
    return artifacts


def _normalize_domains(value):
    domains = []
    seen = set()
    for item in _as_list(value):
        include_subdomains = False
        if isinstance(item, str):
            domain = item
        elif isinstance(item, dict):
            domain = item.get("domain")
            include_subdomains = item.get("include_subdomains") is True
        else:
            continue

        domain = _clean_string(domain)
        if not domain:
            continue
        domain = domain.lower().rstrip(".")
        if domain.startswith("*."):
            domain = domain[2:]
            include_subdomains = True
        if domain.startswith("[") and "]" in domain:
            closing = domain.find("]")
            host = domain[1:closing]
            suffix = domain[closing + 1:]
            if not suffix or (suffix.startswith(":") and suffix[1:].isdigit()):
                domain = host
        elif domain.count(":") == 1:
            host, port = domain.rsplit(":", 1)
            if port.isdigit():
                domain = host
        if not domain or any(ch.isspace() for ch in domain):
            continue

        identity = (domain, include_subdomains)
        if identity in seen:
            continue
        seen.add(identity)
        domains.append({
            "domain": domain,
            "include_subdomains": include_subdomains,
        })
    return domains


def _normalize_provenance(raw, reviewed_at=None):
    provenance = raw.get("provenance")
    if not isinstance(provenance, dict):
        provenance = {}
    else:
        provenance = deepcopy(provenance)

    source_ids = _normalize_artifact_types(provenance.get("source_ids"))
    source_label = (
        _clean_string(raw.get("source"))
        or _clean_string(raw.get("source_type"))
        or _clean_string(raw.get("evidence"))
    )
    if source_label and not source_ids:
        provenance["legacy_source"] = source_label

    provenance["source_ids"] = source_ids
    provenance["locator"] = _clean_string(provenance.get("locator"))
    provenance["evidence"] = _clean_string(provenance.get("evidence"))
    provenance["reviewed_at"] = (
        _clean_string(provenance.get("reviewed_at"))
        or _clean_string(reviewed_at)
    )
    return provenance


def normalize_policy_practice(raw, index, reviewed_at=None, legacy=False):
    """Normalize one practice without interpreting its free-text fields."""
    if not isinstance(raw, dict):
        return None

    category = _clean_string(
        raw.get("privacy_category") or raw.get("category")
    )
    artifacts = _normalize_artifact_types(
        raw.get("artifact_types") or raw.get("artifact_type")
    )
    action = _normalize_enum(raw.get("action"), POLICY_ACTIONS, "unknown")
    recipient_scope = _normalize_enum(
        raw.get("recipient_scope"), POLICY_RECIPIENT_SCOPES, "unknown"
    )
    domains = _normalize_domains(raw.get("recipient_domains"))
    provenance = _normalize_provenance(raw, reviewed_at)

    verification = raw.get("verification")
    if not isinstance(verification, dict):
        verification = {}
    verification_state = _clean_string(verification.get("state"))
    verification_state = (
        verification_state.upper()
        if verification_state
        else "UNVERIFIED"
    )
    if verification_state not in PRACTICE_VERIFICATION_STATES:
        verification_state = "UNVERIFIED"

    practice_coverage = raw.get("coverage")
    if isinstance(practice_coverage, dict):
        practice_coverage = practice_coverage.get("state")
    practice_coverage = _clean_string(practice_coverage)
    practice_coverage = (
        practice_coverage.upper() if practice_coverage else "UNKNOWN"
    )
    if practice_coverage not in PRACTICE_COVERAGE_STATES:
        practice_coverage = "UNKNOWN"

    issues = []
    if not category:
        issues.append("PRIVACY_CATEGORY_MISSING")
    if not artifacts:
        issues.append("ARTIFACT_TYPES_MISSING")
    if action == "unknown":
        issues.append("ACTION_MISSING")
    if recipient_scope == "unknown":
        issues.append("RECIPIENT_SCOPE_MISSING")
    if verification_state != "VERIFIED":
        issues.append("PRACTICE_NOT_VERIFIED")
    if not provenance.get("source_ids"):
        issues.append("PRACTICE_SOURCE_MISSING")
    if not provenance.get("locator"):
        issues.append("PRACTICE_EVIDENCE_LOCATOR_MISSING")
    if not provenance.get("evidence"):
        issues.append("PRACTICE_EVIDENCE_TEXT_MISSING")
    if not provenance.get("reviewed_at"):
        issues.append("PRACTICE_REVIEW_DATE_MISSING")

    practice_id = _clean_string(raw.get("practice_id")) or f"practice-{index}"
    return {
        "practice_id": practice_id,
        "privacy_category": category,
        "artifact_types": artifacts,
        "action": action,
        "recipient_scope": recipient_scope,
        "recipient_domains": domains,
        "purpose": _clean_string(raw.get("purpose")),
        "provenance": provenance,
        "verification": {
            "state": verification_state,
            "reviewed_at": (
                _clean_string(verification.get("reviewed_at"))
                or provenance.get("reviewed_at")
            ),
        },
        "coverage": practice_coverage,
        "specificity_issues": issues,
        "legacy": bool(legacy),
        "legacy_evidence": {
            "data_type": raw.get("data_type") or raw.get("data"),
            "recipient": raw.get("recipient"),
            "source": (
                raw.get("source")
                or raw.get("source_type")
                or raw.get("evidence")
            ),
        },
    }


def normalize_coverage_record(raw, index, reviewed_at=None):
    """Normalize scope-specific completeness evidence.

    VERIFIED_COMPLETE is honored only when category, action, recipient scope,
    source identifiers, and review date are explicit.  Invalid completeness
    claims are downgraded to UNKNOWN instead of creating negative findings.
    """
    if not isinstance(raw, dict):
        return None

    state = _clean_string(raw.get("state"))
    state = state.upper() if state else "UNKNOWN"
    if state not in COVERAGE_STATES:
        state = "UNKNOWN"

    category = _clean_string(raw.get("privacy_category"))
    action = _normalize_enum(raw.get("action"), POLICY_ACTIONS, "unknown")
    recipient_scope = _normalize_enum(
        raw.get("recipient_scope"), POLICY_RECIPIENT_SCOPES, "unknown"
    )
    provenance = _normalize_provenance(raw, reviewed_at)
    artifacts = _normalize_artifact_types(raw.get("artifact_types"))
    domains = _normalize_domains(raw.get("recipient_domains"))

    issues = []
    if not category:
        issues.append("COVERAGE_CATEGORY_MISSING")
    if action == "unknown":
        issues.append("COVERAGE_ACTION_MISSING")
    if recipient_scope == "unknown":
        issues.append("COVERAGE_RECIPIENT_SCOPE_MISSING")
    if not provenance.get("source_ids"):
        issues.append("COVERAGE_SOURCE_MISSING")
    if not provenance.get("locator"):
        issues.append("COVERAGE_EVIDENCE_LOCATOR_MISSING")
    if not provenance.get("evidence"):
        issues.append("COVERAGE_EVIDENCE_TEXT_MISSING")
    if not provenance.get("reviewed_at"):
        issues.append("COVERAGE_REVIEW_DATE_MISSING")

    requested_state = state
    if state == "VERIFIED_COMPLETE" and issues:
        state = "UNKNOWN"
        issues.append("INVALID_VERIFIED_COMPLETE_DOWNGRADED")

    return {
        "coverage_id": (
            _clean_string(raw.get("coverage_id")) or f"coverage-{index}"
        ),
        "privacy_category": category,
        "artifact_types": artifacts,
        "action": action,
        "recipient_scope": recipient_scope,
        "recipient_domains": domains,
        "state": state,
        "requested_state": requested_state,
        "provenance": provenance,
        "issues": issues,
    }


def normalize_policy_document(policy):
    """Return the canonical policy document accepted by the comparator."""
    if not isinstance(policy, dict):
        policy = {}

    sources = normalize_sources(policy)
    last_verified = _clean_string(policy.get("last_verified"))

    declared_categories = []
    for category in _as_list(policy.get("declared_categories")):
        category = _clean_string(category)
        if category and category not in declared_categories:
            declared_categories.append(category)

    practices = []
    for raw in _as_list(policy.get("policy_practices")):
        practice = normalize_policy_practice(
            raw, len(practices) + 1, last_verified, legacy=False
        )
        if practice:
            practices.append(practice)
            category = practice.get("privacy_category")
            if category and category not in declared_categories:
                declared_categories.append(category)

    legacy_practices = [
        item
        for item in _as_list(policy.get("declared_practices"))
        if isinstance(item, dict)
    ]
    for raw in legacy_practices:
        practice = normalize_policy_practice(
            raw, len(practices) + 1, last_verified, legacy=True
        )
        if practice:
            practices.append(practice)
        category = _clean_string(raw.get("category"))
        if category and category not in declared_categories:
            declared_categories.append(category)

    coverage = []
    for raw in _as_list(policy.get("comparison_coverage")):
        record = normalize_coverage_record(
            raw, len(coverage) + 1, last_verified
        )
        if record:
            coverage.append(record)

    known_source_ids = {
        source["source_id"] for source in sources if source.get("source_id")
    }
    for practice in practices:
        referenced = set(practice["provenance"].get("source_ids", []))
        if referenced and not referenced.issubset(known_source_ids):
            practice["specificity_issues"].append(
                "PRACTICE_SOURCE_REFERENCE_UNKNOWN"
            )
            practice["verification"]["state"] = "UNVERIFIED"
    for record in coverage:
        referenced = set(record["provenance"].get("source_ids", []))
        if referenced and not referenced.issubset(known_source_ids):
            record["issues"].append("COVERAGE_SOURCE_REFERENCE_UNKNOWN")
            if record["state"] == "VERIFIED_COMPLETE":
                record["state"] = "UNKNOWN"
                record["issues"].append(
                    "INVALID_VERIFIED_COMPLETE_DOWNGRADED"
                )

    normalization_issues = []
    for practice in practices:
        normalization_issues.extend(practice["specificity_issues"])
    for record in coverage:
        normalization_issues.extend(record["issues"])

    return {
        "_canonical_policy_model": True,
        "schema_version": POLICY_SCHEMA_VERSION,
        "application": (
            _clean_string(policy.get("application"))
            or _clean_string(policy.get("app"))
            or _clean_string(policy.get("app_name"))
            or _clean_string(policy.get("display_name"))
            or "Unknown"
        ),
        "policy_available": policy.get("policy_available"),
        "sources": sources,
        "last_verified": last_verified,
        "declared_categories": declared_categories,
        "declared_practices": deepcopy(legacy_practices),
        "policy_practices": practices,
        "comparison_coverage": coverage,
        "tracking": deepcopy(policy.get("tracking", {})),
        "policy_scope": deepcopy(policy.get("policy_scope", [])),
        "third_party_services": deepcopy(policy.get("third_party_services", [])),
        "normalization_issues": sorted(set(normalization_issues)),
    }


def is_specific_verified_practice(practice):
    return bool(
        isinstance(practice, dict)
        and practice.get("privacy_category")
        and practice.get("artifact_types")
        and practice.get("action") != "unknown"
        and practice.get("recipient_scope") != "unknown"
        and practice.get("verification", {}).get("state") == "VERIFIED"
        and practice.get("provenance", {}).get("source_ids")
        and practice.get("provenance", {}).get("locator")
        and practice.get("provenance", {}).get("evidence")
        and practice.get("provenance", {}).get("reviewed_at")
    )


def is_verified_information_type_practice(practice):
    """Return whether canonical policy evidence identifies handled data.

    Information-level disclosure does not establish the recipient or network
    channel, so recipient scope is intentionally not required here.
    """
    return bool(
        isinstance(practice, dict)
        and practice.get("privacy_category")
        and practice.get("artifact_types")
        and practice.get("action") in {
            "collect", "receive", "use", "share", "disclose", "transmit"
        }
        and practice.get("verification", {}).get("state") == "VERIFIED"
        and practice.get("provenance", {}).get("source_ids")
        and practice.get("provenance", {}).get("locator")
        and practice.get("provenance", {}).get("evidence")
        and practice.get("provenance", {}).get("reviewed_at")
    )
