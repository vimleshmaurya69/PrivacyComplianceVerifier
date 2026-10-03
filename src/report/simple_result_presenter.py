"""Plain-language, capture-scoped policy-versus-traffic presentation."""

from collections import defaultdict

from src.comparator.information_type_comparator import (
    DECLARED_NOT_OBSERVED,
    DISCLOSED,
    NOT_ASSESSABLE,
    NOT_DISCLOSED,
    POLICY_REVIEW_INCOMPLETE,
    RESULT_UNKNOWN,
    build_observed_information_types,
    compare_information_types,
)


PRESENTATION_ORDER = (
    DISCLOSED,
    NOT_DISCLOSED,
    POLICY_REVIEW_INCOMPLETE,
    DECLARED_NOT_OBSERVED,
    NOT_ASSESSABLE,
)

PRESENTATION_MEANINGS = {
    DISCLOSED: "The reviewed policy explicitly names this information type.",
    NOT_DISCLOSED: (
        "This observed information type was not found in the reviewed policy "
        "representation."
    ),
    POLICY_REVIEW_INCOMPLETE: (
        "The local policy representation is not complete enough to treat "
        "absence as non-disclosure."
    ),
    DECLARED_NOT_OBSERVED: (
        "The policy names this information type, but it was not observed in "
        "the available capture."
    ),
    NOT_ASSESSABLE: (
        "The policy names this practice, but HAR traffic cannot reliably "
        "confirm whether it occurred."
    ),
}

RISK_TITLES = {
    "CREDENTIAL_IN_URL": "Credential observed in URL",
    "PERSONAL_DATA_IN_URL": "Personal data observed in URL",
}

DISPLAY_RESULTS = {
    DISCLOSED: "IN POLICY",
    NOT_DISCLOSED: "NOT IN POLICY",
    POLICY_REVIEW_INCOMPLETE: "POLICY REVIEW NEEDED",
    DECLARED_NOT_OBSERVED: "DECLARED, NOT OBSERVED",
    NOT_ASSESSABLE: "NOT ASSESSABLE FROM HAR",
}

DISPLAY_SUMMARIES = {
    "COMPLIANT_WITHIN_CAPTURE_SCOPE": "ALL OBSERVED TYPES DISCLOSED",
    "POTENTIALLY_NON_COMPLIANT": "POTENTIALLY NON-COMPLIANT",
    "CANNOT_DETERMINE": "CANNOT DETERMINE",
}


def _sorted_unique(values):
    return sorted({value for value in values if value})


def _risk_signals(practice_risks):
    return [
        {
            "type": risk.get("type"),
            "title": RISK_TITLES.get(
                risk.get("type"), str(risk.get("type") or "Review signal")
            ),
            "severity": risk.get("severity"),
            "explanation": risk.get("explanation"),
            "evidence_count": len(risk.get("evidence", [])),
        }
        for risk in (practice_risks or [])
        if isinstance(risk, dict)
    ]


def _group_results(results):
    grouped = defaultdict(list)
    for item in results:
        grouped[item["status"]].append(item["artifact_type"])
    return [
        {
            "result": status,
            "information_types": _sorted_unique(grouped[status]),
            "information_type_count": len(set(grouped[status])),
            "decision_record_count": len(grouped[status]),
            "meaning": PRESENTATION_MEANINGS[status],
        }
        for status in PRESENTATION_ORDER
        if status in grouped
    ]


def _legacy_policy_document(compliance_report):
    """Best-effort adapter for callers that have not supplied parsed policy."""
    return {
        "policy_available": compliance_report.get("policy_available"),
        "sources": compliance_report.get("policy_sources", []),
        "last_verified": compliance_report.get("policy_last_verified"),
        "declared_categories": compliance_report.get("declared_categories", []),
        "policy_practices": compliance_report.get("policy_practices", []),
    }


def build_simple_report(privacy_inventory, compliance_report, policy_document=None):
    """Return one decision per distinct information type.

    The detailed practice comparator remains in ``compliance_report['results']``.
    This report is the clearer project-facing interpretation.
    """
    policy = policy_document or _legacy_policy_document(compliance_report)
    comparison = compare_information_types(privacy_inventory, policy)
    risks = _risk_signals(compliance_report.get("practice_risks", []))
    declarations = comparison["policy_declarations"]
    results = comparison["information_type_results"]
    observed = comparison["observed_information_types"]
    excluded = comparison["excluded_evidence"]

    return {
        "schema_version": "information-type-v1",
        "policy_review": comparison["policy_review"],
        "policy_declares": {
            "categories": _sorted_unique(policy.get("declared_categories", [])),
            "information_types": sorted(declarations),
            "declarations": [
                evidence
                for artifact in sorted(declarations)
                for evidence in declarations[artifact]
            ],
        },
        "traffic_transmits": observed,
        "information_type_results": results,
        "comparison": _group_results(results),
        "risk_signals": risks,
        "excluded_evidence": excluded,
        "non_attributable_outbound_findings": sum(
            item["occurrences"]
            for item in excluded
            if item["reason"] == "NON_ATTRIBUTABLE_TRAFFIC"
        ),
        "excluded_non_comparable_findings": sum(
            item["occurrences"]
            for item in excluded
            if item["reason"] == "NOT_COMPARABLE_CATEGORY"
        ),
        "capture_scoped_result": comparison["capture_scoped_result"],
        "result": comparison["capture_scoped_result"],
        "compliance_determination": "NOT DETERMINED",
        "methodology_note": (
            "Project-defined, capture-scoped comparison of distinct outbound "
            "information types against explicit reviewed policy statements; "
            "this is not a legal compliance determination."
        ),
    }


def _cell(value, limit=None):
    text = "-" if value is None or value == "" else str(value)
    text = text.replace("\n", " ")
    if limit and len(text) > limit:
        return text[: max(1, limit - 3)] + "..."
    return text


def _table(headers, rows, limits=None):
    """Render a dependency-free ASCII table that is stable in Windows terminals."""
    limits = limits or [None] * len(headers)
    normalized = [
        [_cell(value, limits[index]) for index, value in enumerate(row)]
        for row in rows
    ]
    widths = []
    for index, header in enumerate(headers):
        widths.append(
            max(
                len(header),
                *(len(row[index]) for row in normalized),
            )
        )

    border = "+-" + "-+-".join("-" * width for width in widths) + "-+"

    def render_row(row):
        return "| " + " | ".join(
            value.ljust(widths[index]) for index, value in enumerate(row)
        ) + " |"

    output = [border, render_row(headers), border]
    output.extend(render_row(row) for row in normalized)
    output.append(border)
    return output


def format_simple_report(report):
    """Format the project-facing result for the command-line interface."""
    review = report.get("policy_review", {})
    lines = [
        "Policy vs Observed Network Traffic",
        "",
        f"Policy review status: {review.get('status', 'REVIEW_INCOMPLETE')}",
    ]

    rows = []
    for item in report.get("information_type_results", []):
        observed = (item.get("occurrences") or 0) > 0
        policy_says = "YES" if item.get("policy_evidence") else (
            "NO" if item.get("status") == NOT_DISCLOSED else "UNCLEAR"
        )
        rows.append([
            item.get("artifact_type", "Unknown"),
            "YES" if observed else "NO",
            item.get("occurrences", 0),
            policy_says,
            DISPLAY_RESULTS.get(item.get("status"), item.get("status", "UNKNOWN")),
        ])

    lines.extend(["", "Information comparison"])
    if rows:
        lines.extend(_table(
            ["Information Type", "Observed", "Count", "In Policy", "Result"],
            rows,
            [24, 8, 8, 9, 25],
        ))
    else:
        lines.append("No comparable information types were found.")

    transmission_rows = []
    for item in report.get("traffic_transmits", []):
        transmission_rows.append([
            item.get("artifact_type", "Unknown"),
            ", ".join(item.get("locations", [])) or "unknown",
            ", ".join(item.get("destinations", [])) or "unknown",
        ])
    if transmission_rows:
        lines.extend(["", "Observed outbound transmission evidence"])
        lines.extend(_table(
            ["Information Type", "Network Location", "Destination"],
            transmission_rows,
            [24, 26, 54],
        ))

    lines.extend(["", "Separate transmission-risk signals"])
    risks = report.get("risk_signals", [])
    if not risks:
        lines.append("None detected. This does not mean every observed type was disclosed.")
    else:
        lines.extend(_table(
            ["Risk Signal", "Severity", "Evidence"],
            [
                [risk["title"], risk.get("severity") or "UNRATED", risk["evidence_count"]]
                for risk in risks
            ],
            [42, 10, 10],
        ))

    lines.extend([
        "",
        "Project result: " + DISPLAY_SUMMARIES.get(
            report.get("capture_scoped_result", RESULT_UNKNOWN),
            report.get("capture_scoped_result", RESULT_UNKNOWN),
        ),
        "Basis: observed outbound information types compared with the reviewed policy.",
        "Note: risk signals are a separate transmission-safety check.",
    ])
    return "\n".join(lines)
