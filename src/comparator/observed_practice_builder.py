"""Derive conservative observed practices from privacy-inventory evidence."""

from src.comparator.semantic_category_mapping import policy_category_for_observed


COMPARISON_TRAFFIC_TYPES = {"Application", "Third Party"}
TRAFFIC_RECIPIENT_SCOPE = {
    "Application": "application",
    "Third Party": "third_party",
}
VALID_POLICY_RECIPIENT_SCOPES = {
    "first_party",
    "third_party",
    "service_provider",
}
URL_SOURCES = {"Query Parameter", "URL Path"}
HIGH_RISK_URL_CATEGORIES = {"Authentication", "API Credentials", "Security"}
PERSONAL_DATA_URL_CATEGORIES = {
    "Personal Information",
    "Device Identifier",
    "Network Information",
    "Location",
}


def _risk_flags(category, source, direction):
    if direction != "outbound" or source not in URL_SOURCES:
        return []
    if category in HIGH_RISK_URL_CATEGORIES:
        return ["CREDENTIAL_IN_URL"]
    if category in PERSONAL_DATA_URL_CATEGORIES:
        return ["PERSONAL_DATA_IN_URL"]
    return []


def _explicit_policy_scope(finding):
    """Use policy recipient scope only with explicit verified justification."""
    scope = finding.get("policy_recipient_scope")
    justification = finding.get("recipient_scope_justification")
    if (
        scope in VALID_POLICY_RECIPIENT_SCOPES
        and isinstance(justification, dict)
        and justification.get("verified") is True
    ):
        return scope, dict(justification)
    return "unknown", None


class ObservedPracticeBuilder:
    """Build grouped comparison practices without changing inventory evidence."""

    def __init__(self, inventory):
        self.inventory = inventory if isinstance(inventory, dict) else {}

    def build(self):
        grouped = {}

        for traffic_type, section in self.inventory.items():
            if traffic_type not in COMPARISON_TRAFFIC_TYPES:
                continue
            if not isinstance(section, dict):
                continue

            findings = section.get("evidence", [])
            if not isinstance(findings, list):
                continue

            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                direction = finding.get("direction")
                # Missing direction is not evidence of outbound transmission.
                # Current inventories preserve direction explicitly; older or
                # external inventories remain visible as evidence but cannot
                # enter automatic network-practice comparison.
                if direction != "outbound":
                    continue

                category = finding.get("privacy_category")
                policy_category = policy_category_for_observed(category)
                if not policy_category:
                    continue

                artifact_type = finding.get("type")
                if not artifact_type:
                    continue

                source = finding.get("source")
                domain = finding.get("domain")
                action = "transmit"
                traffic_scope = TRAFFIC_RECIPIENT_SCOPE.get(
                    traffic_type, "unknown"
                )
                policy_scope, scope_justification = _explicit_policy_scope(finding)

                identity = (
                    policy_category,
                    artifact_type,
                    action,
                    traffic_scope,
                    policy_scope,
                    domain,
                    source,
                )
                practice = grouped.get(identity)
                if practice is None:
                    practice = {
                        "practice_id": None,
                        "privacy_category": policy_category,
                        "observed_category": category,
                        "artifact_type": artifact_type,
                        "action": action,
                        "network_direction": "outbound",
                        "traffic_recipient_scope": traffic_scope,
                        "policy_recipient_scope": policy_scope,
                        "recipient_scope_justification": scope_justification,
                        "recipient_domain": domain,
                        "request_location": source,
                        "keys": [],
                        "risk_flags": [],
                        "occurrence_count": 0,
                        "evidence": [],
                    }
                    grouped[identity] = practice

                key = finding.get("key")
                if key is not None and key not in practice["keys"]:
                    practice["keys"].append(key)
                for flag in _risk_flags(category, source, "outbound"):
                    if flag not in practice["risk_flags"]:
                        practice["risk_flags"].append(flag)

                practice["occurrence_count"] += 1
                practice["evidence"].append({
                    "observed_category": category,
                    "artifact_type": artifact_type,
                    "source": source,
                    "direction": finding.get("direction"),
                    "key": key,
                    "domain": domain,
                    "traffic_type": traffic_type,
                })

        practices = sorted(
            grouped.values(),
            key=lambda item: (
                item["privacy_category"],
                item["artifact_type"],
                item["traffic_recipient_scope"],
                item.get("recipient_domain") or "",
                item.get("request_location") or "",
            ),
        )
        for index, practice in enumerate(practices, 1):
            practice["practice_id"] = f"observed-{index}"
            practice["keys"].sort(key=str)
        return practices
