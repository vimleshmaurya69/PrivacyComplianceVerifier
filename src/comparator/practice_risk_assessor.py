"""Conservative practice-level risks derived from observed network evidence.

These findings are not policy mismatches by themselves.  They identify network
practices that need a more specific policy/security review than category
presence can provide.
"""

URL_SOURCES = {"Query Parameter", "URL Path"}
HIGH_RISK_URL_CATEGORIES = {
    "Authentication",
    "API Credentials",
    "Security",
}
PERSONAL_DATA_URL_CATEGORIES = {
    "Personal Information",
    "Device Identifier",
    "Network Information",
    "Location",
}
THIRD_PARTY_PERSONAL_TYPES = {
    "Address",
    "Date of Birth",
    "Email",
    "Name",
    "Phone",
}
THIRD_PARTY_IDENTIFIER_TYPES = {"Device ID", "User ID"}
THIRD_PARTY_LOCATION_TYPES = {"Latitude", "Longitude", "Location"}


def assess_practice_risks(evidence):
    """Return bounded, evidence-backed practice risks.

    No risk is called non-compliance here: policy purpose, recipient, and
    contextual necessity cannot be inferred reliably from a HAR alone.
    """
    credential_evidence = []
    personal_data_evidence = []
    installed_app_evidence = []
    search_url_evidence = []
    third_party_search_evidence = []
    third_party_location_evidence = []
    third_party_personal_evidence = []
    third_party_identifier_evidence = []

    for finding in evidence:
        if not isinstance(finding, dict):
            continue
        if finding.get("direction") != "outbound":
            continue
        artifact_type = finding.get("artifact_type")
        if finding.get("traffic_type") == "Third Party":
            if artifact_type in THIRD_PARTY_LOCATION_TYPES:
                third_party_location_evidence.append(finding)
            elif artifact_type in THIRD_PARTY_PERSONAL_TYPES:
                third_party_personal_evidence.append(finding)
            elif artifact_type in THIRD_PARTY_IDENTIFIER_TYPES:
                third_party_identifier_evidence.append(finding)
        if artifact_type == "Installed Application List":
            installed_app_evidence.append(finding)
        if artifact_type == "Search Query":
            if finding.get("source") in URL_SOURCES:
                search_url_evidence.append(finding)
            if (
                finding.get("traffic_type") == "Third Party"
                and finding.get("cross_domain_match") is True
            ):
                third_party_search_evidence.append(finding)
        if finding.get("source") not in URL_SOURCES:
            continue
        category = finding.get("observed_category")
        if category in HIGH_RISK_URL_CATEGORIES:
            credential_evidence.append(finding)
        elif category in PERSONAL_DATA_URL_CATEGORIES:
            personal_data_evidence.append(finding)

    risks = []
    if credential_evidence:
        risks.append({
            "type": "CREDENTIAL_IN_URL",
            "status": "REVIEW REQUIRED",
            "severity": "HIGH",
            "explanation": (
                "An authentication, API, or security credential was observed "
                "in an outbound URL. URLs can be retained in logs and history."
            ),
            "evidence": credential_evidence,
        })
    if personal_data_evidence:
        risks.append({
            "type": "PERSONAL_DATA_IN_URL",
            "status": "REVIEW REQUIRED",
            "severity": "MEDIUM",
            "explanation": (
                "Personal, device, network, or location data was observed in "
                "an outbound URL. Policy disclosure alone does not establish "
                "that this channel, recipient, or purpose is appropriate."
            ),
            "evidence": personal_data_evidence,
        })
    if installed_app_evidence:
        risks.append({
            "type": "INSTALLED_APP_LIST_TRANSMITTED",
            "status": "REVIEW REQUIRED",
            "severity": "HIGH",
            "explanation": (
                "A structured list of installed application package identifiers "
                "was observed in outbound traffic. This can reveal other apps "
                "used on the device and requires a specific privacy review."
            ),
            "evidence": installed_app_evidence,
        })
    if search_url_evidence:
        risks.append({
            "type": "SEARCH_ACTIVITY_IN_URL",
            "status": "REVIEW REQUIRED",
            "severity": "MEDIUM",
            "explanation": (
                "User search activity was observed in an outbound URL. URLs "
                "can be retained in logs, histories, and intermediary systems."
            ),
            "evidence": search_url_evidence,
        })
    if third_party_search_evidence:
        risks.append({
            "type": "SEARCH_ACTIVITY_SHARED_WITH_THIRD_PARTY",
            "status": "REVIEW REQUIRED",
            "severity": "HIGH",
            "explanation": (
                "The exact search value observed in application traffic was "
                "also observed in outbound traffic to a classified third-party "
                "destination."
            ),
            "evidence": third_party_search_evidence,
        })
    if third_party_location_evidence:
        risks.append({
            "type": "PRECISE_LOCATION_SHARED_WITH_THIRD_PARTY",
            "status": "REVIEW REQUIRED",
            "severity": "HIGH",
            "explanation": (
                "Precise location evidence was observed in outbound traffic "
                "to a classified third-party destination. This is a "
                "transmission-risk signal, not a policy violation by itself."
            ),
            "evidence": third_party_location_evidence,
        })
    if third_party_personal_evidence:
        risks.append({
            "type": "PERSONAL_DATA_SHARED_WITH_THIRD_PARTY",
            "status": "REVIEW REQUIRED",
            "severity": "MEDIUM",
            "explanation": (
                "Contact or identity data was observed in outbound traffic "
                "to a classified third-party destination. Policy coverage, "
                "necessity, and consent require separate review."
            ),
            "evidence": third_party_personal_evidence,
        })
    if third_party_identifier_evidence:
        risks.append({
            "type": "PERSISTENT_IDENTIFIER_SHARED_WITH_THIRD_PARTY",
            "status": "REVIEW REQUIRED",
            "severity": "MEDIUM",
            "explanation": (
                "A user or device identifier was observed in outbound traffic "
                "to a classified third-party destination. This is reported "
                "separately from the policy-disclosure decision."
            ),
            "evidence": third_party_identifier_evidence,
        })
    return risks
