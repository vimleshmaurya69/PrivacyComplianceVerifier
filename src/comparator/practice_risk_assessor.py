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


def assess_practice_risks(evidence):
    """Return bounded, evidence-backed practice risks.

    No risk is called non-compliance here: policy purpose, recipient, and
    contextual necessity cannot be inferred reliably from a HAR alone.
    """
    credential_evidence = []
    personal_data_evidence = []

    for finding in evidence:
        if not isinstance(finding, dict):
            continue
        if finding.get("direction") != "outbound":
            continue
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
    return risks
