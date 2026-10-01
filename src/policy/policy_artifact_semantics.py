"""Conservative artifact semantics for policy evidence.

Privacy policies usually name information in prose rather than detector labels.
This module recognizes only explicit, bounded aliases from existing policy
evidence. It does not infer artifacts from purposes, HAR observations, or a
broad privacy category alone.
"""

import re


GENERIC_ARTIFACT_MEMBERS = {
    "Location": {"Location", "Latitude", "Longitude", "GPS"},
    "Device Identifier": {
        "Device Identifier",
        "Device ID",
        "Advertising ID",
        "Android ID",
        "IMEI",
        "IMSI",
        "MAC Address",
    },
}


def _text(value):
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple, set)):
        return " ".join(_text(item) for item in value)
    if isinstance(value, dict):
        return " ".join(_text(item) for item in value.values())
    return ""


def extract_explicit_policy_artifacts(value, category=None):
    """Extract detector-facing artifacts explicitly named in policy prose."""
    text = _text(value).lower()
    if not text:
        return []

    artifacts = []

    def add(artifact):
        if artifact not in artifacts:
            artifacts.append(artifact)

    # Specific compound terms must be recognized before their components.
    if re.search(r"\bip(?:v[46])?\s+address(?:es)?\b", text):
        add("IP Address")
    if re.search(r"\b(?:e-?mail)(?:\s+address(?:es)?)?\b", text):
        add("Email")
    if re.search(
        r"\b(?:phone|telephone)(?:\s+number(?:s)?)?\b"
        r"|\bmobile\s+(?:phone(?:\s+number(?:s)?)?|number(?:s)?)\b",
        text,
    ):
        add("Phone")
    if re.search(r"\buser\s*name(?:s)?\b|\busername(?:s)?\b", text):
        add("Username")
    if re.search(r"\b(?:first|last|full|profile|display)\s+name(?:s)?\b", text):
        add("Name")
    elif re.search(r"\bname(?:s)?\b", text) and category == "Personal Information":
        add("Name")
    if re.search(r"\b(?:date of birth|birth date|dob)\b", text):
        add("Date of Birth")
    if re.search(r"\b(?:user|account)\s+(?:id|identifier)(?:s)?\b", text):
        add("User ID")

    address_text = re.sub(
        r"\b(?:e-?mail|ip(?:v[46])?|web)\s+address(?:es)?\b", "", text
    )
    if re.search(
        r"\b(?:street|postal|mailing|home|business)?\s*address(?:es)?\b",
        address_text,
    ):
        add("Address")

    if re.search(r"\badvertising\s+(?:id|identifier)(?:s)?\b", text):
        add("Advertising ID")
    if re.search(r"\bandroid\s+id\b", text):
        add("Android ID")
    if re.search(r"\bimei\b", text):
        add("IMEI")
    if re.search(r"\bimsi\b", text):
        add("IMSI")
    if re.search(r"\bmac\s+address\b", text):
        add("MAC Address")
    if re.search(r"\bdevice\s+(?:id|ids)\b", text):
        add("Device ID")
    if re.search(
        r"\b(?:device|unique|online|mobile application)\s+identifier(?:s)?\b",
        text,
    ):
        add("Device Identifier")

    if category == "Location" and re.search(
        r"\b(?:geo-?location|location|gps|latitude|longitude|coordinates?)\b",
        text,
    ):
        add("Location")

    if re.search(r"\bauthorization\s+token\b|\baccess\s+token\b", text):
        add("Authorization Token")
    if re.search(r"\bbearer\s+token\b", text):
        add("Bearer Token")
    if re.search(r"\bsession\s+cookie\b", text):
        add("Session Cookie")
    if re.search(r"\bpassword(?:s)?\b", text):
        add("Password")

    return artifacts


def policy_artifacts(practice):
    explicit = list(practice.get("artifact_types", []))
    if explicit:
        return explicit
    legacy = practice.get("legacy_evidence", {})
    return extract_explicit_policy_artifacts(
        legacy.get("data_type"), practice.get("privacy_category")
    )


def artifact_matches(observed_artifact, practice):
    """Return the matching policy artifact label, or ``None``."""
    for policy_artifact in policy_artifacts(practice):
        if observed_artifact == policy_artifact:
            return policy_artifact
        members = GENERIC_ARTIFACT_MEMBERS.get(policy_artifact, set())
        if observed_artifact in members:
            return policy_artifact
    return None
