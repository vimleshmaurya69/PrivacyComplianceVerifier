"""Semantic boundary between observed runtime categories and policy categories."""

# Only these pairs are approved for automatic compliance comparison.
EXACT_CATEGORY_MAPPINGS = {
    "Location": "Location",
    "Personal Information": "Personal Information",
    "Authentication": "Authentication",
    "Device Identifier": "Device Identifier",
    "Network Information": "Network Information",
    "Contacts": "Contacts",
}

# These runtime findings remain evidence, but have no policy category that is
# approved for direct privacy-disclosure comparison.
NON_COMPARABLE_OBSERVED_CATEGORIES = {
    "API Credentials",
    "Security",
    "Unknown",
}

# Retained as design documentation only.  These pairs must never be used as
# automatic equivalences.
INFORMATIONAL_ONLY_RELATIONSHIPS = {
    ("Device Identifier", "Device Information"),
    ("Authentication", "Passwords"),
    ("Authentication", "Cookies"),
    ("Security", "Authentication"),
    ("API Credentials", "Authentication"),
}


def policy_category_for_observed(observed_category):
    """Return the policy category only when an exact mapping is approved."""
    return EXACT_CATEGORY_MAPPINGS.get(observed_category)


def comparable_policy_categories(observed_categories):
    """Map comparable observed categories into the policy vocabulary."""
    return {
        policy_category
        for category in observed_categories
        if (policy_category := policy_category_for_observed(category))
    }


def is_automatically_comparable_policy_category(policy_category):
    """Whether HAR evidence can participate in automatic comparison."""
    return policy_category in set(EXACT_CATEGORY_MAPPINGS.values())
