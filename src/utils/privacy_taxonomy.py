"""
Privacy Taxonomy
Maps low-level runtime artifacts to high-level privacy concepts.
"""

PRIVACY_CATEGORY_MAP = {
    # --------------------------------------------------
    # Location
    # --------------------------------------------------
    "Latitude": "Location",
    "Longitude": "Location",
    "GPS": "Location",

    # --------------------------------------------------
    # Personal Information
    # --------------------------------------------------
    "Email": "Personal Information",
    "Phone": "Personal Information",
    "Username": "Personal Information",
    "Name": "Personal Information",
    "Date of Birth": "Personal Information",
    "Address": "Personal Information",

    # --------------------------------------------------
    # Authentication
    # --------------------------------------------------
    "Authorization Token": "Authentication",
    "Session Cookie": "Authentication",
    "Bearer Token": "Authentication",
    "Password": "Authentication",

    # --------------------------------------------------
    # API Credentials
    # --------------------------------------------------
    "API Key": "API Credentials",

    # --------------------------------------------------
    # Security
    # --------------------------------------------------
    "CSRF Token": "Security",

    # --------------------------------------------------
    # Device Identifier
    # --------------------------------------------------
    "Device ID": "Device Identifier",
    "Advertising ID": "Device Identifier",
    "Android ID": "Device Identifier",
    "IMEI": "Device Identifier",
    "IMSI": "Device Identifier",
    "MAC Address": "Device Identifier",

    # --------------------------------------------------
    # Network Information
    # --------------------------------------------------
    "IP Address": "Network Information",
}
