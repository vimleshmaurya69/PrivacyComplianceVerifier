"""
Privacy Taxonomy
Maps low-level runtime artifacts to high-level privacy concepts.
"""

PRIVACY_CATEGORY_MAP = {
    "Latitude": "Location",
    "Longitude": "Location",
    "GPS": "Location",

    "Email": "Personal Information",
    "Phone": "Personal Information",
    "Username": "Personal Information",
    "Password": "Personal Information",

    "Authorization Token": "Authentication",
    "Session Cookie": "Authentication",
    "Bearer Token": "Authentication",

    "API Key": "API Credentials",

    "Device ID": "Device Identifier",
    "Advertising ID": "Device Identifier",
    "Android ID": "Device Identifier",
    "IMEI": "Device Identifier",
    "IMSI": "Device Identifier",
    "MAC Address": "Device Identifier",

    "IP Address": "Network Information",
}