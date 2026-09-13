from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class Request:
    """
    Represents one HTTP request and its corresponding response
    extracted from a HAR file.
    """

    # -----------------------------
    # Request information
    # -----------------------------
    method: str
    url: str
    domain: str
    status: int
    mime_type: str

    headers: Dict[str, str] = field(default_factory=dict)
    query_params: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    cookies: Dict[str, str] = field(default_factory=dict)

    # -----------------------------
    # Response information
    # -----------------------------
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_cookies: Dict[str, str] = field(default_factory=dict)
    response_body: Optional[str] = None

    # Response body metadata
    response_body_type: str = "text"
    response_body_encoding: Optional[str] = None
    response_content_type: str = ""

    # -----------------------------
    # Network metadata
    # -----------------------------
    server_ip: Optional[str] = None
    started_datetime: Optional[str] = None
    response_size: int = 0

    # -----------------------------
    # Analysis results
    # -----------------------------
    sensitive_data: List[dict] = field(default_factory=list)
    policy_match: Optional[bool] = None
    compliance_status: Optional[str] = None
    traffic_type: str = "Unknown"

    # -----------------------------
    # Request body metadata
    # -----------------------------
    body_type: str = "text"
    body_encoding: Optional[str] = None
    content_type: str = ""

    def __str__(self):
        return (
            f"{self.method:<6}"
            f"{self.domain:<35}"
            f"{self.status:<6}"
            f"{self.mime_type}"
        )