from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class Request:
    """
    Represents one HTTP request extracted from a HAR file.
    """

    method: str
    url: str
    domain: str
    status: int
    mime_type: str

    headers: Dict[str, str] = field(default_factory=dict)
    query_params: Dict[str, str] = field(default_factory=dict)

    body: Optional[str] = None
    cookies: Dict[str, str] = field(default_factory=dict)

    server_ip: Optional[str] = None
    started_datetime: Optional[str] = None
    response_size: int = 0

    # Will be populated later
    sensitive_data: List[dict] = field(default_factory=list)
    policy_match: Optional[bool] = None
    compliance_status: Optional[str] = None
    traffic_type: str = "Unknown"

    def __str__(self):

        return (
            f"{self.method:<6}"
            f"{self.domain:<35}"
            f"{self.status:<6}"
            f"{self.mime_type}"
        )