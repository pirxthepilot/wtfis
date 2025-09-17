from __future__ import annotations

import json
from typing import List, Optional

import msgspec

from .base import MapBase

# pylint: disable=too-few-public-methods


class AbuseIpDb(msgspec.Struct, kw_only=True):  # type: ignore[call-arg]
    ip_address: str = msgspec.field(name="ipAddress")
    is_public: Optional[bool] = msgspec.field(name="isPublic", default=None)
    ip_version: Optional[int] = msgspec.field(name="ipVersion", default=None)
    is_whitelisted: Optional[bool] = msgspec.field(name="isWhitelisted", default=None)
    abuse_confidence_score: int = msgspec.field(name="abuseConfidenceScore")
    country_code: Optional[str] = msgspec.field(name="countryCode", default=None)
    usage_type: Optional[str] = msgspec.field(name="usageType", default=None)
    isp: str
    domain: Optional[str] = None
    hostnames: Optional[List[str]] = None
    is_tor: Optional[bool] = msgspec.field(name="isTor", default=None)
    total_reports: Optional[int] = msgspec.field(name="totalReports", default=None)
    num_distinct_users: Optional[int] = msgspec.field(
        name="numDistinctUsers", default=None
    )
    last_reported_at: Optional[str] = msgspec.field(name="lastReportedAt", default=None)

    @staticmethod
    def model_validate(d: dict) -> "AbuseIpDb":
        obj: AbuseIpDb = msgspec.json.decode(json.dumps(d), type=AbuseIpDb)
        return obj


AbuseIpDbMap = MapBase[AbuseIpDb]
