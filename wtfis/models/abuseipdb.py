from __future__ import annotations

from typing import Dict, List, Optional

from pydantic import BaseModel, Field, RootModel


class AbuseIpDb(BaseModel):
    ip_address: str = Field(alias="ipAddress")
    is_public: Optional[bool] = Field(None, alias="isPublic")
    ip_version: Optional[int] = Field(None, alias="ipVersion")
    is_whitelisted: Optional[bool] = Field(None, alias="isWhitelisted")
    abuse_confidence_score: int = Field(alias="abuseConfidenceScore")
    country_code: Optional[str] = Field(None, alias="countryCode")
    usage_type: Optional[str] = Field(None, alias="usageType")
    isp: str
    domain: Optional[str] = None
    hostnames: Optional[List[str]] = None
    is_tor: Optional[bool] = Field(None, alias="isTor")
    total_reports: Optional[int] = Field(None, alias="totalReports")
    num_distinct_users: Optional[int] = Field(None, alias="numDistinctUsers")
    last_reported_at: Optional[str] = Field(None, alias="lastReportedAt")


class AbuseIpDbMap(RootModel):
    root: Dict[str, AbuseIpDb]

    @classmethod
    def empty(cls) -> AbuseIpDbMap:
        return cls.model_validate({})
