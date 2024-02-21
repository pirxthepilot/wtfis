from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, RootModel


class abuseIPDBIp(BaseModel):
    ipAddress: str
    isPublic: bool
    ipVersion: int
    isWhitelisted: Optional[bool] = None
    abuseConfidenceScore: int
    countryCode: Optional[str] = None
    countryName: Optional[str] = None
    usageType: Optional[str] = None
    isp: str
    domain: Optional[str] = None
    hostnames: Optional[list[str]] = None
    isTor: Optional[bool] = None
    totalReports: int
    numDistinctUsers: Optional[int] = None
    lastReportedAt: Optional[str] = None
    reports: Optional[list] = None


class abuseIPDBIpMap(RootModel):
    root: dict[str, abuseIPDBIp]

    @classmethod
    def empty(cls) -> abuseIPDBIpMap:
        return cls.model_validate({})
