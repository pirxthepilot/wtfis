"""
ipwhois datamodels
API doc: https://ipwhois.io/documentation
"""

from __future__ import annotations

from typing import Dict, Optional

from pydantic import AliasPath, ConfigDict, Field

from wtfis.models.base import IpGeoAsnBase, IpGeoAsnMapBase


class IpWhois(IpGeoAsnBase):
    # Metadata
    source: str = "IPWhois"

    # Config
    model_config = ConfigDict(populate_by_name=True)

    # Results
    ip: str
    city: str
    region: str
    country: str
    asn: str = Field(validation_alias=AliasPath("connection", "asn"))
    org: str = Field(validation_alias=AliasPath("connection", "org"))
    isp: str = Field(validation_alias=AliasPath("connection", "isp"))
    domain: str = Field(validation_alias=AliasPath("connection", "domain"))
    is_proxy: Optional[bool] = None


class IpWhoisMap(IpGeoAsnMapBase):  # type: ignore[override]
    root: Dict[str, IpWhois]

    @classmethod
    def empty(cls) -> IpWhoisMap:
        return cls.model_validate({})
