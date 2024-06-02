"""
ipwhois datamodels
API doc: https://ipwhois.io/documentation
"""
from __future__ import annotations

from typing import Dict

from pydantic import AliasPath, Field

from wtfis.models.base import IpGeoAsnBase, IpGeoAsnMapBase


class IpWhois(IpGeoAsnBase):
    # Metadata
    source: str = "IPWhois"

    # Results
    ip: str
    city: str
    region: str
    country: str
    continent: str
    asn: str = Field(validation_alias=AliasPath("connection", "asn"))
    org: str = Field(validation_alias=AliasPath("connection", "org"))
    isp: str = Field(validation_alias=AliasPath("connection", "isp"))
    domain: str = Field(validation_alias=AliasPath("connection", "domain"))


class IpWhoisMap(IpGeoAsnMapBase):
    root: Dict[str, IpWhois]

    @classmethod
    def empty(cls) -> IpWhoisMap:
        return cls.model_validate({})
