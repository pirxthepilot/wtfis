"""
ip2location datamodels
API doc: https://www.ip2location.io/ip2location-documentation
"""

from __future__ import annotations

from typing import Dict, Optional

from pydantic import ConfigDict, Field

from wtfis.models.base import IpGeoAsnBase, IpGeoAsnMapBase


class Ip2Location(IpGeoAsnBase):
    # Metadata
    source: str = "IP2Location"

    # Config
    model_config = ConfigDict(populate_by_name=True)

    # Results
    city: Optional[str] = Field(None, alias="city_name")
    region: Optional[str] = Field(None, alias="region_name")
    country: Optional[str] = Field(None, alias="country_name")
    org: Optional[str] = Field(None, alias="as")


class Ip2LocationMap(IpGeoAsnMapBase):  # type: ignore[override]
    root: Dict[str, Ip2Location]

    @classmethod
    def empty(cls) -> Ip2LocationMap:
        return cls.model_validate({})
