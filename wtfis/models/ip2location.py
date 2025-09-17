"""
ip2location datamodels
API doc: https://www.ip2location.io/ip2location-documentation
"""

from __future__ import annotations

import json
from typing import Optional

import msgspec

from wtfis.models.base import IpGeoAsnBase, MapBase

# pylint: disable=too-few-public-methods


class Ip2Location(IpGeoAsnBase):
    # Metadata
    source = "IP2Location"

    # Results
    city: Optional[str] = msgspec.field(name="city_name", default=None)
    region: Optional[str] = msgspec.field(name="region_name", default=None)
    country: Optional[str] = msgspec.field(name="country_name", default=None)
    org: Optional[str] = msgspec.field(name="as", default=None)

    @staticmethod
    def model_validate(d: dict) -> "Ip2Location":
        obj: Ip2Location = msgspec.json.decode(json.dumps(d), type=Ip2Location)
        return obj


Ip2LocationMap = MapBase[Ip2Location]
