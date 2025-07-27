"""
ipinfo datamodels
API doc: https://ipinfo.io/developers
"""

from __future__ import annotations

import re
from typing import Dict

from pydantic import ConfigDict, model_validator

from wtfis.models.base import IpGeoAsnBase, IpGeoAsnMapBase


class IpInfo(IpGeoAsnBase):
    # Metadata
    source: str = "IPinfo"

    # Config
    model_config = ConfigDict(populate_by_name=True)

    @model_validator(mode="before")
    @classmethod
    def transforms(cls, v):
        # Extract ASN and Org from the org field
        regex = r"AS(\d+)\s+(.+)$"
        match = re.search(regex, v.get("org", ""))
        if match:
            v["asn"] = match.group(1)
            v["org"] = match.group(2).strip()

        # Generate URL to ipinfo.io
        v["link"] = f"https://ipinfo.io/{v['ip']}"

        return v


class IpInfoMap(IpGeoAsnMapBase):  # type: ignore[override]
    root: Dict[str, IpInfo]

    @classmethod
    def empty(cls) -> IpInfoMap:
        return cls.model_validate({})
