"""
ipinfo datamodels
API doc: https://ipinfo.io/developers
"""

from __future__ import annotations

import json
import re
from typing import Optional

import msgspec

from wtfis.models.base import IpGeoAsnBase, MapBase

# pylint: disable=too-few-public-methods


class IpInfo(IpGeoAsnBase, kw_only=True, dict=True):  # type: ignore[call-arg]  # https://github.com/python/mypy/issues/11036
    # Metadata
    source = "IPinfo"

    # Other
    _is_anycast: Optional[bool] = msgspec.field(name="anycast", default=None)

    @staticmethod
    def model_validate(v: dict) -> "IpInfo":
        # Extract ASN and Org from the org field
        regex = r"AS(\d+)\s+(.+)$"
        match = re.search(regex, v.get("org", ""))
        if match:
            v["asn"] = match.group(1)
            v["org"] = match.group(2).strip()

        # Generate URL to ipinfo.io
        v["link"] = f"https://ipinfo.io/{v['ip']}"

        obj: IpInfo = msgspec.json.decode(json.dumps(v), type=IpInfo)
        return obj


IpInfoMap = MapBase[IpInfo]
