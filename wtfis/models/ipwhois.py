"""
ipwhois datamodels
API doc: https://ipwhois.io/documentation
"""

from __future__ import annotations

import json
from typing import Optional

import msgspec

from wtfis.models.base import IpGeoAsnBase, MapBase


def path2str(d: dict, *path) -> Optional[str]:
    "d[path0][path1]...[pathN] or None"
    v = None
    try:
        for p in path:
            v = d = d[p]
    except KeyError:
        v = None
    return str(v) if v else None


class IpWhois(IpGeoAsnBase):
    # Metadata
    source = "IPWhois"

    @staticmethod
    def model_validate(d: dict) -> "IpWhois":
        d["asn"] = path2str(d, "connection", "asn")
        d["org"] = path2str(d, "connection", "org")
        d["isp"] = path2str(d, "connection", "isp")
        d["domain"] = path2str(d, "connection", "domain")
        obj: IpWhois = msgspec.json.decode(json.dumps(d), type=IpWhois)
        return obj


IpWhoisMap = MapBase[IpWhois]
