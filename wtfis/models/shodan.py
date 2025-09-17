from __future__ import annotations

import json
from collections import defaultdict, namedtuple
from typing import List, Optional

import msgspec

from .base import MapBase

# pylint: disable=too-few-public-methods


class PortData(msgspec.Struct, kw_only=True):  # type: ignore[call-arg]
    port: int
    product: Optional[str] = None
    transport: str


class ShodanIp(msgspec.Struct, kw_only=True):  # type: ignore[call-arg]
    asn: Optional[str] = None
    city: Optional[str] = None
    country_code: str
    country_name: str
    data: List[PortData]
    ip_str: str
    isp: Optional[str] = None
    last_update: str
    org: Optional[str] = None
    os: Optional[str] = None
    ports: Optional[List[int]] = None
    region_name: Optional[str] = None
    tags: Optional[List[str]] = None

    def group_ports_by_product(self) -> dict:
        PortProtocol = namedtuple("PortProtocol", "port transport")
        result = defaultdict(list)
        unknown = []  # Save ports with no product for adding later as last result item
        for port in self.data:
            port_data = PortProtocol(port.port, port.transport)
            if port.product:
                result[port.product].append(port_data)
            else:
                unknown.append(port_data)
        if unknown:
            result["Other"] = unknown
        return result

    @staticmethod
    def model_validate(d: dict) -> "ShodanIp":
        obj: ShodanIp = msgspec.json.decode(json.dumps(d), type=ShodanIp)
        return obj


ShodanIpMap = MapBase[ShodanIp]
