from collections import defaultdict, namedtuple
from pydantic import BaseModel
from typing import Dict, List, Optional


class PortData(BaseModel):
    port: int
    product: Optional[str]
    transport: str


class ShodanIp(BaseModel):
    asn: Optional[str]
    city: Optional[str]
    country_code: str
    country_name: str
    data: List[PortData]
    ip_str: str
    isp: Optional[str]
    last_update: str
    org: Optional[str]
    os: Optional[str]
    ports: Optional[List[int]]
    region_name: Optional[str]
    tags: Optional[List[str]]

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


class ShodanIpMap(BaseModel):
    __root__: Dict[str, ShodanIp]
