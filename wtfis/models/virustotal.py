import json
from datetime import datetime, timezone
from functools import cached_property
from typing import Any, Dict, List, Optional, Set, Union

import msgspec

from wtfis.models.base import WhoisBase

# pylint: disable=too-few-public-methods


class BaseData(msgspec.Struct, kw_only=True):  # type: ignore[call-arg]
    attributes: Any = None
    id_: str = msgspec.field(name="id")
    type_: str = msgspec.field(name="type")


class Meta(msgspec.Struct):
    count: int


class AnalysisResult(msgspec.Struct):
    category: str
    engine_name: str
    method: str
    result: str


LastAnalysisResults = Dict[str, AnalysisResult]


class LastAnalysisStats(msgspec.Struct):
    harmless: int
    malicious: int
    suspicious: int
    timeout: int
    undetected: int


class Popularity(msgspec.Struct):
    rank: int
    timestamp: int


PopularityRanks = Dict[str, Popularity]


class BaseAttributes(msgspec.Struct, kw_only=True):  # type: ignore[call-arg]
    jarm: Optional[str] = None
    last_analysis_results: LastAnalysisResults
    last_analysis_stats: LastAnalysisStats
    last_https_certificate_date: Optional[int] = None
    last_modification_date: Optional[int] = None
    reputation: int
    tags: List[str]


class DomainAttributes(BaseAttributes, kw_only=True, dict=True):  # type: ignore[call-arg]
    _categories: Dict[str, str] = msgspec.field(name="categories")
    creation_date: Optional[int] = None
    last_dns_records_date: Optional[int] = None
    last_update_date: Optional[int] = None
    popularity_ranks: PopularityRanks
    registrar: Optional[str] = None

    @cached_property
    def categories(self) -> List[str]:
        cats: Set[str] = set()
        for category in self._categories.values():
            for delimiter in [", ", ",", "/", " / "]:
                if delimiter in category:
                    cats = cats | set(category.lower().split(delimiter))
                    break
            else:
                cats.add(category.lower())
        return sorted(cats)


class DomainData(BaseData):
    attributes: DomainAttributes


class Domain(msgspec.Struct):
    data: DomainData

    @staticmethod
    def model_validate(d: dict) -> "Domain":
        obj: Domain = msgspec.json.decode(json.dumps(d), type=Domain)
        return obj


class IpAttributes(BaseAttributes, dict=True):  # type: ignore[call-arg]
    _asn: Optional[int] = msgspec.field(name="asn", default=None)
    continent: Optional[str] = None
    country: Optional[str] = None
    network: Optional[str] = None

    @cached_property
    def asn(self) -> Optional[str]:
        return str(self._asn) if self._asn else None


class IpData(BaseData):
    attributes: IpAttributes


class IpAddress(msgspec.Struct):
    data: IpData

    @staticmethod
    def model_validate(d: dict) -> "IpAddress":
        obj: IpAddress = msgspec.json.decode(json.dumps(d), type=IpAddress)
        return obj


class ResolutionAttributes(msgspec.Struct):
    date: int
    host_name: str
    resolver: str
    ip_address_last_analysis_stats: LastAnalysisStats
    ip_address: str
    host_name_last_analysis_stats: LastAnalysisStats


class ResolutionData(BaseData):
    attributes: ResolutionAttributes


class Resolutions(msgspec.Struct):
    meta: Meta
    data: List[ResolutionData]

    def ip_list(self, limit: int) -> List[str]:
        """
        IP list from the first n resolutions
        where n is defined by the limit
        """
        ips = []
        for idx, resolution in enumerate(self.data):
            if idx < limit:
                ips.append(resolution.attributes.ip_address)
        return ips

    @staticmethod
    def model_validate(d: dict) -> "Resolutions":
        obj: Resolutions = msgspec.json.decode(json.dumps(d), type=Resolutions)
        return obj


class WhoisMsg(msgspec.Struct):
    domain: str = msgspec.field(name="Domain Name", default="")

    registrar1: str = msgspec.field(name="registrar_name", default="")
    registrar2: str = msgspec.field(name="Registrar", default="")

    organization: Optional[str] = msgspec.field(
        name="Registrant Organization", default=None
    )

    name1: Optional[str] = msgspec.field(name="registrant_name", default=None)
    name2: Optional[str] = msgspec.field(name="Registrant Name", default=None)

    email: Optional[str] = msgspec.field(name="Registrant Email", default=None)
    phone: Optional[str] = msgspec.field(name="Registrant Phone", default=None)
    street: Optional[str] = msgspec.field(name="Registrant Street", default=None)
    city: Optional[str] = msgspec.field(name="Registrant City", default=None)
    state: Optional[str] = msgspec.field(name="Registrant State/Province", default=None)

    country1: Optional[str] = msgspec.field(name="registrant_country", default=None)
    country2: Optional[str] = msgspec.field(name="Registrant Country", default=None)

    postal_code: Optional[str] = msgspec.field(
        name="Registrant Postal Code", default=None
    )
    name_server: Optional[str] = msgspec.field(name="Name Server", default=None)

    date_created1: Optional[str] = msgspec.field(name="Creation Date", default=None)
    date_created2: Optional[str] = msgspec.field(name="Registered on", default=None)

    date_changed1: Optional[int] = msgspec.field(name="last_updated", default=None)
    date_changed2: Optional[str] = msgspec.field(name="Updated Date", default=None)
    date_changed3: Optional[str] = msgspec.field(name="Last updated", default=None)

    date_expires1: Optional[str] = msgspec.field(name="Expiry Date", default=None)
    date_expires2: Optional[str] = msgspec.field(
        name="Registry Expiry Date", default=None
    )
    date_expires3: Optional[str] = msgspec.field(name="Expiry date", default=None)

    dnssec: Optional[str] = msgspec.field(name="DNSSEC", default=None)


def int2time2str(x: Union[int, str, None]) -> Union[str, None]:
    if isinstance(x, int):
        dt = datetime.fromtimestamp(x, timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    return x


def dedupe_values(v: Union[str, None]) -> Union[str, None]:
    if v and "|" in v:
        return v.split(" | ")[0]
    return v


class Whois(WhoisBase):
    source = "virustotal"

    @staticmethod
    def model_validate(d: dict) -> "Whois":
        try:
            transformed = d["data"][0]["attributes"]
        except (KeyError, IndexError):
            transformed = {}
        # Flatten
        transformed = {**transformed.get("whois_map", {}), **transformed}

        obj: WhoisMsg = msgspec.json.decode(json.dumps(transformed), type=WhoisMsg)
        whois = Whois()
        # copy fields
        whois.domain = dedupe_values(obj.domain.lower())
        whois.registrar = obj.registrar1 or obj.registrar2
        whois.organization = obj.organization
        whois.name = obj.name1 or obj.name2
        whois.email = obj.email
        whois.phone = obj.phone
        whois.street = obj.street
        whois.city = obj.city
        whois.state = obj.state
        whois.country = obj.country1 or obj.country2
        whois.postal_code = obj.postal_code
        if v := obj.name_server:
            whois.name_servers = v.lower().split(" | ")
        else:
            whois.name_servers = []
        whois.date_created = obj.date_created1 or obj.date_created2
        whois.date_changed = int2time2str(
            obj.date_changed1 or obj.date_changed2 or obj.date_changed3
        )
        whois.date_expires = obj.date_expires1 or obj.date_expires2 or obj.date_expires3
        whois.dnssec = obj.dnssec
        return whois
