from pydantic import BaseModel, root_validator, validator
from typing import Any, Dict, List, Optional

from wtfis.models.common import WhoisBase


class BaseData(BaseModel):
    attributes: Any
    id_: str
    type_: str

    class Config:
        fields = {
            "id_": "id",
            "type_": "type",
        }


class Meta(BaseModel):
    count: int


class AnalysisResult(BaseModel):
    category: str
    engine_name: str
    method: str
    result: str


class LastAnalysisResults(BaseModel):
    __root__: Dict[str, AnalysisResult]


class LastAnalysisStats(BaseModel):
    harmless: int
    malicious: int
    suspicious: int
    timeout: int
    undetected: int


class Popularity(BaseModel):
    rank: int
    timestamp: int


class PopularityRanks(BaseModel):
    __root__: Dict[str, Popularity]


class BaseAttributes(BaseModel):
    jarm: Optional[str]
    last_analysis_results: LastAnalysisResults
    last_analysis_stats: LastAnalysisStats
    last_https_certificate_date: Optional[int]
    last_modification_date: Optional[int]
    reputation: int
    tags: List[str]


class DomainAttributes(BaseAttributes):
    categories: List[str]
    creation_date: Optional[int]
    last_dns_records_date: Optional[int]
    last_update_date: Optional[int]
    popularity_ranks: PopularityRanks
    registrar: Optional[str]

    @validator("categories", pre=True)
    def transform_categories(cls, v):
        cats = set()
        for category in v.values():
            for delimiter in [", ", ",", "/", " / "]:
                if delimiter in category:
                    cats = cats | set(category.lower().split(delimiter))
                    break
            else:
                cats.add(category.lower())
        return sorted(cats)


class DomainData(BaseData):
    attributes: DomainAttributes


class Domain(BaseModel):
    data: DomainData


class IpAttributes(BaseAttributes):
    asn: Optional[int]
    continent: Optional[str]
    country: Optional[str]
    network: Optional[str]


class IpData(BaseData):
    attributes: IpAttributes


class IpAddress(BaseModel):
    data: IpData


class ResolutionAttributes(BaseModel):
    date: int
    host_name: str
    resolver: str
    ip_address_last_analysis_stats: LastAnalysisStats
    ip_address: str
    host_name_last_analysis_stats: LastAnalysisStats


class ResolutionData(BaseData):
    attributes: ResolutionAttributes


class Resolutions(BaseModel):
    meta: Meta
    data: List[ResolutionData]


class Whois(WhoisBase):
    source: str = "virustotal"
    domain: str = ""
    registrar: Optional[str]
    organization: Optional[str]
    name: Optional[str]
    email: Optional[str]
    phone: Optional[str]
    street: Optional[str]
    city: Optional[str]
    state: Optional[str]
    country: Optional[str]
    postal_code: Optional[str]
    name_servers: List[str] = []
    date_created: Optional[str]
    date_changed: Optional[str]
    date_expires: Optional[str]
    dnssec: Optional[str]

    class Config:
        fields = {
            "domain": "Domain Name",
            "organization": "Registrant Organization",
            "email": "Registrant Email",
            "phone": "Registrant Phone",
            "street": "Registrant Street",
            "city": "Registrant City",
            "state": "Registrant State/Province",
            "postal_code": "Registrant Postal Code",
            "name_servers": "Name Server",
            "dnssec": "DNSSEC",
        }

    @root_validator(pre=True)
    def get_latest_whois_record_and_transform(cls, v):
        data = v.pop("data")
        if not data:
            return {}
        transformed = data[0].get("attributes", {})

        # Flatten
        transformed = {**transformed.pop("whois_map"), **transformed}

        # Normalized fields with multiple possible sources
        fields_w_multiple_possible_sources = {
            "date_changed": (
                transformed.pop("last_updated", None) or
                transformed.pop("Updated Date", None) or
                transformed.pop("Last updated", None)
            ),
            "date_created": (
                transformed.pop("Creation Date", None) or
                transformed.pop("Registered on", None)
            ),
            "date_expires": (
                transformed.pop("Expiry Date", None) or
                transformed.pop("Registry Expiry Date", None) or
                transformed.pop("Expiry date", None)
            ),
            "name": (
                transformed.pop("registrant_name", None) or
                transformed.pop("Registrant Name", None)
            ),
            "country": (
                transformed.pop("registrant_country", None) or
                transformed.pop("Registrant Country", None)
            ),
            "registrar": (
                transformed.pop("registrar_name", None) or
                transformed.pop("Registrar", None)
            ),
        }

        return {**transformed, **fields_w_multiple_possible_sources}

    @validator("name_servers", pre=True)
    def transform_nameservers(cls, v):
        return v.lower().split(" | ")

    @validator("domain", pre=True)
    def lowercase_domain(cls, v):
        return v.lower()

    @validator("*")
    def dedupe_values(cls, v):
        if v is not None and "|" in v:
            return v.split(" | ")[0]
        return v
