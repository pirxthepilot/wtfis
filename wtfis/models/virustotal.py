from pydantic import BaseModel, Field, RootModel, field_validator, model_validator
from typing import Any, Dict, List, Optional

from wtfis.models.common import LaxStr, WhoisBase


class BaseData(BaseModel):
    attributes: Any = None
    id_: str = Field(alias="id")
    type_: str = Field(alias="type")


class Meta(BaseModel):
    count: int


class AnalysisResult(BaseModel):
    category: str
    engine_name: str
    method: str
    result: str


class LastAnalysisResults(RootModel):
    root: Dict[str, AnalysisResult]


class LastAnalysisStats(BaseModel):
    harmless: int
    malicious: int
    suspicious: int
    timeout: int
    undetected: int


class Popularity(BaseModel):
    rank: int
    timestamp: int


class PopularityRanks(RootModel):
    root: Dict[str, Popularity]


class BaseAttributes(BaseModel):
    jarm: Optional[str] = None
    last_analysis_results: LastAnalysisResults
    last_analysis_stats: LastAnalysisStats
    last_https_certificate_date: Optional[int] = None
    last_modification_date: Optional[int] = None
    reputation: int
    tags: List[str]


class DomainAttributes(BaseAttributes):
    categories: List[str]
    creation_date: Optional[int] = None
    last_dns_records_date: Optional[int] = None
    last_update_date: Optional[int] = None
    popularity_ranks: PopularityRanks
    registrar: Optional[str] = None

    @field_validator("categories", mode="before")
    @classmethod
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
    asn: Optional[LaxStr] = None
    continent: Optional[str] = None
    country: Optional[str] = None
    network: Optional[str] = None


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
    domain: str = Field("", alias="Domain Name")
    registrar: Optional[str] = None
    organization: Optional[str] = Field(None, alias="Registrant Organization")
    name: Optional[str] = None
    email: Optional[str] = Field(None, alias="Registrant Email")
    phone: Optional[str] = Field(None, alias="Registrant Phone")
    street: Optional[str] = Field(None, alias="Registrant Street")
    city: Optional[str] = Field(None, alias="Registrant City")
    state: Optional[str] = Field(None, alias="Registrant State/Province")
    country: Optional[str] = None
    postal_code: Optional[str] = Field(None, alias="Registrant Postal Code")
    name_servers: List[str] = Field([], alias="Name Server")
    date_created: Optional[str] = None
    date_changed: Optional[LaxStr] = None
    date_expires: Optional[str] = None
    dnssec: Optional[str] = Field(None, alias="DNSSEC")

    @model_validator(mode="before")
    @classmethod
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

    @field_validator("name_servers", mode="before")
    @classmethod
    def transform_nameservers(cls, v):
        return v.lower().split(" | ")

    @field_validator("domain", mode="before")
    @classmethod
    def lowercase_domain(cls, v):
        return v.lower()

    @field_validator("*")
    @classmethod
    def dedupe_values(cls, v):
        if v is not None and "|" in v:
            return v.split(" | ")[0]
        return v
