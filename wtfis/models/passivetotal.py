from pydantic import Field, model_validator
from typing import List, Optional

from wtfis.models.common import WhoisBase


class Whois(WhoisBase):
    source: str = "passivetotal"
    registrar: Optional[str] = None
    organization: Optional[str] = None
    name: Optional[str] = None
    email: Optional[str] = Field(None, alias="contactEmail")
    phone: Optional[str] = Field(None, alias="telephone")
    street: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    country: Optional[str] = None
    postal_code: Optional[str] = Field(None, alias="postalCode")
    name_servers: List[str] = Field([], alias="nameServers")
    date_created: Optional[str] = Field(None, alias="registered")
    date_changed: Optional[str] = Field(None, alias="registryUpdatedAt")
    date_expires: Optional[str] = Field(None, alias="expiresAt")
    dnssec: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def extract_registrant(cls, v):
        registrant = v.pop("registrant")
        for field in ["telephone", "street", "city", "state", "country", "postalCode"]:
            v[field] = registrant.get(field)
        return v
