from pydantic import root_validator
from typing import List, Optional

from wtfis.models.common import WhoisBase


class Whois(WhoisBase):
    source: str = "passivetotal"
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
            "email": "contactEmail",
            "phone": "telephone",
            "name_servers": "nameServers",
            "postal_code": "postalCode",
            "date_created": "registered",
            "date_changed": "registryUpdatedAt",
            "date_expires": "expiresAt",
        }

    @root_validator(pre=True)
    def extract_registrant(cls, v):
        registrant = v.pop("registrant")
        for field in ["telephone", "street", "city", "state", "country", "postalCode"]:
            v[field] = registrant.get(field)
        return v
