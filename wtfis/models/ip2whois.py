from pydantic import root_validator, validator
from typing import List, Optional

from wtfis.models.common import WhoisBase


class Whois(WhoisBase):
    source: str = "ip2whois"
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
    whois_server: Optional[str]
    dnssec: Optional[str]

    class Config:
        fields = {
            "date_created": "create_date",
            "date_changed": "update_date",
            "date_expires": "expire_date",
            "street": "street_address",
            "state": "region",
            "postal_code": "zip_code",
            "name_servers": "nameservers",
        }

    @root_validator(pre=True)
    def extract_registrant(cls, v):
        """ Surface registrant fields to root level """
        registrant = v.pop("registrant", {})
        if not registrant:
            return v
        for field in [
            "organization", "name", "email", "phone",
            "street_address", "city", "region", "country", "zip_code",
        ]:
            v[field] = registrant.get(field)
        return v

    @validator("registrar", pre=True)
    def transform_registrar(cls, v):
        """ Convert registrar from dict to simply registrar.name """
        return v.get("name") if v else v
