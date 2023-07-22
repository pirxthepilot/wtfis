from pydantic import Field, field_validator, model_validator
from typing import List, Optional

from wtfis.models.common import WhoisBase


class Whois(WhoisBase):
    source: str = "ip2whois"
    domain: str = ""
    registrar: Optional[str] = None
    organization: Optional[str] = None
    name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    street: Optional[str] = Field(None, alias="street_address")
    city: Optional[str] = None
    state: Optional[str] = Field(None, alias="region")
    country: Optional[str] = None
    postal_code: Optional[str] = Field(None, alias="zip_code")
    name_servers: List[str] = Field([], alias="nameservers")
    date_created: Optional[str] = Field(None, alias="create_date")
    date_changed: Optional[str] = Field(None, alias="update_date")
    date_expires: Optional[str] = Field(None, alias="expire_date")
    whois_server: Optional[str] = None
    dnssec: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
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

    @field_validator("registrar", mode="before")
    @classmethod
    def transform_registrar(cls, v):
        """ Convert registrar from dict to simply registrar.name """
        return v.get("name") if v else v
