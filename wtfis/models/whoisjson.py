from pydantic import root_validator, validator
from typing import List, Optional

from wtfis.models.common import WhoisBase


class Whois(WhoisBase):
    source: str = "whoisjson"
    domain: str
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
            "postal_code": "zipcode",
            "date_created": "created",
            "date_changed": "changed",
            "date_expires": "expires",
            "name_servers": "nameserver",
        }

    @root_validator(pre=True)
    def rename_name_to_domain(cls, v):
        """ Rename name to avoid name collisions """
        name = v.pop("name")
        v["domain"] = name
        return v

    @root_validator(pre=True)
    def extract_latest_owner(cls, v):
        """ Surface owner details to top level and remove contacts field from root """
        contacts = v.pop("contacts")
        if not contacts:
            return v
        owner = contacts["owner"][0]
        for field in [
            "organization", "name", "email", "phone",
            "street", "city", "state", "country", "zipcode",
        ]:
            v[field] = owner.get(field)
        return v

    @validator("registrar", pre=True)
    def transform_registrar(cls, v):
        """ Convert registrar from dict to simply registrar.name """
        return v.get("name") if v else v

    @validator("name_servers", pre=True)
    def convert_null_to_empty_list(cls, v):
        return v if v is not None else []
