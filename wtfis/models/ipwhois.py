from pydantic import BaseModel, Field, RootModel
from typing import Dict

from wtfis.models.common import LaxStr


class Flag(BaseModel):
    img: str
    emoji: str
    emoji_unicode: str


class Connection(BaseModel):
    asn: LaxStr
    org: str
    isp: str
    domain: str


class IpWhois(BaseModel):
    ip: str
    success: bool
    type_: str = Field(alias="type")
    continent: str
    continent_code: str
    country: str
    country_code: str
    region: str
    region_code: str
    city: str
    is_eu: bool
    postal: str
    calling_code: str
    capital: str
    borders: str
    flag: Flag
    connection: Connection


class IpWhoisMap(RootModel):
    root: Dict[str, IpWhois]
