from pydantic import BaseModel
from typing import Dict


class Flag(BaseModel):
    img: str
    emoji: str
    emoji_unicode: str


class Connection(BaseModel):
    asn: int
    org: str
    isp: str
    domain: str


class IpWhois(BaseModel):
    ip: str
    success: bool
    type_: str
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

    class Config:
        fields = {
            "type_": "type",
        }


class IpWhoisMap(BaseModel):
    __root__: Dict[str, IpWhois]
