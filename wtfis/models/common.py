import abc

from pydantic import BaseModel
from typing import List, Optional, TypeVar


class WhoisBase(BaseModel, abc.ABC):
    """ Use to normalize WHOIS fields from different sources """
    source: Optional[str]
    domain: Optional[str]
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


WhoisType = TypeVar("WhoisType", bound=WhoisBase)
