from __future__ import annotations

import abc
from decimal import Decimal
from typing import Any, List, Mapping, Optional, Union

from pydantic import BaseModel, BeforeValidator, ConfigDict, RootModel

from typing import Annotated

from wtfis.exceptions import ModelException


def str_validator(v: Any) -> Union[str]:
    """Lazy conversion to string type (adopted from pydantic v1)"""
    if isinstance(v, str):
        return v
    if isinstance(v, (float, int, Decimal)):
        # is there anything else we want to add here? If you think so, create an issue.
        return str(v)
    if isinstance(v, (bytes, bytearray)):
        return v.decode()
    raise ModelException("Cannot be cast to string")


LaxStr = Annotated[str, BeforeValidator(str_validator)]


class WhoisBase(BaseModel, abc.ABC):
    """Use to normalize WHOIS fields from different sources"""

    source: Optional[str] = None
    domain: Optional[str] = None
    registrar: Optional[str] = None
    organization: Optional[str] = None
    name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    street: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    country: Optional[str] = None
    postal_code: Optional[str] = None
    name_servers: List[str] = []
    date_created: Optional[str] = None
    date_changed: Optional[str] = None
    date_expires: Optional[str] = None
    dnssec: Optional[str] = None


class IpGeoAsnBase(BaseModel, abc.ABC):
    """Use to normalize IP geolocation and ASN fields"""

    model_config = ConfigDict(coerce_numbers_to_str=True)

    ip: str

    # Geolocation
    city: Optional[str] = None
    country: Optional[str] = None
    region: Optional[str] = None

    # ASN
    asn: Optional[str] = None
    org: Optional[str] = None
    isp: Optional[str] = None

    # Other
    domain: Optional[str] = None
    hostname: Optional[str] = None
    is_proxy: Optional[LaxStr] = None  # Cast bool to str
    is_anycast: Optional[LaxStr] = None  # Cast bool to str

    # Meta
    link: Optional[str] = None


class IpGeoAsnMapBase(RootModel, abc.ABC):
    root: Mapping[str, IpGeoAsnBase]

    @classmethod
    def empty(cls) -> IpGeoAsnMapBase:
        return cls.model_validate({})  # pragma: no coverage
