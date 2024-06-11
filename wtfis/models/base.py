from __future__ import annotations

import abc
import sys
from typing import List, Mapping, Optional

from pydantic import BaseModel, BeforeValidator, ConfigDict, RootModel
from pydantic.v1.validators import str_validator

if sys.version_info >= (3, 9):
    from typing import Annotated
else:
    from typing_extensions import Annotated  # pragma: no coverage


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
    city: Optional[str]
    continent: Optional[str]
    country: Optional[str]
    region: Optional[str]

    # ASN
    asn: Optional[str]
    org: Optional[str]
    isp: Optional[str]
    domain: Optional[str]


class IpGeoAsnMapBase(RootModel, abc.ABC):
    root: Mapping[str, IpGeoAsnBase]

    @classmethod
    def empty(cls) -> IpGeoAsnMapBase:
        return cls.model_validate({})  # pragma: no coverage
