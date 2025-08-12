from __future__ import annotations

from functools import cached_property
from typing import ClassVar, Dict, List, Optional, TypeVar

import msgspec

# pylint: disable=too-few-public-methods


class WhoisBase:
    """Use to normalize WHOIS fields from different sources"""

    source: ClassVar[str]

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


class IpGeoAsnBase(msgspec.Struct, kw_only=True, dict=True):  # type: ignore[call-arg]  # https://github.com/python/mypy/issues/11036
    """Use to normalize IP geolocation and ASN fields"""

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
    _is_proxy: Optional[bool] = msgspec.field(name="is_proxy", default=None)
    _is_anycast: Optional[bool] = msgspec.field(name="is_anycast", default=None)

    # Meta
    link: Optional[str] = None

    @cached_property
    def is_proxy(self) -> Optional[str]:
        if self._is_proxy is not None:
            return str(self._is_proxy)
        return None

    @cached_property
    def is_anycast(self) -> Optional[str]:
        if self._is_anycast is not None:
            return str(self._is_anycast)
        return None


T = TypeVar("T")


class MapBase(Dict[str, T]):
    @classmethod
    def empty(cls) -> MapBase[T]:
        return cls.model_validate({})  # pragma: no coverage

    @staticmethod
    def model_validate(d: dict) -> MapBase[T]:
        obj = MapBase[T]()
        for k, v in d.items():
            obj[k] = v
        return obj
