import json
from functools import cached_property
from typing import List, Optional

import msgspec

from wtfis.models.base import WhoisBase

# pylint: disable=too-few-public-methods


class Registrant(msgspec.Struct):
    organization: Optional[str] = None
    name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    street: Optional[str] = msgspec.field(name="street_address", default=None)
    city: Optional[str] = None
    state: Optional[str] = msgspec.field(name="region", default=None)
    country: Optional[str] = None
    postal_code: Optional[str] = msgspec.field(name="zip_code", default=None)


class Registrar(msgspec.Struct):
    name: Optional[str] = None


class WhoisMsg(msgspec.Struct, dict=True):  # type: ignore[call-arg]
    domain: str = ""
    _registrar: Optional[Registrar] = msgspec.field(name="registrar", default=None)
    registrant: Optional[Registrant] = None
    name_servers: List[str] = msgspec.field(name="nameservers", default_factory=list)
    date_created: Optional[str] = msgspec.field(name="create_date", default=None)
    date_changed: Optional[str] = msgspec.field(name="update_date", default=None)
    date_expires: Optional[str] = msgspec.field(name="expire_date", default=None)
    whois_server: Optional[str] = None
    dnssec: Optional[str] = None

    @cached_property
    def registrar(self) -> Optional[str]:
        if self._registrar:
            return self._registrar.name
        return None


class Whois(WhoisBase):
    source = "ip2whois"

    @staticmethod
    def model_validate(d: dict) -> "Whois":
        obj: WhoisMsg = msgspec.json.decode(json.dumps(d), type=WhoisMsg)
        whois = Whois()
        if r := obj.registrant:
            for name in [
                "organization",
                "name",
                "email",
                "phone",
                "street",
                "city",
                "state",
                "country",
                "postal_code",
            ]:
                setattr(whois, name, getattr(r, name))
        for name in [
            "domain",
            "registrar",
            "name_servers",
            "date_created",
            "date_changed",
            "date_expires",
            "whois_server",
            "dnssec",
        ]:
            setattr(whois, name, getattr(obj, name))
        return whois
