import abc
import sys

from pydantic import BaseModel, BeforeValidator
from pydantic.v1.validators import str_validator
from typing import List, Optional

if sys.version_info >= (3, 9):
    from typing import Annotated
else:
    from typing_extensions import Annotated


LaxStr = Annotated[str, BeforeValidator(str_validator)]


class WhoisBase(BaseModel, abc.ABC):
    """ Use to normalize WHOIS fields from different sources """
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
