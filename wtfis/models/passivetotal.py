from pydantic import BaseModel
from typing import List, Optional


class Registrant(BaseModel):
    organization: Optional[str]
    email: Optional[str]
    name: Optional[str]
    telephone: Optional[str]
    street: Optional[str]
    city: Optional[str]
    state: Optional[str]
    country: Optional[str]
    postalCode: Optional[str]


class Whois(BaseModel):
    contactEmail: Optional[str]
    domain: str
    expiresAt: Optional[str]
    lastLoadedAt: str
    name: str
    nameServers: List[str]
    organization: Optional[str]
    registered: Optional[str]
    registrant: Registrant
    registrar: Optional[str]
    registryUpdatedAt: Optional[str]
