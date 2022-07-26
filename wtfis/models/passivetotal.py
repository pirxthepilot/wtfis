from pydantic import BaseModel
from typing import List, Optional


class Registrant(BaseModel):
    organization: Optional[str]
    email: Optional[str]
    name: Optional[str]
    telephone: Optional[str]


class Whois(BaseModel):
    contactEmail: str
    domain: str
    expiresAt: str
    lastLoadedAt: str
    name: str
    nameServers: List[str]
    organization: Optional[str]
    registered: str
    registrant: Registrant
    registrar: str
    registryUpdatedAt: str
