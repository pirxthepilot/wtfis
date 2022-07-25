from pydantic import BaseModel
from typing import List


class Registrant(BaseModel):
    organization: str
    email: str
    name: str
    telephone: str


class Whois(BaseModel):
    contactEmail: str
    domain: str
    expiresAt: str
    name: str
    nameServers: List[str]
    organization: str
    registered: str
    registrant: Registrant
    registrar: str
    registryUpdatedAt: str
