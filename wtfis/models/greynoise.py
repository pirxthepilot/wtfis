from pydantic import BaseModel
from typing import Dict, Optional


class GreynoiseIp(BaseModel):
    ip: str
    noise: bool
    riot: bool
    message: str
    classification: Optional[str]
    name: Optional[str]
    link: Optional[str]
    last_seen: Optional[str]


class GreynoiseIpMap(BaseModel):
    __root__: Dict[str, GreynoiseIp]
