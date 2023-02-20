from __future__ import annotations

from pydantic import BaseModel
from typing import Dict, Optional


class GreynoiseIp(BaseModel):
    ip: str
    noise: bool
    riot: bool
    message: str
    link: str
    classification: Optional[str]
    name: Optional[str]
    last_seen: Optional[str]


class GreynoiseIpMap(BaseModel):
    __root__: Dict[str, GreynoiseIp]

    @classmethod
    def empty(cls) -> GreynoiseIpMap:
        return cls(__root__={})
