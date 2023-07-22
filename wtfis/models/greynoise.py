from __future__ import annotations

from pydantic import BaseModel, RootModel
from typing import Dict, Optional


class GreynoiseIp(BaseModel):
    ip: str
    noise: bool
    riot: bool
    message: str
    link: str
    classification: Optional[str] = None
    name: Optional[str] = None
    last_seen: Optional[str] = None


class GreynoiseIpMap(RootModel):
    root: Dict[str, GreynoiseIp]

    @classmethod
    def empty(cls) -> GreynoiseIpMap:
        return cls.model_validate({})
