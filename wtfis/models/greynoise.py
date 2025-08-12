from __future__ import annotations

import json
from typing import Optional

import msgspec

from .base import MapBase

# pylint: disable=too-few-public-methods


class GreynoiseIp(msgspec.Struct):
    ip: str
    noise: bool
    riot: bool
    message: str
    link: str
    classification: Optional[str] = None
    name: Optional[str] = None
    last_seen: Optional[str] = None

    @staticmethod
    def model_validate(d: dict) -> "GreynoiseIp":
        obj: GreynoiseIp = msgspec.json.decode(json.dumps(d), type=GreynoiseIp)
        return obj


GreynoiseIpMap = MapBase[GreynoiseIp]
