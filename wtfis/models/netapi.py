from __future__ import annotations

from datetime import datetime
from typing import Dict, Optional

from pydantic import BaseModel, RootModel, field_validator


class NetApi(BaseModel):
    value: str
    type: str
    listed_now: bool
    listed_ever: bool
    matched_value: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    block_reason: Optional[str] = None

    @field_validator("last_seen", mode="after")
    @classmethod
    def standardize_last_seen(cls, v):
        """Convert "2026-11-20 05:28:24 UTC" to the standard UTC format"""
        try:
            return datetime.strptime(v, "%Y-%m-%d %H:%M:%S UTC").strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
        except (TypeError, ValueError):  # None or another format; keep as is
            return v

    @property
    def link(self) -> str:
        return f"https://netapi.com/lookup-{self.type}/{self.value}/"


class NetApiMap(RootModel):
    root: Dict[str, NetApi]

    @classmethod
    def empty(cls) -> NetApiMap:
        return cls.model_validate({})
