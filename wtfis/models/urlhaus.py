from __future__ import annotations

import json
from functools import cached_property
from typing import List, Optional, Set

import msgspec

from .base import MapBase

# pylint: disable=too-few-public-methods


class Blacklists(msgspec.Struct):
    spamhaus_dbl: str
    surbl: str


class Url(msgspec.Struct, dict=True):  # type: ignore[call-arg]
    id: str
    urlhaus_reference: str
    url: str
    url_status: str
    date_added: str
    threat: str
    reporter: str
    _larted: str = msgspec.field(name="larted")
    _takedown_time_seconds: Optional[str] = msgspec.field(name="takedown_time_seconds")
    tags: List[str] = []

    mapping = {"true": True, "false": False}

    @cached_property
    def larted(self) -> bool:
        return self.mapping[self._larted.lower()]

    @cached_property
    def takedown_time_seconds(self) -> Optional[int]:
        if self._takedown_time_seconds is not None:
            return int(self._takedown_time_seconds)
        return self._takedown_time_seconds


class UrlHaus(msgspec.Struct, dict=True):  # type: ignore[call-arg]
    query_status: str
    urlhaus_reference: Optional[str] = None
    host: Optional[str] = None
    firstseen: Optional[str] = None
    _url_count: Optional[str] = msgspec.field(name="url_count", default=None)
    blacklists: Optional[Blacklists] = None
    urls: List[Url] = []
    _online_url_count: Optional[int] = None
    _tags: Set[str] = set()

    # Extracted fields

    @cached_property
    def url_count(self) -> Optional[int]:
        return int(self._url_count) if self._url_count else None

    @cached_property
    def online_url_count(self) -> int:
        if not self._online_url_count:
            self._online_url_count = (
                len([u for u in self.urls if u.url_status == "online"])
                if self.urls
                else 0
            )
        return self._online_url_count

    @cached_property
    def tags(self) -> List[str]:
        if not self._tags:
            for url in self.urls:
                for tag in url.tags:
                    self._tags.add(tag)
        return sorted(self._tags)

    @staticmethod
    def model_validate(d: dict) -> "UrlHaus":
        obj: UrlHaus = msgspec.json.decode(json.dumps(d), type=UrlHaus)
        return obj


UrlHausMap = MapBase[UrlHaus]
