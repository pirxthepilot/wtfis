from __future__ import annotations

from typing import Dict, List, Optional, Set

from pydantic import BaseModel, RootModel, field_validator


class Blacklists(BaseModel):
    spamhaus_dbl: str
    surbl: str


class Url(BaseModel):
    id: str
    urlhaus_reference: str
    url: str
    url_status: str
    date_added: str
    threat: str
    reporter: str
    larted: bool
    takedown_time_seconds: Optional[int]
    tags: List[str] = []

    @field_validator("larted", mode="before")
    @classmethod
    def convert_larted(cls, v):
        """Cast larted to bool"""
        mapping = {"true": True, "false": False}
        return mapping[v.lower()]

    @field_validator("tags", mode="before")
    @classmethod
    def handle_none_tags(cls, v):
        """Turn NoneType tags into an empty list"""
        return [] if v is None else v


class UrlHaus(BaseModel):
    query_status: str
    urlhaus_reference: Optional[str] = None
    host: Optional[str] = None
    firstseen: Optional[str] = None
    url_count: Optional[int] = None
    blacklists: Optional[Blacklists] = None
    urls: List[Url] = []
    _online_url_count: Optional[int] = None
    _tags: Set[str] = set()

    # Extracted fields

    @field_validator("url_count", mode="before")
    @classmethod
    def convert_url_count(cls, v):
        """Cast url_count to int"""
        return int(v) if v else None

    @property
    def online_url_count(self) -> int:
        if not self._online_url_count:
            self._online_url_count = (
                len([u for u in self.urls if u.url_status == "online"])
                if self.urls
                else 0
            )
        return self._online_url_count

    @property
    def tags(self) -> List[str]:
        if not self._tags:
            for url in self.urls:
                for tag in url.tags:
                    self._tags.add(tag)
        return sorted(self._tags)


class UrlHausMap(RootModel):
    root: Dict[str, UrlHaus]

    @classmethod
    def empty(cls) -> UrlHausMap:
        return cls.model_validate({})
