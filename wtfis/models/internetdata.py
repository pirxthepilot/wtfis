"""
InternetData datamodels
API doc: https://docs.internetdata.io
"""

from __future__ import annotations

from typing import Dict, Optional

from pydantic import AliasPath, ConfigDict, Field, model_validator

from wtfis.models.base import IpGeoAsnBase, IpGeoAsnMapBase, LaxStr


class InternetData(IpGeoAsnBase):
    # Metadata
    source: str = "InternetData"

    # Config
    model_config = ConfigDict(populate_by_name=True)

    # Results
    country: Optional[str] = Field(
        None, validation_alias=AliasPath("location", "country_name")
    )
    asn: Optional[str] = Field(None, validation_alias=AliasPath("asn", "asn"))
    org: Optional[str] = Field(None, validation_alias=AliasPath("asn", "name"))
    domain: Optional[str] = Field(None, validation_alias=AliasPath("asn", "domain"))
    is_anycast: Optional[LaxStr] = Field(None, validation_alias=AliasPath("is_anycast"))

    @model_validator(mode="before")
    @classmethod
    def transforms(cls, v):
        # Generate URL to internetdata.io
        v["link"] = f"https://internetdata.io/{v['ip']}"

        return v


class InternetDataMap(IpGeoAsnMapBase):  # type: ignore[override]
    root: Dict[str, InternetData]

    @classmethod
    def empty(cls) -> InternetDataMap:
        return cls.model_validate({})
