from pydantic import BaseModel
from typing import Dict, List, Optional


class AnalysisResult(BaseModel):
    category: str
    engine_name: str
    method: str
    result: str


class LastAnalysisResults(BaseModel):
    __root__: Dict[str, AnalysisResult]


class LastAnalysisStats(BaseModel):
    harmless: int
    malicious: int
    suspicious: int
    timeout: int
    undetected: int


class Popularity(BaseModel):
    rank: int
    timestamp: int


class PopularityRanks(BaseModel):
    __root__: Dict[str, Popularity]


class Attributes(BaseModel):
    creation_date: Optional[int]
    jarm: Optional[str]
    last_analysis_results: LastAnalysisResults
    last_analysis_stats: LastAnalysisStats
    last_dns_records_date: Optional[int]
    last_https_certificate_date: Optional[int]
    last_modification_date: Optional[int]
    last_update_date: Optional[int]
    popularity_ranks: PopularityRanks
    registrar: Optional[str]
    reputation: int
    tags: List[str]


class Data(BaseModel):
    attributes: Attributes
    id_: str
    type_: str

    class Config:
        fields = {
            "id_": "id",
            "type_": "type",
        }


class Domain(BaseModel):
    data: Data


class ResolutionAttributes(BaseModel):
    date: int
    host_name: str
    resolver: str
    ip_address_last_analysis_stats: LastAnalysisStats
    ip_address: str
    host_name_last_analysis_stats: LastAnalysisStats


class ResolutionMeta(BaseModel):
    count: int


class ResolutionData(Data):
    attributes: ResolutionAttributes


class Resolutions(BaseModel):
    meta: ResolutionMeta
    data: List[ResolutionData]
