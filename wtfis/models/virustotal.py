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


class Domain(BaseModel):
    """
    Essential VT domain fields
    """
    creation_date: int
    jarm: str
    last_analysis_results: LastAnalysisResults
    last_analysis_stats: LastAnalysisStats
    last_dns_records_date: int
    last_https_certificate_date: int
    last_modification_date: int
    last_update_date: int
    popularity_ranks: PopularityRanks
    registrar: str
    reputation: int
    tags: List[str]
    whois: str
    whois_date: Optional[int]
