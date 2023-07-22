import json
from wtfis.models.virustotal import (
    Domain,
    Resolutions,
)


class TestVirustotalModels:
    def test_domain_1(self, test_data):
        domain = Domain.model_validate(json.loads(test_data("vt_domain_gist.json")))

        assert domain.data.id_ == "gist.github.com"
        assert domain.data.type_ == "domain"
        assert domain.data.attributes.last_analysis_stats.malicious == 0
        assert domain.data.attributes.last_analysis_stats.suspicious == 0
        assert domain.data.attributes.last_analysis_stats.harmless == 84
        assert domain.data.attributes.last_analysis_stats.undetected == 10
        assert list(domain.data.attributes.last_analysis_results.root.keys())[:2] == [
            "CMC Threat Intelligence",
            "Snort IP sample list",
        ]

    def test_resolutions_1(self, test_data):
        res = Resolutions.model_validate(json.loads(test_data("vt_resolutions_gist.json")))

        assert res.meta.count == 37
        assert len(res.data) == 10
        assert res.data[1].attributes.ip_address == "192.30.255.113"
        assert res.data[1].attributes.ip_address_last_analysis_stats.malicious == 1
        assert res.data[1].attributes.ip_address_last_analysis_stats.suspicious == 0
        assert res.data[1].attributes.ip_address_last_analysis_stats.harmless == 82
        assert res.data[1].attributes.ip_address_last_analysis_stats.undetected == 11
        assert res.data[1].attributes.date == 1655835054
