import json
from wtfis.models.virustotal import (
    Domain,
    HistoricalWhois,
    Resolutions,
)


class TestVirustotalModels:
    def test_domain_1(self, test_data):
        domain = Domain.parse_obj(json.loads(test_data("vt_domain_gist.json")))

        assert domain.data.id_ == "gist.github.com"
        assert domain.data.type_ == "domain"
        assert domain.data.attributes.last_analysis_stats.malicious == 0
        assert domain.data.attributes.last_analysis_stats.suspicious == 0
        assert domain.data.attributes.last_analysis_stats.harmless == 84
        assert domain.data.attributes.last_analysis_stats.undetected == 10
        assert list(domain.data.attributes.last_analysis_results.__root__.keys())[:2] == [
            "CMC Threat Intelligence",
            "Snort IP sample list",
        ]

    def test_resolutions_1(self, test_data):
        res = Resolutions.parse_obj(json.loads(test_data("vt_resolutions_gist.json")))

        assert res.meta.count == 37
        assert len(res.data) == 10
        assert res.data[1].attributes.ip_address == "192.30.255.113"
        assert res.data[1].attributes.ip_address_last_analysis_stats.malicious == 1
        assert res.data[1].attributes.ip_address_last_analysis_stats.suspicious == 0
        assert res.data[1].attributes.ip_address_last_analysis_stats.harmless == 82
        assert res.data[1].attributes.ip_address_last_analysis_stats.undetected == 11
        assert res.data[1].attributes.date == 1655835054

    def test_historical_whois_1(self, test_data):
        whois = HistoricalWhois.parse_obj(json.loads(test_data("vt_whois_bbc.json")))

        assert whois.meta.count == 5
        assert whois.data[0].attributes.whois_map.domain == ""
        assert whois.data[0].attributes.whois_map.name_servers == ["dns1.bbc.com"]
        assert whois.data[0].attributes.whois_map.registrant_org is None

    def test_historical_whois_2(self, test_data):
        whois = HistoricalWhois.parse_obj(json.loads(test_data("vt_whois_example.json")))

        assert whois.meta.count == 9
        assert whois.data[0].attributes.whois_map.domain == "example.com"
        assert whois.data[0].attributes.whois_map.registrant_name == "1f8f4166599d23ee"
        assert whois.data[0].attributes.whois_map.registrant_org == "b46a98a26fe2fd9f"
        assert whois.data[0].attributes.whois_map.name_servers == [
            "lochlan.ns.cloudflare.com",
            "nelci.ns.cloudflare.com",
        ]
        assert whois.data[6].attributes.whois_map is None
        assert whois.data[6].attributes.first_seen_date == 1574839630
