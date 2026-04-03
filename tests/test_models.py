import json

import pytest

from wtfis.exceptions import ModelException
from wtfis.models.base import str_validator
from wtfis.models.ip2location import Ip2Location, Ip2LocationMap
from wtfis.models.ipinfo import IpInfo, IpInfoMap
from wtfis.models.ipwhois import IpWhois
from wtfis.models.virustotal import Domain, Resolutions


class TestStrValidator:
    def test_string(self):
        value: str = "hello"
        assert isinstance(str_validator(value), str)
        assert str_validator(value) == "hello"

    def test_float(self):
        value: float = 1.0
        assert isinstance(str_validator(value), str)
        assert str_validator(value) == "1.0"

    def test_int(self):
        value: int = 1
        assert isinstance(str_validator(value), str)
        assert str_validator(value) == "1"

    def test_bytes(self):
        value: bytes = b"hello"
        assert isinstance(str_validator(value), str)
        assert str_validator(value) == "hello"

    def test_bytearray(self):
        value: bytearray = bytearray(b"hello")
        assert isinstance(str_validator(value), str)
        assert str_validator(value) == "hello"

    def test_validation_error(self):
        value: dict = {"hello": "world"}
        with pytest.raises(ModelException) as e:
            str_validator(value)
            assert e.value.args[0] == "Cannot be cast to string"


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
        res = Resolutions.model_validate(
            json.loads(test_data("vt_resolutions_gist.json"))
        )

        assert res.meta.count == 37
        assert len(res.data) == 10
        assert res.data[1].attributes.ip_address == "192.30.255.113"
        assert res.data[1].attributes.ip_address_last_analysis_stats.malicious == 1
        assert res.data[1].attributes.ip_address_last_analysis_stats.suspicious == 0
        assert res.data[1].attributes.ip_address_last_analysis_stats.harmless == 82
        assert res.data[1].attributes.ip_address_last_analysis_stats.undetected == 11
        assert res.data[1].attributes.date == 1655835054


class TestIp2LocationModels:
    def test_special_fields(self, test_data):
        ip2location = Ip2Location.model_validate(
            json.loads(test_data("ip2location_1.1.1.1.json")).get("1.1.1.1")
        )
        assert ip2location.is_proxy == "False"

    def test_empty_map(self):
        assert Ip2LocationMap.empty() == Ip2LocationMap.model_validate({})


class TestIpInfoModels:
    def test_special_fields(self, test_data):
        ipinfo = IpInfo.model_validate(
            json.loads(test_data("ipinfo_1.1.1.1.json")).get("1.1.1.1")
        )
        assert ipinfo.hostname == "one.one.one.one"
        assert ipinfo.is_anycast == "True"
        assert ipinfo.link == "https://ipinfo.io/1.1.1.1"

    def test_empty_map(self):
        assert IpInfoMap.empty() == IpInfoMap.model_validate({})


class TestIpWhoisModels:
    def test_special_fields(self, test_data):
        ipwhois = IpWhois.model_validate(
            json.loads(test_data("ipwhois_1.1.1.1.json")).get("1.1.1.1")
        )
        assert ipwhois.domain == "cloudflare.com"
