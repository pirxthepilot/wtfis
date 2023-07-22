import pytest
import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Span, Text
from unittest.mock import MagicMock

from wtfis.clients.greynoise import GreynoiseClient
from wtfis.clients.ipwhois import IpWhoisClient
from wtfis.clients.shodan import ShodanClient
from wtfis.models.greynoise import GreynoiseIpMap
from wtfis.models.ipwhois import IpWhoisMap
from wtfis.models.passivetotal import Whois as PTWhois
from wtfis.models.virustotal import (
    IpAddress,
    Whois as VTWhois,
)
from wtfis.ui.view import IpAddressView


@pytest.fixture()
def view01(test_data, mock_ipwhois_get, mock_greynoise_get):
    """ 1.1.1.1 with PT whois. Complete test of all panels. Also test print(). """
    ip = "1.1.1.1"
    ipwhois_pool = json.loads(test_data("ipwhois_1.1.1.1.json"))
    ipwhois_client = IpWhoisClient()
    ipwhois_client.get_ipwhois = MagicMock(side_effect=lambda ip: mock_ipwhois_get(ip, ipwhois_pool))
    ip_enrich = ipwhois_client.single_get_ip(ip)

    greynoise_pool = json.loads(test_data("greynoise_1.1.1.1.json"))
    greynoise_client = GreynoiseClient("dummykey")
    greynoise_client.get_ip = MagicMock(side_effect=lambda ip: mock_greynoise_get(ip, greynoise_pool))
    greynoise_enrich = greynoise_client.single_get_ip(ip)

    return IpAddressView(
        console=Console(),
        entity=IpAddress.model_validate(json.loads(test_data("vt_ip_1.1.1.1.json"))),
        whois=PTWhois.model_validate(json.loads(test_data("pt_whois_1.1.1.1.json"))),
        ip_enrich=ip_enrich,
        greynoise=greynoise_enrich,
    )


@pytest.fixture()
def view02(test_data, mock_shodan_get_ip, mock_greynoise_get):
    """ 1.1.1.1 with Shodan and Greynoise. Test the whole IP panel. """
    ip = "1.1.1.1"
    shodan_pool = json.loads(test_data("shodan_1.1.1.1.json"))
    shodan_client = ShodanClient(MagicMock())
    shodan_client.get_ip = MagicMock(side_effect=lambda ip: mock_shodan_get_ip(ip, shodan_pool))
    ip_enrich = shodan_client.single_get_ip(ip)

    greynoise_pool = json.loads(test_data("greynoise_1.1.1.1.json"))
    greynoise_client = GreynoiseClient("dummykey")
    greynoise_client.get_ip = MagicMock(side_effect=lambda ip: mock_greynoise_get(ip, greynoise_pool))
    greynoise_enrich = greynoise_client.single_get_ip(ip)

    return IpAddressView(
        console=Console(),
        entity=IpAddress.model_validate(json.loads(test_data("vt_ip_1.1.1.1.json"))),
        whois=MagicMock(),
        ip_enrich=ip_enrich,
        greynoise=greynoise_enrich,
    )


@pytest.fixture()
def view03(test_data):
    """ 1.1.1.1 VT whois. Whois panel test only."""
    return IpAddressView(
        console=Console(),
        entity=MagicMock(),
        whois=VTWhois.model_validate(json.loads(test_data("vt_whois_1.1.1.1.json"))),
        ip_enrich=MagicMock(),
        greynoise=MagicMock(),
    )


@pytest.fixture()
def view04(test_data):
    """
    142.251.220.110. Test whole IP panel with 0 malicious, 0 reputation and no IP and
    Greynoise enrichment.
    """
    return IpAddressView(
        console=Console(),
        entity=IpAddress.model_validate(json.loads(test_data("vt_ip_142.251.220.110.json"))),
        whois=MagicMock(),
        ip_enrich=IpWhoisMap.model_validate({}),
        greynoise=GreynoiseIpMap.model_validate({}),
    )


@pytest.fixture()
def view05(test_data, mock_greynoise_get):
    """ 1.1.1.1 with alt Greynoise results. Test Greynoise only. """
    ip = "1.1.1.1"
    greynoise_pool = json.loads(test_data("greynoise_1.1.1.1_malicious.json"))
    greynoise_client = GreynoiseClient("dummykey")
    greynoise_client.get_ip = MagicMock(side_effect=lambda ip: mock_greynoise_get(ip, greynoise_pool))
    greynoise_enrich = greynoise_client.single_get_ip(ip)

    return IpAddressView(
        console=Console(),
        entity=IpAddress.model_validate(json.loads(test_data("vt_ip_1.1.1.1.json"))),
        whois=MagicMock(),
        ip_enrich=IpWhoisMap.model_validate({}),
        greynoise=greynoise_enrich,
    )


@pytest.fixture()
def view06(test_data, mock_greynoise_get):
    """ 1.1.1.1 with another alt Greynoise result (unknown class). Test Greynoise only. """
    ip = "1.1.1.1"
    greynoise_pool = json.loads(test_data("greynoise_1.1.1.1_unknown.json"))
    greynoise_client = GreynoiseClient("dummykey")
    greynoise_client.get_ip = MagicMock(side_effect=lambda ip: mock_greynoise_get(ip, greynoise_pool))
    greynoise_enrich = greynoise_client.single_get_ip(ip)

    return IpAddressView(
        console=Console(),
        entity=IpAddress.model_validate(json.loads(test_data("vt_ip_1.1.1.1.json"))),
        whois=MagicMock(),
        ip_enrich=IpWhoisMap.model_validate({}),
        greynoise=greynoise_enrich,
    )


class TestView01:
    def test_ip_panel(self, view01, theme, display_timestamp):
        ip = view01.ip_panel()
        assert type(ip) is Panel
        assert ip.title == Text("ip")

        # Heading
        assert ip.renderable.renderables[0] == Text(
            "1.1.1.1",
            spans=[Span(0, 7, 'bold yellow link https://virustotal.com/gui/ip-address/1.1.1.1')]
        )

        # Table
        table = ip.renderable.renderables[1]
        assert type(table) is Table
        assert table.columns[0].style == "bold bright_magenta"
        assert table.columns[0].justify == "left"
        assert table.columns[0]._cells == [
            "Analysis:",
            "Reputation:",
            "Updated:",
            "ASN:",
            "ISP:",
            "Location:",
            Text(
                "Greynoise:",
                spans=[Span(0, 9, "link https://viz.greynoise.io/riot/1.1.1.1")]
            ),
        ]
        assert table.columns[1].style == "none"
        assert table.columns[1].justify == "left"
        assert table.columns[1]._cells == [
            Text(
                "4/94 malicious\nCMC Threat Intelligence, Comodo Valkyrie Verdict, CRDF, Blueliv",
                spans=[
                    Span(15, 78, ''),
                    Span(15, 38, 'cyan'),
                    Span(38, 40, 'default'),
                    Span(40, 63, 'cyan'),
                    Span(63, 65, 'default'),
                    Span(65, 69, 'cyan'),
                    Span(69, 71, 'default'),
                    Span(71, 78, 'cyan'),
                ]
            ),
            Text("134"),
            display_timestamp("2022-09-03T06:47:04Z"),
            Text(
                "13335 (APNIC and Cloudflare DNS Resolver project)",
                spans=[Span(7, 48, theme.asn_org)],
            ),
            "Cloudflare, Inc.",
            Text(
                "Sydney, New South Wales, Australia",
                spans=[
                    Span(6, 8, 'default'),
                    Span(23, 25, 'default'),
                ]
            ),
            Text(
                "✓ riot  ✗ noise  ✓ benign",
                spans=[
                    Span(0, 1, theme.info),
                    Span(2, 6, theme.tags),
                    Span(8, 9, theme.warn),
                    Span(10, 15, theme.tags),
                    Span(17, 18, theme.info),
                    Span(19, 25, theme.tags_green),
                ]
            ),
        ]

    def test_whois_panel(self, view01):
        whois = view01.whois_panel()
        assert type(whois) is Panel
        assert whois.title == Text("whois")

        # Heading
        assert whois.renderable.renderables[0] == Text(
            "1.1.1.0",
            spans=[Span(0, 7, "bold yellow link https://community.riskiq.com/search/1.1.1.0/whois")]
        )

        # Table
        table = whois.renderable.renderables[1]
        assert type(table) is Table
        assert table.columns[0].style == "bold bright_magenta"
        assert table.columns[0].justify == "left"
        assert table.columns[0]._cells == [
            "Registrar:",
            "Organization:",
            "Name:",
            "Email:",
            "Phone:",
            "Street:",
            "Registered:",
            "Updated:",
        ]
        assert table.columns[1].style == "none"
        assert table.columns[1].justify == "left"
        assert [str(c) for c in table.columns[1]._cells] == [
            "APNIC",
            "APNIC Research and Development",
            "APNIC Research and Development",
            "helpdesk@apnic.net",
            "+61-7-38583100",
            "6 cordelia st",
            "2011-08-10T23:12:35Z",
            "2020-07-15T13:10:57Z",
        ]

    def test_print(self, view01):
        view01.ip_panel = MagicMock()
        view01.whois_panel = MagicMock()
        view01.console.print = MagicMock()

        view01.print()
        view01.ip_panel.assert_called_once()
        view01.whois_panel.assert_called_once()
        view01.console.print.assert_called_once()


class TestView02:
    def test_ip_panel(self, view02, theme, display_timestamp):
        ip = view02.ip_panel()
        assert type(ip) is Panel
        assert ip.title == Text("ip")

        # Heading
        assert ip.renderable.renderables[0] == Text(
            "1.1.1.1",
            spans=[Span(0, 7, "bold yellow link https://virustotal.com/gui/ip-address/1.1.1.1")]
        )

        # Table
        table = ip.renderable.renderables[1]
        assert type(table) is Table
        assert table.columns[0].style == "bold bright_magenta"
        assert table.columns[0].justify == "left"
        assert table.columns[0]._cells == [
            "Analysis:",
            "Reputation:",
            "Updated:",
            "ASN:",
            "ISP:",
            "Location:",
            Text(
                "Services:",
                spans=[Span(0, 8, "link https://www.shodan.io/host/1.1.1.1")]
            ),
            "Last Scan:",
            Text(
                "Greynoise:",
                spans=[Span(0, 9, "link https://viz.greynoise.io/riot/1.1.1.1")]
            ),
        ]
        assert table.columns[1].style == "none"
        assert table.columns[1].justify == "left"
        assert table.columns[1]._cells == [
            Text(
                "4/94 malicious\nCMC Threat Intelligence, Comodo Valkyrie Verdict, CRDF, Blueliv",
                spans=[
                    Span(15, 78, ''),
                    Span(15, 38, 'cyan'),
                    Span(38, 40, 'default'),
                    Span(40, 63, 'cyan'),
                    Span(63, 65, 'default'),
                    Span(65, 69, 'cyan'),
                    Span(69, 71, 'default'),
                    Span(71, 78, 'cyan'),
                ]
            ),
            Text("134"),
            display_timestamp("2022-09-03T06:47:04Z"),
            Text(
                "13335 (APNIC and Cloudflare DNS Resolver project)",
                spans=[Span(7, 48, theme.asn_org)],
            ),
            "Cloudflare, Inc.",
            Text(
                "Los Angeles, United States",
                spans=[Span(11, 13, "default")]
            ),
            Text(
                (
                    "Cisco router tftpd (69/udp)\nCloudFlare (80/tcp, 8080/tcp, 8880/tcp)\n"
                    "DrayTek Vigor Router (443/tcp)\nOther (53/tcp, 53/udp, 161/udp, "
                    "2082/tcp, 2083/tcp, 2086/tcp, 2087/tcp, 8443/tcp)"
                ),
                spans=[
                    Span(0, 18, "orange_red1"),
                    Span(20, 26, ""),
                    Span(20, 26, ""),
                    Span(20, 22, "bright_cyan"),
                    Span(22, 26, "cyan"),
                    Span(28, 38, "orange_red1"),
                    Span(40, 66, ""),
                    Span(40, 46, ""),
                    Span(40, 42, "bright_cyan"),
                    Span(42, 46, "cyan"),
                    Span(46, 48, "default"),
                    Span(48, 56, ""),
                    Span(48, 52, "bright_cyan"),
                    Span(52, 56, "cyan"),
                    Span(56, 58, "default"),
                    Span(58, 66, ""),
                    Span(58, 62, "bright_cyan"),
                    Span(62, 66, "cyan"),
                    Span(68, 88, "orange_red1"),
                    Span(90, 97, ""),
                    Span(90, 97, ""),
                    Span(90, 93, "bright_cyan"),
                    Span(93, 97, "cyan"),
                    Span(99, 104, "orange_red1"),
                    Span(106, 179, ""),
                    Span(106, 112, ""),
                    Span(106, 108, "bright_cyan"),
                    Span(108, 112, "cyan"),
                    Span(112, 114, "default"),
                    Span(114, 120, ""),
                    Span(114, 116, "bright_cyan"),
                    Span(116, 120, "cyan"),
                    Span(120, 122, "default"),
                    Span(122, 129, ""),
                    Span(122, 125, "bright_cyan"),
                    Span(125, 129, "cyan"),
                    Span(129, 131, "default"),
                    Span(131, 139, ""),
                    Span(131, 135, "bright_cyan"),
                    Span(135, 139, "cyan"),
                    Span(139, 141, "default"),
                    Span(141, 149, ""),
                    Span(141, 145, "bright_cyan"),
                    Span(145, 149, "cyan"),
                    Span(149, 151, "default"),
                    Span(151, 159, ""),
                    Span(151, 155, "bright_cyan"),
                    Span(155, 159, "cyan"),
                    Span(159, 161, "default"),
                    Span(161, 169, ""),
                    Span(161, 165, "bright_cyan"),
                    Span(165, 169, "cyan"),
                    Span(169, 171, "default"),
                    Span(171, 179, ""),
                    Span(171, 175, "bright_cyan"),
                    Span(175, 179, "cyan"),
                ]
            ),
            display_timestamp("2022-09-04T01:03:56Z"),
            Text(
                "✓ riot  ✗ noise  ✓ benign",
                spans=[
                    Span(0, 1, theme.info),
                    Span(2, 6, theme.tags),
                    Span(8, 9, theme.warn),
                    Span(10, 15, theme.tags),
                    Span(17, 18, theme.info),
                    Span(19, 25, theme.tags_green),
                ]
            ),
        ]


class TestView03:
    def test_whois_panel(self, view03):
        whois = view03.whois_panel()
        assert type(whois) is Panel
        assert whois.title == Text("whois")

        # Heading
        assert whois.renderable.renderables[0] == Text(
            "one.one",
            spans=[Span(0, 7, "bold yellow")]
        )

        # Table
        table = whois.renderable.renderables[1]
        assert type(table) is Table
        assert table.columns[0].style == "bold bright_magenta"
        assert table.columns[0].justify == "left"
        assert table.columns[0]._cells == [
            "Registrar:",
            "Organization:",
            "Name:",
            "Email:",
            "Phone:",
            "Street:",
            "City:",
            "Country:",
            "Postcode:",
            "Nameservers:",
            "DNSSEC:",
            "Registered:",
            "Updated:",
            "Expires:",
        ]
        assert table.columns[1].style == "none"
        assert table.columns[1].justify == "left"
        assert [str(c) for c in table.columns[1]._cells] == [
            "One.com A/S - ONE",
            "One.com A/S",
            "REDACTED FOR PRIVACY",
            (
                "Please query the RDDS service of the Registrar of Record identified in this "
                "output for information on how to contact the Registrant, Admin, or Tech "
                "contact of the queried domain name."
            ),
            "REDACTED FOR PRIVACY",
            "REDACTED FOR PRIVACY",
            "REDACTED FOR PRIVACY",
            "dk",
            "REDACTED FOR PRIVACY",
            (
                "* a response from the service that a domain name is 'available', does not "
                "guarantee that is able to be registered,, * we may restrict, suspend or "
                "terminate your access to the service at any time, and, * the copying, "
                "compilation, repackaging, dissemination or other use of the information "
                "provided by the service is not permitted, without our express written "
                "consent., this information has been prepared and published in order to "
                "represent administrative and technical management of the tld., we may "
                "discontinue or amend any part or the whole of these terms of service from "
                "time to time at our absolute discretion."
            ),
            "signedDelegation",
            "2015-05-20T12:15:44Z",
            "2021-07-04T12:15:49Z",
            "2022-05-20T12:15:44Z",
        ]


class TestView04:
    def test_ip_panel(self, view04, display_timestamp):
        ip = view04.ip_panel()
        assert type(ip) is Panel
        assert ip.title == Text("ip")

        # Heading
        assert ip.renderable.renderables[0] == Text(
            "142.251.220.110",
            spans=[Span(0, 15, "bold yellow link https://virustotal.com/gui/ip-address/142.251.220.110")]
        )

        # Table
        table = ip.renderable.renderables[1]
        assert type(table) is Table
        assert table.columns[0].style == "bold bright_magenta"
        assert table.columns[0].justify == "left"
        assert table.columns[0]._cells == [
            "Analysis:",
            "Reputation:",
            "Updated:",
        ]
        assert table.columns[1].style == "none"
        assert table.columns[1].justify == "left"
        assert table.columns[1]._cells == [
            Text("0/93 malicious"),
            Text("0"),
            display_timestamp("2022-09-03T16:58:45Z"),
        ]


class TestView05:
    def test_ip_panel_greynoise_only(self, view05, theme):
        ip = view05.ip_panel()

        # Table
        table = ip.renderable.renderables[1]
        assert table.columns[1]._cells[-1] == Text(
            "✗ riot  ✓ noise  ! malicious",
            spans=[
                Span(0, 1, theme.warn),
                Span(2, 6, theme.tags),
                Span(8, 9, theme.info),
                Span(10, 15, theme.tags),
                Span(17, 18, theme.error),
                Span(19, 28, theme.tags_red),
            ]
        )


class TestView06:
    def test_ip_panel_greynoise_only(self, view06, theme):
        ip = view06.ip_panel()

        # Table
        table = ip.renderable.renderables[1]
        assert table.columns[1]._cells[-1] == Text(
            "✓ riot  ✗ noise  ? unknown",
            spans=[
                Span(0, 1, theme.info),
                Span(2, 6, theme.tags),
                Span(8, 9, theme.warn),
                Span(10, 15, theme.tags),
                Span(19, 26, theme.tags),
            ]
        )
