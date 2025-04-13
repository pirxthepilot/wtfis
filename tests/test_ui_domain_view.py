import json
from unittest.mock import MagicMock

import pytest
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Span, Text

from wtfis.clients.abuseipdb import AbuseIpDbClient
from wtfis.clients.greynoise import GreynoiseClient
from wtfis.clients.ipwhois import IpWhoisClient
from wtfis.clients.shodan import ShodanClient
from wtfis.clients.urlhaus import UrlHausClient
from wtfis.models.abuseipdb import AbuseIpDbMap
from wtfis.models.greynoise import GreynoiseIpMap
from wtfis.models.ip2whois import Whois as Ip2Whois
from wtfis.models.ipwhois import IpWhoisMap
from wtfis.models.shodan import ShodanIpMap
from wtfis.models.urlhaus import UrlHausMap
from wtfis.models.virustotal import Domain, Resolutions
from wtfis.models.virustotal import Whois as VTWhois
from wtfis.ui.view import DomainView


@pytest.fixture()
def view01(test_data, mock_ipwhois_get):
    """gist.github.com with PT whois. Complete test of all panels. Also test print()."""
    resolutions = Resolutions.model_validate(
        json.loads(test_data("vt_resolutions_gist.json"))
    )

    geoasn_pool = json.loads(test_data("ipwhois_gist.json"))
    geoasn_client = IpWhoisClient()
    geoasn_client._get_ipwhois = MagicMock(
        side_effect=lambda ip: mock_ipwhois_get(ip, geoasn_pool)
    )
    geoasn_enrich = geoasn_client.enrich_ips(*resolutions.ip_list(3))

    return DomainView(
        console=Console(),
        entity=Domain.model_validate(json.loads(test_data("vt_domain_gist.json"))),
        resolutions=resolutions,
        geoasn=geoasn_enrich,
        whois=Ip2Whois.model_validate(
            json.loads(test_data("ip2whois_whois_gist.json"))
        ),
        shodan=ShodanIpMap.model_validate({}),
        greynoise=GreynoiseIpMap.model_validate({}),
        abuseipdb=AbuseIpDbMap.model_validate({}),
        urlhaus=UrlHausMap.model_validate({}),
    )


@pytest.fixture()
def view02(test_data):
    """
    gist.github.com VT whois. Resolution and whois tests only. Test empty enrichment
    and max_resolutions=1
    """
    return DomainView(
        console=Console(),
        entity=MagicMock(),
        resolutions=Resolutions.model_validate(
            json.loads(test_data("vt_resolutions_gist.json"))
        ),
        geoasn=IpWhoisMap.model_validate({}),
        whois=VTWhois.model_validate(json.loads(test_data("vt_whois_gist.json"))),
        shodan=ShodanIpMap.model_validate({}),
        greynoise=GreynoiseIpMap.model_validate({}),
        abuseipdb=AbuseIpDbMap.model_validate({}),
        urlhaus=MagicMock(),
        max_resolutions=1,
    )


@pytest.fixture()
def view03(test_data):
    """bbc.co.uk VT whois. Whois panel test only. Test whois with no domain field."""
    return DomainView(
        console=Console(),
        entity=MagicMock(),
        resolutions=MagicMock(),
        geoasn=MagicMock(),
        whois=VTWhois.model_validate(json.loads(test_data("vt_whois_bbc.json"))),
        shodan=MagicMock(),
        greynoise=MagicMock(),
        abuseipdb=MagicMock(),
        urlhaus=MagicMock(),
    )


@pytest.fixture()
def view04(test_data):
    """
    google.com domain. Domain and resolution test only. Test domain with 1 malicious
    analysis point, and empty resolutions.
    """
    return DomainView(
        console=Console(),
        entity=Domain.model_validate(json.loads(test_data("vt_domain_google.json"))),
        resolutions=None,
        geoasn=MagicMock(),
        whois=MagicMock(),
        shodan=MagicMock(),
        greynoise=MagicMock(),
        abuseipdb=MagicMock(),
        urlhaus=MagicMock(),
    )


@pytest.fixture()
def view05(test_data):
    """tucows.com domain. Domain test only. Test domain with negative reputation and no
    popularity."""
    return DomainView(
        console=Console(),
        entity=Domain.model_validate(json.loads(test_data("vt_domain_tucows.json"))),
        resolutions=MagicMock(),
        geoasn=MagicMock(),
        whois=MagicMock(),
        shodan=MagicMock(),
        greynoise=MagicMock(),
        abuseipdb=MagicMock(),
        urlhaus=MagicMock(),
    )


@pytest.fixture()
def view06(test_data):
    """exmple.com VT whois. Whois test only. Test empty whois_map."""
    return DomainView(
        console=Console(),
        entity=MagicMock(),
        resolutions=MagicMock(),
        geoasn=MagicMock(),
        whois=VTWhois.model_validate(json.loads(test_data("vt_whois_example_2.json"))),
        shodan=MagicMock(),
        greynoise=MagicMock(),
        abuseipdb=MagicMock(),
        urlhaus=MagicMock(),
    )


@pytest.fixture()
def view07(test_data, mock_ipwhois_get, mock_shodan_get_ip):
    """gist.github.com with Shodan. Only test resolution, geoasn and Shodan."""
    resolutions = Resolutions.model_validate(
        json.loads(test_data("vt_resolutions_gist.json"))
    )

    geoasn_pool = json.loads(test_data("ipwhois_gist.json"))
    geoasn_client = IpWhoisClient()
    geoasn_client._get_ipwhois = MagicMock(
        side_effect=lambda ip: mock_ipwhois_get(ip, geoasn_pool)
    )
    geoasn_enrich = geoasn_client.enrich_ips(*resolutions.ip_list(3))

    shodan_pool = json.loads(test_data("shodan_gist.json"))
    shodan_client = ShodanClient(MagicMock())
    shodan_client._get_ip = MagicMock(
        side_effect=lambda ip: mock_shodan_get_ip(ip, shodan_pool)
    )
    shodan_enrich = shodan_client.enrich_ips(*resolutions.ip_list(3))

    return DomainView(
        console=Console(),
        entity=MagicMock(),
        resolutions=resolutions,
        geoasn=geoasn_enrich,
        whois=MagicMock(),
        shodan=shodan_enrich,
        greynoise=GreynoiseIpMap.model_validate({}),
        abuseipdb=AbuseIpDbMap.model_validate({}),
        urlhaus=MagicMock(),
    )


@pytest.fixture()
def view08(test_data, mock_shodan_get_ip):
    """www.wired.com with Shodan. Only test resolution and Shodan."""
    resolutions = Resolutions.model_validate(
        json.loads(test_data("vt_resolutions_wired.json"))
    )

    shodan_pool = json.loads(test_data("shodan_wired.json"))
    shodan_client = ShodanClient(MagicMock())
    shodan_client._get_ip = MagicMock(
        side_effect=lambda ip: mock_shodan_get_ip(ip, shodan_pool)
    )
    shodan_enrich = shodan_client.enrich_ips(*resolutions.ip_list(1))

    return DomainView(
        console=Console(),
        entity=MagicMock(),
        resolutions=resolutions,
        geoasn=IpWhoisMap.model_validate({}),
        whois=MagicMock(),
        shodan=shodan_enrich,
        greynoise=GreynoiseIpMap.model_validate({}),
        abuseipdb=AbuseIpDbMap.model_validate({}),
        urlhaus=MagicMock(),
        max_resolutions=1,
    )


@pytest.fixture()
def view09(test_data, mock_shodan_get_ip, mock_greynoise_get, mock_abuseipdb_get):
    """one.one.one.one with Shodan, Greynoise and AbuseIPDB. Only test mentioned
    services."""
    resolutions = Resolutions.model_validate(
        json.loads(test_data("vt_resolutions_one.json"))
    )

    shodan_pool = json.loads(test_data("shodan_one.json"))
    shodan_client = ShodanClient(MagicMock())
    shodan_client._get_ip = MagicMock(
        side_effect=lambda ip: mock_shodan_get_ip(ip, shodan_pool)
    )
    shodan_enrich = shodan_client.enrich_ips(*resolutions.ip_list(1))

    greynoise_pool = json.loads(test_data("greynoise_one.json"))
    greynoise_client = GreynoiseClient("dummykey")
    greynoise_client._get_ip = MagicMock(
        side_effect=lambda ip: mock_greynoise_get(ip, greynoise_pool)
    )
    greynoise_enrich = greynoise_client.enrich_ips(*resolutions.ip_list(1))

    abuseipdb_pool = json.loads(test_data("abuseipdb_one.json"))
    abuseipdb_client = AbuseIpDbClient("dummykey")
    abuseipdb_client._get_ip = MagicMock(
        side_effect=lambda ip: mock_abuseipdb_get(ip, abuseipdb_pool)
    )
    abuseipdb_enrich = abuseipdb_client.enrich_ips(*resolutions.ip_list(1))

    return DomainView(
        console=Console(),
        entity=MagicMock(),
        resolutions=resolutions,
        geoasn=MagicMock(),
        whois=MagicMock(),
        shodan=shodan_enrich,
        greynoise=greynoise_enrich,
        abuseipdb=abuseipdb_enrich,
        urlhaus=MagicMock(),
        max_resolutions=1,
    )


@pytest.fixture()
def view10(test_data):
    """Dummy VT whois. Whois panel test only. Test whois with no data."""
    return DomainView(
        console=Console(),
        entity=MagicMock(),
        resolutions=MagicMock(),
        geoasn=MagicMock(),
        whois=VTWhois.model_validate(json.loads(test_data("vt_whois_foo.json"))),
        shodan=MagicMock(),
        greynoise=GreynoiseIpMap.model_validate({}),
        abuseipdb=AbuseIpDbMap.model_validate({}),
        urlhaus=MagicMock(),
    )


@pytest.fixture()
def view11(test_data, mock_shodan_get_ip):
    """gist.github.com with Shodan. Only test Shodan. Test empty open ports."""
    resolutions = Resolutions.model_validate(
        json.loads(test_data("vt_resolutions_gist.json"))
    )

    shodan_pool = json.loads(test_data("shodan_gist_2.json"))
    shodan_client = ShodanClient(MagicMock())
    shodan_client._get_ip = MagicMock(
        side_effect=lambda ip: mock_shodan_get_ip(ip, shodan_pool)
    )
    shodan_enrich = shodan_client.enrich_ips(*resolutions.ip_list(3))

    return DomainView(
        console=Console(),
        entity=MagicMock(),
        resolutions=resolutions,
        geoasn=MagicMock(),
        whois=MagicMock(),
        shodan=shodan_enrich,
        greynoise=GreynoiseIpMap.model_validate({}),
        abuseipdb=AbuseIpDbMap.model_validate({}),
        urlhaus=MagicMock(),
    )


@pytest.fixture()
def view12(test_data):
    """Dummy IP2WHOIS whois. Whois panel test only."""
    return DomainView(
        console=Console(),
        entity=MagicMock(),
        resolutions=MagicMock(),
        geoasn=MagicMock(),
        whois=Ip2Whois.model_validate(
            json.loads(test_data("ip2whois_whois_hotmail.json"))
        ),
        shodan=MagicMock(),
        greynoise=MagicMock(),
        abuseipdb=MagicMock(),
        urlhaus=MagicMock(),
    )


@pytest.fixture()
def view13(test_data):
    """Dummy IP2WHOIS whois. Whois panel test only. Test null registrant."""
    return DomainView(
        console=Console(),
        entity=MagicMock(),
        resolutions=MagicMock(),
        geoasn=MagicMock(),
        whois=Ip2Whois.model_validate(json.loads(test_data("ip2whois_whois_bbc.json"))),
        shodan=MagicMock(),
        greynoise=MagicMock(),
        abuseipdb=MagicMock(),
        urlhaus=MagicMock(),
    )


@pytest.fixture()
def view14(test_data, mock_ipwhois_get, mock_urlhaus_get):
    """Same as view01() but with Urlhaus enrichment. Test URLhaus only."""
    resolutions = Resolutions.model_validate(
        json.loads(test_data("vt_resolutions_gist.json"))
    )

    geoasn_pool = json.loads(test_data("ipwhois_gist.json"))
    geoasn_client = IpWhoisClient()
    geoasn_client._get_ipwhois = MagicMock(
        side_effect=lambda ip: mock_ipwhois_get(ip, geoasn_pool)
    )
    geoasn_enrich = geoasn_client.enrich_ips(*resolutions.ip_list(3))

    urlhaus_pool = json.loads(test_data("urlhaus_gist.json"))
    urlhaus_client = UrlHausClient()
    urlhaus_client._get_host = MagicMock(
        side_effect=lambda domain: mock_urlhaus_get(domain, urlhaus_pool)
    )
    urlhaus_enrich = urlhaus_client.enrich_domains("gist.github.com")

    return DomainView(
        console=Console(),
        entity=Domain.model_validate(json.loads(test_data("vt_domain_gist.json"))),
        resolutions=resolutions,
        geoasn=geoasn_enrich,
        whois=Ip2Whois.model_validate(
            json.loads(test_data("ip2whois_whois_gist.json"))
        ),
        shodan=ShodanIpMap.model_validate({}),
        greynoise=GreynoiseIpMap.model_validate({}),
        abuseipdb=AbuseIpDbMap.model_validate({}),
        urlhaus=urlhaus_enrich,
    )


class TestView01:
    def test_domain_panel(self, view01, theme, display_timestamp):
        domain = view01.domain_panel()
        assert type(domain) is Panel
        assert domain.title == Text("gist.github.com")
        assert domain.title.style == theme.panel_title

        #
        # VT section
        #

        vt_section = domain.renderable.renderables[0]

        # Heading
        assert vt_section.renderables[0] == Text("VirusTotal")
        assert vt_section.renderables[0].style == theme.heading_h1

        # Table
        table = vt_section.renderables[1]
        assert type(table) is Table
        assert table.columns[0].style == theme.table_field
        assert table.columns[0].justify == "left"
        assert table.columns[0]._cells == [
            Text(
                "Analysis:",
                spans=[
                    Span(0, 8, "link https://virustotal.com/gui/domain/gist.github.com")
                ],
            ),
            "Reputation:",
            "Popularity:",
            "Categories:",
            "Updated:",
            "Last Seen:",
        ]
        assert table.columns[1].style == theme.table_value
        assert table.columns[1].justify == "left"
        assert table.columns[1]._cells == [
            Text("0/94 malicious", spans=[Span(0, 14, theme.info)]),
            Text("0"),
            Text(
                "Majestic (532)\nCisco Umbrella (39463)",
                spans=[
                    Span(0, 8, "bright_cyan"),
                    Span(10, 13, "cyan"),
                    Span(15, 29, "bright_cyan"),
                    Span(31, 36, "cyan"),
                ],
            ),
            Text(
                (
                    "advice, file sharing/storage, information technology, "
                    "media sharing, social networks"
                ),
                spans=[
                    Span(0, 6, "bright_white on black"),
                    Span(6, 8, "default"),
                    Span(8, 28, "bright_white on black"),
                    Span(28, 30, "default"),
                    Span(30, 52, "bright_white on black"),
                    Span(52, 54, "default"),
                    Span(54, 67, "bright_white on black"),
                    Span(67, 69, "default"),
                    Span(69, 84, "bright_white on black"),
                ],
            ),
            display_timestamp("2022-08-16T06:14:59Z"),
            display_timestamp("2022-08-15T22:25:30Z"),
        ]

    def test_resolutions_panel(self, view01, theme, display_timestamp):
        res = view01.resolutions_panel()
        assert type(res) is Panel

        # Sections
        title = res.renderable.renderables[0]
        ip1 = res.renderable.renderables[1]
        ip2 = res.renderable.renderables[3]
        ip3 = res.renderable.renderables[5]
        footer = res.renderable.renderables[7]

        # Title
        assert title == Text("Resolutions")
        assert title.style == theme.heading_h1

        # Entry 1
        group = ip1.renderables

        # Heading
        assert group[0] == Text(
            "13.234.210.38",
            spans=[Span(0, 13, theme.heading_h2)],
        )

        # Table
        assert group[1].columns[0].style == theme.table_field
        assert group[1].columns[0].justify == "left"
        assert group[1].columns[0]._cells == [
            Text(
                "Analysis:",
                spans=[
                    Span(
                        0, 8, "link https://virustotal.com/gui/ip-address/13.234.210.38"
                    )
                ],
            ),
            "Resolved:",
            "ASN:",
            "ISP:",
            "Location:",
        ]
        assert group[1].columns[1].style == theme.table_value
        assert group[1].columns[1].justify == "left"
        assert group[1].columns[1]._cells == [
            Text("0/94 malicious", spans=[Span(0, 14, theme.info)]),
            display_timestamp("2022-08-06T14:56:20Z"),
            Text(
                "16509 (Amazon Data Services India)", spans=[Span(7, 33, theme.asn_org)]
            ),
            "Amazon.com, Inc.",
            Text(
                "Mumbai, Maharashtra, India",
                spans=[
                    Span(6, 8, "default"),
                    Span(19, 21, "default"),
                ],
            ),
        ]

        # Spacing
        assert res.renderable.renderables[2] == ""

        # Entry 2
        group = ip2.renderables

        # Heading
        assert group[0] == Text(
            "192.30.255.113",
            spans=[Span(0, 14, theme.heading_h2)],
        )

        # Table
        assert group[1].columns[0].style == theme.table_field
        assert group[1].columns[0].justify == "left"
        assert group[1].columns[0]._cells == [
            Text(
                "Analysis:",
                spans=[
                    Span(
                        0,
                        8,
                        "link https://virustotal.com/gui/ip-address/192.30.255.113",
                    )
                ],
            ),
            "Resolved:",
            "ASN:",
            "ISP:",
            "Location:",
        ]
        assert group[1].columns[1].style == theme.table_value
        assert group[1].columns[1].justify == "left"
        assert group[1].columns[1]._cells == [
            Text("1/94 malicious", spans=[Span(0, 14, theme.error)]),
            display_timestamp("2022-06-21T18:10:54Z"),
            Text("36459 (GitHub, Inc.)", spans=[Span(7, 19, theme.asn_org)]),
            "GitHub, Inc.",
            Text(
                "Seattle, Washington, United States",
                spans=[
                    Span(7, 9, "default"),
                    Span(19, 21, "default"),
                ],
            ),
        ]

        # Spacing
        assert res.renderable.renderables[4] == ""

        # Entry 3 (NOTE: Timestamp on data modified to be really old)
        group = ip3.renderables

        # Heading
        assert group[0] == Text(
            "13.234.176.102",
            spans=[Span(0, 14, theme.heading_h2)],
        )

        # Unlike the previous entries, the table is inside a group of (Table, Text)
        # due to old timestamp warning
        # table = group[1].renderables[0]
        table = group[1]
        assert table.columns[0].style == theme.table_field
        assert table.columns[0].justify == "left"
        assert table.columns[0]._cells == [
            Text(
                "Analysis:",
                spans=[
                    Span(
                        0,
                        8,
                        "link https://virustotal.com/gui/ip-address/13.234.176.102",
                    )
                ],
            ),
            "Resolved:",
            "ASN:",
            "ISP:",
            "Location:",
        ]
        assert table.columns[1].style == theme.table_value
        assert table.columns[1].justify == "left"
        assert table.columns[1]._cells == [
            Text("0/94 malicious", spans=[Span(0, 14, theme.info)]),
            display_timestamp("2015-08-17T07:11:53Z"),
            Text(
                "16509 (Amazon Data Services India)", spans=[Span(7, 33, theme.asn_org)]
            ),
            "Amazon.com, Inc.",
            Text(
                "Mumbai, Maharashtra, India",
                spans=[
                    Span(6, 8, "default"),
                    Span(19, 21, "default"),
                ],
            ),
        ]

        # Old timestamp warning
        # assert group[1].renderables[1] == Text("**Enrichment data may be inaccurate")

        # Spacing and remaining count footer
        assert res.renderable.renderables[6] == ""
        assert str(footer) == "+34 more"
        assert footer.spans[0].style.startswith(
            f"{theme.footer} link https://virustotal.com/gui/domain/"
        )

    def test_whois_panel(self, view01, theme, display_timestamp):
        whois = view01.whois_panel()
        assert type(whois) is Panel
        assert whois.title is None

        # Sections
        title = whois.renderable.renderables[0]
        content = whois.renderable.renderables[1]

        # Title
        assert title == Text("Whois")
        assert title.style == theme.heading_h1

        # Content
        assert content.renderables[0] == Text(
            "github.com",
            spans=[Span(0, 10, "bold yellow")],
        )

        table = content.renderables[1]
        assert type(table) is Table
        assert table.columns[0].style == theme.table_field
        assert table.columns[0].justify == "left"
        assert table.columns[0]._cells == [
            "Registrar:",
            "Organization:",
            "Email:",
            "State:",
            "Country:",
            "Nameservers:",
            "Registered:",
            "Updated:",
            "Expires:",
        ]
        assert table.columns[1].style == theme.table_value
        assert table.columns[1].justify == "left"
        assert table.columns[1]._cells == [
            "MarkMonitor, Inc.",
            Text("GitHub, Inc.", style=theme.whois_org),
            (
                "Select Request Email Form at "
                "https://domains.markmonitor.com/whois/github.com"
            ),
            "CA",
            "US",
            Text(
                (
                    "ns-421.awsdns-52.com, ns-1707.awsdns-21.co.uk, ns-1283.awsdns-32.org, "
                    "dns4.p08.nsone.net, dns2.p08.nsone.net, dns3.p08.nsone.net, "
                    "ns-520.awsdns-01.net, dns1.p08.nsone.net"
                ),
                spans=[
                    Span(0, 20, theme.nameserver_list),
                    Span(20, 22, "default"),
                    Span(22, 45, theme.nameserver_list),
                    Span(45, 47, "default"),
                    Span(47, 68, theme.nameserver_list),
                    Span(68, 70, "default"),
                    Span(70, 88, theme.nameserver_list),
                    Span(88, 90, "default"),
                    Span(90, 108, theme.nameserver_list),
                    Span(108, 110, "default"),
                    Span(110, 128, theme.nameserver_list),
                    Span(128, 130, "default"),
                    Span(130, 150, theme.nameserver_list),
                    Span(150, 152, "default"),
                    Span(152, 170, theme.nameserver_list),
                ],
            ),
            display_timestamp("2007-10-09T18:20:50Z"),
            display_timestamp("2024-09-07T09:16:33Z"),
            display_timestamp("2026-10-09T00:00:00Z"),
        ]

    def test_print(self, view01):
        view01.domain_panel = MagicMock()
        view01.resolutions_panel = MagicMock()
        view01.whois_panel = MagicMock()
        view01.console.print = MagicMock()

        view01.print()
        view01.domain_panel.assert_called_once()
        view01.resolutions_panel.assert_called_once()
        view01.whois_panel.assert_called_once()
        view01.console.print.assert_called_once()


class TestView02:
    def test_resolutions_panel(self, view02, theme, display_timestamp):
        res = view02.resolutions_panel()
        assert type(res) is Panel

        # Sections
        title = res.renderable.renderables[0]
        ip1 = res.renderable.renderables[1]
        footer = res.renderable.renderables[3]

        # Title
        assert title == Text("Resolutions")
        assert title.style == theme.heading_h1

        # Entry 1
        group = ip1.renderables

        # Heading
        assert group[0] == Text(
            "13.234.210.38",
            spans=[Span(0, 13, theme.heading_h2)],
        )

        # Table
        assert group[1].columns[0].style == theme.table_field
        assert group[1].columns[0].justify == "left"
        assert group[1].columns[0]._cells == [
            Text(
                "Analysis:",
                spans=[
                    Span(
                        0, 8, "link https://virustotal.com/gui/ip-address/13.234.210.38"
                    )
                ],
            ),
            "Resolved:",
        ]
        assert group[1].columns[1].style == theme.table_value
        assert group[1].columns[1].justify == "left"
        assert group[1].columns[1]._cells == [
            Text("0/94 malicious", spans=[Span(0, 14, theme.info)]),
            display_timestamp("2022-08-06T14:56:20Z"),
        ]

        # Spacing and remaining count footer
        assert res.renderable.renderables[2] == ""
        assert str(footer) == "+36 more"
        assert footer.spans[0].style.startswith(
            f"{theme.footer} link https://virustotal.com/gui/domain/"
        )

    def test_whois_panel(self, view02, theme):
        whois = view02.whois_panel()
        assert type(whois) is Panel
        assert whois.title is None

        # Sections
        title = whois.renderable.renderables[0]
        content = whois.renderable.renderables[1]

        # Title
        assert title == Text("Whois")
        assert title.style == theme.heading_h1

        # Content
        assert content.renderables[0] == Text(
            "github.com", spans=[Span(0, 10, "bold yellow")]
        )

        table = content.renderables[1]
        assert type(table) is Table
        assert table.columns[0].style == theme.table_field
        assert table.columns[0].justify == "left"
        assert table.columns[0]._cells == [
            "Registrar:",
            "Nameservers:",
            "DNSSEC:",
            "Registered:",
            "Updated:",
            "Expires:",
        ]
        assert table.columns[1].style == theme.table_value
        assert table.columns[1].justify == "left"
        assert [
            str(c) for c in table.columns[1]._cells
        ] == [  # Just test the strings (no style)
            "MarkMonitor Inc.",
            "dns1.p08.nsone.net, dns2.p08.nsone.net, dns3.p08.nsone.net, "
            "dns4.p08.nsone.net, ns-1283.awsdns-32.org, ns-1707.awsdns-21.co.uk, "
            "ns-421.awsdns-52.com, ns-520.awsdns-01.net",
            "unsigned",
            "2007-10-09T18:20:50Z",
            "2020-09-08T09:18:27Z",
            "2022-10-09T18:20:50Z",
        ]


class TestView03:
    def test_whois_panel(self, view03, theme):
        whois = view03.whois_panel()
        assert type(whois) is Panel
        assert whois.title is None

        # Sections
        title = whois.renderable.renderables[0]
        content = whois.renderable.renderables[1]

        # Title
        assert title == Text("Whois")
        assert title.style == theme.heading_h1

        # Table
        # Note: there should not be a subheading (a.k.a the domain)
        table = content
        assert type(table) is Table
        assert table.columns[0].style == theme.table_field
        assert table.columns[0].justify == "left"
        assert table.columns[0]._cells == [
            "Nameservers:",
            "Registered:",
            "Updated:",
            "Expires:",
        ]
        assert table.columns[1].style == theme.table_value
        assert table.columns[1].justify == "left"
        assert [str(c) for c in table.columns[1]._cells] == [
            "dns1.bbc.com",
            "before Aug-1996",
            "10-Dec-2020",
            "13-Dec-2025",
        ]


class TestView04:
    def test_domain_panel(self, view04, theme, display_timestamp):
        domain = view04.domain_panel()
        assert type(domain) is Panel
        assert domain.title == Text("google.com")

        #
        # VT section
        #

        vt_section = domain.renderable.renderables[0]

        # Heading
        assert vt_section.renderables[0] == Text("VirusTotal")
        assert vt_section.renderables[0].style == theme.heading_h1

        # Table
        table = vt_section.renderables[1]
        assert type(table) is Table
        assert table.columns[0].style == theme.table_field
        assert table.columns[0].justify == "left"
        assert table.columns[0]._cells == [
            Text(
                "Analysis:",
                spans=[Span(0, 8, "link https://virustotal.com/gui/domain/google.com")],
            ),
            "Reputation:",
            "Popularity:",
            "Categories:",
            "Updated:",
            "Last Seen:",
        ]
        assert table.columns[1].style == theme.table_value
        assert table.columns[1].justify == "left"
        assert table.columns[1]._cells == [
            Text(
                "1/94 malicious\nCyble",
                spans=[
                    Span(0, 14, theme.error),
                    Span(15, 20, "cyan"),
                ],
            ),
            Text("448"),
            Text(
                (
                    "Majestic (1)\nStatvoo (1)\nAlexa (1)\nCisco Umbrella (2)\n"
                    "Quantcast (1)"
                ),
                spans=[
                    Span(0, 8, "bright_cyan"),
                    Span(10, 11, "cyan"),
                    Span(13, 20, "bright_cyan"),
                    Span(22, 23, "cyan"),
                    Span(25, 30, "bright_cyan"),
                    Span(32, 33, "cyan"),
                    Span(35, 49, "bright_cyan"),
                    Span(51, 52, "cyan"),
                    Span(54, 63, "bright_cyan"),
                    Span(65, 66, "cyan"),
                ],
            ),
            Text(
                (
                    "mobile communications, portals, search engines, "
                    "search engines and portals, searchengines"
                ),
                spans=[
                    Span(0, 21, "bright_white on black"),
                    Span(21, 23, "default"),
                    Span(23, 30, "bright_white on black"),
                    Span(30, 32, "default"),
                    Span(32, 46, "bright_white on black"),
                    Span(46, 48, "default"),
                    Span(48, 74, "bright_white on black"),
                    Span(74, 76, "default"),
                    Span(76, 89, "bright_white on black"),
                ],
            ),
            display_timestamp("2022-08-17T06:03:03Z"),
            display_timestamp("2022-08-17T00:35:19Z"),
        ]

    def test_resolutions_panel(self, view04):
        res = view04.resolutions_panel()
        assert res is None


class TestView05:
    def test_domain_panel(self, view05, theme, display_timestamp):
        domain = view05.domain_panel()
        assert type(domain) is Panel
        assert domain.title == Text("tucows.com")

        #
        # VT section
        #

        vt_section = domain.renderable.renderables[0]

        # Heading
        assert vt_section.renderables[0] == Text("VirusTotal")
        assert vt_section.renderables[0].style == theme.heading_h1

        # Table
        table = vt_section.renderables[1]
        assert type(table) is Table
        assert table.columns[0].style == theme.table_field
        assert table.columns[0].justify == "left"
        assert table.columns[0]._cells == [
            Text(
                "Analysis:",
                spans=[Span(0, 8, "link https://virustotal.com/gui/domain/tucows.com")],
            ),
            "Reputation:",
            "Categories:",
            "Updated:",
            "Last Seen:",
        ]
        assert table.columns[1].style == theme.table_value
        assert table.columns[1].justify == "left"
        assert table.columns[1]._cells == [
            Text(
                "1/94 malicious\nDr.Web",
                spans=[
                    Span(0, 14, theme.error),
                    Span(15, 21, "cyan"),
                ],
            ),
            Text("-1"),
            Text(
                (
                    "ads/analytics, dynamic dns and isp sites, hosting, "
                    "information technology, known infection source, "
                    "mobile communications, not recommended site"
                ),
                spans=[
                    Span(0, 13, "bright_white on black"),
                    Span(13, 15, "default"),
                    Span(15, 40, "bright_white on black"),
                    Span(40, 42, "default"),
                    Span(42, 49, "bright_white on black"),
                    Span(49, 51, "default"),
                    Span(51, 73, "bright_white on black"),
                    Span(73, 75, "default"),
                    Span(75, 97, "bright_white on black"),
                    Span(97, 99, "default"),
                    Span(99, 120, "bright_white on black"),
                    Span(120, 122, "default"),
                    Span(122, 142, "bright_white on black"),
                ],
            ),
            display_timestamp("2022-08-17T05:30:23Z"),
            display_timestamp("2022-08-16T22:24:18Z"),
        ]


class TestView06:
    def test_whois_panel(self, view06, theme):
        whois = view06.whois_panel()
        assert type(whois) is Panel
        assert whois.title is None

        # Sections
        title = whois.renderable.renderables[0]
        content = whois.renderable.renderables[1]

        # Title
        assert title == Text("Whois")
        assert title.style == theme.heading_h1

        # Warning message
        assert content == Text("No WHOIS data was found")
        assert content.style == theme.disclaimer


class TestView07:
    def test_resolutions_panel(self, view07, theme, display_timestamp):
        res = view07.resolutions_panel()
        assert type(res) is Panel

        # Sections
        title = res.renderable.renderables[0]
        ip1 = res.renderable.renderables[1]
        ip2 = res.renderable.renderables[3]
        ip3 = res.renderable.renderables[5]
        footer = res.renderable.renderables[7]

        # Title
        assert title == Text("Resolutions")
        assert title.style == theme.heading_h1

        # Entry 1
        group = ip1.renderables

        # Heading
        assert group[0] == Text(
            "13.234.210.38",
            spans=[Span(0, 13, theme.heading_h2)],
        )

        # Table
        assert group[1].columns[0].style == theme.table_field
        assert group[1].columns[0].justify == "left"
        assert group[1].columns[0]._cells == [
            Text(
                "Analysis:",
                spans=[
                    Span(
                        0, 8, "link https://virustotal.com/gui/ip-address/13.234.210.38"
                    )
                ],
            ),
            "Resolved:",
            "ASN:",
            "ISP:",
            "Location:",
            Text(
                "Services:",
                spans=[Span(0, 8, "link https://www.shodan.io/host/13.234.210.38")],
            ),
            "Tags:",
        ]
        assert group[1].columns[1].style == theme.table_value
        assert group[1].columns[1].justify == "left"
        assert group[1].columns[1]._cells == [
            Text("0/94 malicious", spans=[Span(0, 14, theme.info)]),
            display_timestamp("2022-08-06T14:56:20Z"),
            Text(
                "16509 (Amazon Data Services India)",
                spans=[Span(7, 33, "bright_white")],
            ),
            "Amazon.com, Inc.",
            Text(
                "Mumbai, Maharashtra, India",
                spans=[Span(6, 8, "default"), Span(19, 21, "default")],
            ),
            Text(
                "22/tcp, 80/tcp, 443/tcp",
                spans=[
                    Span(0, 2, theme.port),
                    Span(2, 6, theme.transport),
                    Span(6, 8, "default"),
                    Span(8, 10, theme.port),
                    Span(10, 14, theme.transport),
                    Span(14, 16, "default"),
                    Span(16, 19, theme.port),
                    Span(19, 23, theme.transport),
                ],
            ),
            Text("cloud", spans=[Span(0, 5, "bright_white on black")]),
        ]

        # Spacing
        assert res.renderable.renderables[2] == ""

        # Entry 2
        group = ip2.renderables

        # Heading
        assert group[0] == Text(
            "192.30.255.113",
            spans=[Span(0, 14, theme.heading_h2)],
        )

        # Table
        assert group[1].columns[0].style == theme.table_field
        assert group[1].columns[0].justify == "left"
        assert group[1].columns[0]._cells == [
            Text(
                "Analysis:",
                spans=[
                    Span(
                        0,
                        8,
                        "link https://virustotal.com/gui/ip-address/192.30.255.113",
                    )
                ],
            ),
            "Resolved:",
            "ASN:",
            "ISP:",
            "Location:",
            Text(
                "Services:",
                spans=[Span(0, 8, "link https://www.shodan.io/host/192.30.255.113")],
            ),
        ]
        assert group[1].columns[1].style == theme.table_value
        assert group[1].columns[1].justify == "left"
        assert group[1].columns[1]._cells == [
            Text("1/94 malicious", spans=[Span(0, 14, theme.error)]),
            display_timestamp("2022-06-21T18:10:54Z"),
            Text("36459 (GitHub, Inc.)", spans=[Span(7, 19, "bright_white")]),
            "GitHub, Inc.",
            Text(
                "Seattle, Washington, United States",
                spans=[Span(7, 9, "default"), Span(19, 21, "default")],
            ),
            Text(
                "22/tcp, 80/tcp, 443/tcp",
                spans=[
                    Span(0, 2, theme.port),
                    Span(2, 6, theme.transport),
                    Span(6, 8, "default"),
                    Span(8, 10, theme.port),
                    Span(10, 14, theme.transport),
                    Span(14, 16, "default"),
                    Span(16, 19, theme.port),
                    Span(19, 23, theme.transport),
                ],
            ),
        ]

        # Spacing
        assert res.renderable.renderables[4] == ""

        # Entry 3 (NOTE: Timestamp on data modified to be really old)
        group = ip3.renderables

        # Heading
        assert group[0] == Text(
            "13.234.176.102",
            spans=[Span(0, 14, theme.heading_h2)],
        )

        # Unlike the previous entries, the table is inside a group of (Table, Text) due
        # to old timestamp warning
        # table = group[1].renderables[0]
        table = group[1]
        assert table.columns[0].style == theme.table_field
        assert table.columns[0].justify == "left"
        assert table.columns[0]._cells == [
            Text(
                "Analysis:",
                spans=[
                    Span(
                        0,
                        8,
                        "link https://virustotal.com/gui/ip-address/13.234.176.102",
                    )
                ],
            ),
            "Resolved:",
            "ASN:",
            "ISP:",
            "Location:",
            Text(
                "Services:",
                spans=[Span(0, 8, "link https://www.shodan.io/host/13.234.176.102")],
            ),
            "Tags:",
        ]
        assert table.columns[1].style == theme.table_value
        assert table.columns[1].justify == "left"
        assert table.columns[1]._cells == [
            Text("0/94 malicious", spans=[Span(0, 14, theme.info)]),
            display_timestamp("2015-08-17T07:11:53Z"),
            Text(
                "16509 (Amazon Data Services India)",
                spans=[Span(7, 33, "bright_white")],
            ),
            "Amazon.com, Inc.",
            Text(
                "Mumbai, Maharashtra, India",
                spans=[Span(6, 8, "default"), Span(19, 21, "default")],
            ),
            Text(
                "22/tcp, 80/tcp, 443/tcp",
                spans=[
                    Span(0, 2, theme.port),
                    Span(2, 6, theme.transport),
                    Span(6, 8, "default"),
                    Span(8, 10, theme.port),
                    Span(10, 14, theme.transport),
                    Span(14, 16, "default"),
                    Span(16, 19, theme.port),
                    Span(19, 23, theme.transport),
                ],
            ),
            Text("cloud", spans=[Span(0, 5, "bright_white on black")]),
        ]

        # Old timestamp warning
        # assert group[1].renderables[1] == Text("**Enrichment data may be inaccurate")

        # Spacing and remaining count footer
        assert res.renderable.renderables[6] == ""
        assert str(footer) == "+34 more"
        assert footer.spans[0].style.startswith(
            f"{theme.footer} link https://virustotal.com/gui/domain/"
        )


class TestView08:
    def test_resolutions_panel(self, view08, theme, display_timestamp):
        res = view08.resolutions_panel()
        assert type(res) is Panel

        # Sections
        title = res.renderable.renderables[0]
        ip1 = res.renderable.renderables[1]
        footer = res.renderable.renderables[3]

        # Title
        assert title == Text("Resolutions")
        assert title.style == theme.heading_h1

        # Entry 1
        group = ip1.renderables

        # Heading
        assert group[0] == Text(
            "199.232.34.194",
            spans=[Span(0, 14, theme.heading_h2)],
        )

        # Table
        assert group[1].columns[0].style == theme.table_field
        assert group[1].columns[0].justify == "left"
        assert group[1].columns[0]._cells == [
            Text(
                "Analysis:",
                spans=[
                    Span(
                        0,
                        8,
                        "link https://virustotal.com/gui/ip-address/199.232.34.194",
                    )
                ],
            ),
            "Resolved:",
            Text(
                "Services:",
                spans=[Span(0, 8, "link https://www.shodan.io/host/199.232.34.194")],
            ),
            "Tags:",
        ]
        assert group[1].columns[1].style == theme.table_value
        assert group[1].columns[1].justify == "left"
        assert group[1].columns[1]._cells == [
            Text("0/93 malicious", spans=[Span(0, 14, theme.info)]),
            display_timestamp("2022-06-03T22:32:19Z"),
            Text(
                "Varnish HTTP Cache (80/tcp)\nOther (443/tcp)",
                spans=[
                    Span(0, 18, theme.product),
                    Span(20, 22, theme.port),
                    Span(22, 26, theme.transport),
                    Span(28, 33, theme.product),
                    Span(35, 38, theme.port),
                    Span(38, 42, theme.transport),
                ],
            ),
            Text(
                "cdn",
                spans=[
                    Span(0, 3, "bright_white on black"),
                ],
            ),
        ]

        # Spacing
        assert res.renderable.renderables[2] == ""

        # Footer
        assert str(footer) == "+199 more"
        assert footer.spans[0].style.startswith(
            f"{theme.footer} link https://virustotal.com/gui/domain/"
        )


class TestView09:
    def test_resolutions_panel(self, view09, theme, display_timestamp):
        res = view09.resolutions_panel()
        assert type(res) is Panel

        # Sections
        title = res.renderable.renderables[0]
        ip1 = res.renderable.renderables[1]
        footer = res.renderable.renderables[3]

        # Title
        assert title == Text("Resolutions")
        assert title.style == theme.heading_h1

        # Entry 1
        group = ip1.renderables

        # Heading
        assert group[0] == Text(
            "1.0.0.1",
            spans=[Span(0, 7, theme.heading_h2)],
        )

        # Table
        # table = group[1].renderables[0]
        table = group[1]
        assert table.columns[0].style == theme.table_field
        assert table.columns[0].justify == "left"
        assert table.columns[0]._cells == [
            Text(
                "Analysis:",
                spans=[
                    Span(0, 8, "link https://virustotal.com/gui/ip-address/1.0.0.1")
                ],
            ),
            "Resolved:",
            Text(
                "Services:",
                spans=[Span(0, 8, "link https://www.shodan.io/host/1.0.0.1")],
            ),
            Text(
                "GreyNoise:",
                spans=[Span(0, 9, "link https://viz.greynoise.io/riot/1.0.0.1")],
            ),
            Text(
                "AbuseIPDB:",
                spans=[Span(0, 9, "link https://www.abuseipdb.com/check/1.0.0.1")],
            ),
        ]
        assert table.columns[1].style == theme.table_value
        assert table.columns[1].justify == "left"
        assert table.columns[1]._cells == [
            Text("2/94 malicious", spans=[Span(0, 14, theme.error)]),
            display_timestamp("2020-08-01T22:07:20Z"),
            Text(
                (
                    "CloudFlare (80/tcp, 8080/tcp)\nOther (53/tcp, 53/udp, 443/tcp, "
                    "2082/tcp, 2086/tcp, 2087/tcp, 8443/tcp)"
                ),
                spans=[
                    Span(0, 10, theme.product),
                    Span(12, 14, theme.port),
                    Span(14, 18, theme.transport),
                    Span(18, 20, "default"),
                    Span(20, 24, theme.port),
                    Span(24, 28, theme.transport),
                    Span(30, 35, theme.product),
                    Span(37, 39, theme.port),
                    Span(39, 43, theme.transport),
                    Span(43, 45, "default"),
                    Span(45, 47, theme.port),
                    Span(47, 51, theme.transport),
                    Span(51, 53, "default"),
                    Span(53, 56, theme.port),
                    Span(56, 60, theme.transport),
                    Span(60, 62, "default"),
                    Span(62, 66, theme.port),
                    Span(66, 70, theme.transport),
                    Span(70, 72, "default"),
                    Span(72, 76, theme.port),
                    Span(76, 80, theme.transport),
                    Span(80, 82, "default"),
                    Span(82, 86, theme.port),
                    Span(86, 90, theme.transport),
                    Span(90, 92, "default"),
                    Span(92, 96, theme.port),
                    Span(96, 100, theme.transport),
                ],
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
                ],
            ),
            Text(
                "100 confidence score (567 reports)",
                spans=[
                    Span(0, 3, theme.error),
                    Span(3, 20, "red"),
                    Span(20, 34, theme.table_value),
                ],
            ),
        ]

        # Old timestamp warning
        # assert group[1].renderables[1] == Text("**Enrichment data may be inaccurate")

        # Spacing
        assert res.renderable.renderables[2] == ""

        # Footer
        assert str(footer) == "+1 more"
        assert footer.spans[0].style.startswith(
            f"{theme.footer} link https://virustotal.com/gui/domain/"
        )


class TestView10:
    def test_whois_panel(self, view10, theme):
        whois = view10.whois_panel()
        assert type(whois) is Panel
        assert whois.title is None

        # Sections
        title = whois.renderable.renderables[0]
        content = whois.renderable.renderables[1]

        # Title
        assert title == Text("Whois")
        assert title.style == theme.heading_h1

        # Warning message
        assert content == Text("No WHOIS data was found")
        assert content.style == theme.disclaimer


class TestView11:
    def test_resolutions_panel(self, view11, theme, display_timestamp):
        res = view11.resolutions_panel()
        assert type(res) is Panel

        # Sections
        title = res.renderable.renderables[0]
        ip1 = res.renderable.renderables[1]

        # Title
        assert title == Text("Resolutions")
        assert title.style == theme.heading_h1

        # Entry 1
        group = ip1.renderables

        # Heading
        assert group[0] == Text(
            "13.234.210.38",
            spans=[Span(0, 13, theme.heading_h2)],
        )

        # Table
        assert group[1].columns[0].style == theme.table_field
        assert group[1].columns[0].justify == "left"
        assert group[1].columns[0]._cells == [
            Text(
                "Analysis:",
                spans=[
                    Span(
                        0, 8, "link https://virustotal.com/gui/ip-address/13.234.210.38"
                    )
                ],
            ),
            "Resolved:",
            "Tags:",
        ]
        assert group[1].columns[1].style == theme.table_value
        assert group[1].columns[1].justify == "left"
        assert group[1].columns[1]._cells == [
            Text("0/94 malicious", spans=[Span(0, 14, theme.info)]),
            display_timestamp("2022-08-06T14:56:20Z"),
            Text("cloud", spans=[Span(0, 5, theme.tags)]),
        ]


class TestView12:
    def test_whois_panel(self, view12, theme):
        whois = view12.whois_panel()
        assert type(whois) is Panel
        assert whois.title is None

        # Sections
        title = whois.renderable.renderables[0]
        content = whois.renderable.renderables[1]

        # Title
        assert title == Text("Whois")
        assert title.style == theme.heading_h1

        # Content
        assert content.renderables[0] == Text(
            "hotmail.com", spans=[Span(0, 11, "bold yellow")]
        )

        # Table
        table = content.renderables[1]
        assert type(table) is Table
        assert table.columns[0].style == theme.table_field
        assert table.columns[0].justify == "left"
        assert table.columns[0]._cells == [
            "Registrar:",
            "Organization:",
            "Name:",
            "Email:",
            "Phone:",
            "Street:",
            "City:",
            "State:",
            "Country:",
            "Postcode:",
            "Nameservers:",
            "Registered:",
            "Updated:",
            "Expires:",
        ]
        assert table.columns[1].style == theme.table_value
        assert table.columns[1].justify == "left"
        assert [
            str(c) for c in table.columns[1]._cells
        ] == [  # Just test the strings (no style)
            "MarkMonitor, Inc.",
            "Microsoft Corporation",
            "Domain Administrator",
            "domains@microsoft.com",
            "+1.4258828080",
            "One Microsoft Way,",
            "Redmond",
            "WA",
            "US",
            "98052",
            (
                "ns4-205.azure-dns.info, ns3-205.azure-dns.org, ns1-205.azure-dns.com, "
                "ns2-205.azure-dns.net"
            ),
            "1996-03-27T05:00:00Z",
            "2021-02-02T17:08:19Z",
            "2024-03-27T07:00:00Z",
        ]


class TestView13:
    def test_whois_panel(self, view13, theme):
        whois = view13.whois_panel()
        assert type(whois) is Panel
        assert whois.title is None

        # Sections
        title = whois.renderable.renderables[0]
        content = whois.renderable.renderables[1]

        # Title
        assert title == Text("Whois")
        assert title.style == theme.heading_h1

        # Content
        # Note: there should not be a subheading (a.k.a the domain)
        table = content
        assert type(table) is Table
        assert table.columns[0].style == theme.table_field
        assert table.columns[0].justify == "left"
        assert table.columns[0]._cells == [
            "Registered:",
            "Updated:",
            "Expires:",
        ]
        assert table.columns[1].style == theme.table_value
        assert table.columns[1].justify == "left"
        assert [
            str(c) for c in table.columns[1]._cells
        ] == [  # Just test the strings (no style)
            "1996-08-01T00:00:00Z",
            "2020-12-10T00:00:00Z",
            "2025-12-13T00:00:00Z",
        ]


class TestView14:
    def test_domain_panel_urlhaus(self, view14, theme):
        domain = view14.domain_panel()
        urlhaus_section = domain.renderable.renderables[2]

        # Heading
        assert urlhaus_section.renderables[0] == Text("URLhaus")
        assert urlhaus_section.renderables[0].style == theme.heading_h1

        # Table
        table = urlhaus_section.renderables[1]
        assert type(table) is Table
        assert table.columns[0].style == theme.table_field
        assert table.columns[0].justify == "left"
        assert table.columns[0]._cells == [
            Text(
                "Malware URLs:",
                spans=[
                    Span(0, 12, "link https://urlhaus.abuse.ch/host/gist.github.com/")
                ],
            ),
            "Blocklists:",
            "Tags:",
        ]
        assert table.columns[1].style == theme.table_value
        assert table.columns[1].justify == "left"
        assert table.columns[1]._cells == [
            Text(
                "1+ online (3248 total)",
                spans=[
                    Span(0, 9, theme.error),
                    Span(9, 22, theme.table_value),
                ],
            ),
            Text(
                "abused_legit_malware in spamhaus\nlisted in surbl",
                spans=[
                    Span(0, 20, theme.urlhaus_bl_med),
                    Span(24, 32, theme.urlhaus_bl_name),
                    Span(33, 39, theme.urlhaus_bl_high),
                    Span(43, 48, theme.urlhaus_bl_name),
                ],
            ),
            Text(
                "Pikabot, TA577, foo, zip",
                spans=[
                    Span(0, 7, theme.tags),
                    Span(7, 9, "default"),
                    Span(9, 14, theme.tags),
                    Span(14, 16, "default"),
                    Span(16, 19, theme.tags),
                    Span(19, 21, "default"),
                    Span(21, 24, theme.tags),
                ],
            ),
        ]
