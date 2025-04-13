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
from wtfis.models.greynoise import GreynoiseIpMap
from wtfis.models.ipwhois import IpWhoisMap
from wtfis.models.urlhaus import UrlHausMap
from wtfis.models.virustotal import IpAddress
from wtfis.models.virustotal import Whois as VTWhois
from wtfis.ui.view import IpAddressView


@pytest.fixture()
def view01(
    test_data,
    mock_abuseipdb_get,
    mock_ipwhois_get,
    mock_shodan_get_ip,
    mock_greynoise_get,
    mock_urlhaus_get,
):
    """1.1.1.1 with PT whois. Complete test of all panels. Also test print()."""
    ip = "1.1.1.1"

    geoasn_pool = json.loads(test_data("ipwhois_1.1.1.1.json"))
    geoasn_client = IpWhoisClient()
    geoasn_client._get_ipwhois = MagicMock(
        side_effect=lambda ip: mock_ipwhois_get(ip, geoasn_pool)
    )
    geoasn_enrich = geoasn_client.enrich_ips(ip)

    shodan_pool = json.loads(test_data("shodan_1.1.1.1.json"))
    shodan_client = ShodanClient(MagicMock())
    shodan_client._get_ip = MagicMock(
        side_effect=lambda ip: mock_shodan_get_ip(ip, shodan_pool)
    )
    shodan_enrich = shodan_client.enrich_ips(ip)

    greynoise_pool = json.loads(test_data("greynoise_1.1.1.1.json"))
    greynoise_client = GreynoiseClient("dummykey")
    greynoise_client._get_ip = MagicMock(
        side_effect=lambda ip: mock_greynoise_get(ip, greynoise_pool)
    )
    greynoise_enrich = greynoise_client.enrich_ips(ip)

    abuseipdb_pool = json.loads(test_data("abuseipdb_1.1.1.1_red.json"))
    abuseipdb_client = AbuseIpDbClient("dummykey")
    abuseipdb_client._get_ip = MagicMock(
        side_effect=lambda ip: mock_abuseipdb_get(ip, abuseipdb_pool)
    )
    abuseipdb_enrich = abuseipdb_client.enrich_ips(ip)

    urlhaus_pool = json.loads(test_data("urlhaus_1.1.1.1.json"))
    urlhaus_client = UrlHausClient()
    urlhaus_client._get_host = MagicMock(
        side_effect=lambda ip: mock_urlhaus_get(ip, urlhaus_pool)
    )
    urlhaus_enrich = urlhaus_client.enrich_ips(ip)

    return IpAddressView(
        console=Console(),
        entity=IpAddress.model_validate(json.loads(test_data("vt_ip_1.1.1.1.json"))),
        geoasn=geoasn_enrich,
        whois=VTWhois.model_validate(json.loads(test_data("vt_whois_1.1.1.1.json"))),
        shodan=shodan_enrich,
        greynoise=greynoise_enrich,
        abuseipdb=abuseipdb_enrich,
        urlhaus=urlhaus_enrich,
    )


@pytest.fixture()
def view02(test_data, mock_ipwhois_get, mock_shodan_get_ip, mock_greynoise_get):
    """1.1.1.1 with Shodan and Greynoise. Test the whole IP panel."""
    ip = "1.1.1.1"
    geoasn_pool = json.loads(test_data("ipwhois_1.1.1.1.json"))
    geoasn_client = IpWhoisClient()
    geoasn_client._get_ipwhois = MagicMock(
        side_effect=lambda ip: mock_ipwhois_get(ip, geoasn_pool)
    )
    geoasn_enrich = geoasn_client.enrich_ips(ip)

    shodan_pool = json.loads(test_data("shodan_1.1.1.1.json"))
    shodan_client = ShodanClient(MagicMock())
    shodan_client._get_ip = MagicMock(
        side_effect=lambda ip: mock_shodan_get_ip(ip, shodan_pool)
    )
    shodan_enrich = shodan_client.enrich_ips(ip)

    greynoise_pool = json.loads(test_data("greynoise_1.1.1.1.json"))
    greynoise_client = GreynoiseClient("dummykey")
    greynoise_client._get_ip = MagicMock(
        side_effect=lambda ip: mock_greynoise_get(ip, greynoise_pool)
    )
    greynoise_enrich = greynoise_client.enrich_ips(ip)

    return IpAddressView(
        console=Console(),
        entity=IpAddress.model_validate(json.loads(test_data("vt_ip_1.1.1.1.json"))),
        geoasn=geoasn_enrich,
        whois=MagicMock(),
        shodan=shodan_enrich,
        greynoise=greynoise_enrich,
        abuseipdb=MagicMock(),
        urlhaus=UrlHausMap.model_validate({}),
    )


@pytest.fixture()
def view03(test_data):
    """1.1.1.1 VT whois. Whois panel test only."""
    return IpAddressView(
        console=Console(),
        entity=MagicMock(),
        geoasn=MagicMock(),
        whois=VTWhois.model_validate(json.loads(test_data("vt_whois_1.1.1.1.json"))),
        shodan=MagicMock(),
        greynoise=MagicMock(),
        abuseipdb=MagicMock(),
        urlhaus=MagicMock(),
    )


@pytest.fixture()
def view04(test_data):
    """
    142.251.220.110. Test whole IP panel with 0 malicious, 0 reputation and no IP and
    Greynoise enrichment.
    """
    return IpAddressView(
        console=Console(),
        entity=IpAddress.model_validate(
            json.loads(test_data("vt_ip_142.251.220.110.json"))
        ),
        geoasn=IpWhoisMap.model_validate({}),
        whois=MagicMock(),
        shodan=MagicMock(),
        greynoise=GreynoiseIpMap.model_validate({}),
        abuseipdb=MagicMock(),
        urlhaus=UrlHausMap.model_validate({}),
    )


@pytest.fixture()
def view05(test_data, mock_greynoise_get):
    """1.1.1.1 with alt Greynoise results. Test Greynoise only."""
    ip = "1.1.1.1"
    greynoise_pool = json.loads(test_data("greynoise_1.1.1.1_malicious.json"))
    greynoise_client = GreynoiseClient("dummykey")
    greynoise_client._get_ip = MagicMock(
        side_effect=lambda ip: mock_greynoise_get(ip, greynoise_pool)
    )
    greynoise_enrich = greynoise_client.enrich_ips(ip)

    return IpAddressView(
        console=Console(),
        entity=IpAddress.model_validate(json.loads(test_data("vt_ip_1.1.1.1.json"))),
        geoasn=IpWhoisMap.model_validate({}),
        whois=MagicMock(),
        shodan=MagicMock(),
        greynoise=greynoise_enrich,
        abuseipdb=MagicMock(),
        urlhaus=UrlHausMap.model_validate({}),
    )


@pytest.fixture()
def view06(test_data, mock_greynoise_get):
    """1.1.1.1 with another alt Greynoise result (unknown class).
    Test Greynoise only."""
    ip = "1.1.1.1"
    greynoise_pool = json.loads(test_data("greynoise_1.1.1.1_unknown.json"))
    greynoise_client = GreynoiseClient("dummykey")
    greynoise_client._get_ip = MagicMock(
        side_effect=lambda ip: mock_greynoise_get(ip, greynoise_pool)
    )
    greynoise_enrich = greynoise_client.enrich_ips(ip)

    return IpAddressView(
        console=Console(),
        entity=IpAddress.model_validate(json.loads(test_data("vt_ip_1.1.1.1.json"))),
        geoasn=IpWhoisMap.model_validate({}),
        whois=MagicMock(),
        shodan=MagicMock(),
        greynoise=greynoise_enrich,
        abuseipdb=MagicMock(),
        urlhaus=MagicMock(),
    )


@pytest.fixture()
def view07(test_data, mock_abuseipdb_get):
    """1.1.1.1 with green AbuseIPDB score. Test AbuseIPDB only."""
    ip = "1.1.1.1"
    abuseipdb_pool = json.loads(test_data("abuseipdb_1.1.1.1_green.json"))
    abuseipdb_client = AbuseIpDbClient("dummykey")
    abuseipdb_client._get_ip = MagicMock(
        side_effect=lambda ip: mock_abuseipdb_get(ip, abuseipdb_pool)
    )
    abuseipdb_enrich = abuseipdb_client.enrich_ips(ip)

    return IpAddressView(
        console=Console(),
        entity=IpAddress.model_validate(json.loads(test_data("vt_ip_1.1.1.1.json"))),
        geoasn=IpWhoisMap.model_validate({}),
        whois=MagicMock(),
        shodan=MagicMock(),
        greynoise=MagicMock(),
        abuseipdb=abuseipdb_enrich,
        urlhaus=MagicMock(),
    )


@pytest.fixture()
def view08(test_data, mock_abuseipdb_get):
    """1.1.1.1 with yellow AbuseIPDB score. Test AbuseIPDB only."""
    ip = "1.1.1.1"
    abuseipdb_pool = json.loads(test_data("abuseipdb_1.1.1.1_yellow.json"))
    abuseipdb_client = AbuseIpDbClient("dummykey")
    abuseipdb_client._get_ip = MagicMock(
        side_effect=lambda ip: mock_abuseipdb_get(ip, abuseipdb_pool)
    )
    abuseipdb_enrich = abuseipdb_client.enrich_ips(ip)

    return IpAddressView(
        console=Console(),
        entity=IpAddress.model_validate(json.loads(test_data("vt_ip_1.1.1.1.json"))),
        geoasn=IpWhoisMap.model_validate({}),
        whois=MagicMock(),
        shodan=MagicMock(),
        greynoise=MagicMock(),
        abuseipdb=abuseipdb_enrich,
        urlhaus=MagicMock(),
    )


class TestView01:
    def test_ip_panel(self, view01, theme, display_timestamp):
        ip = view01.ip_panel()
        assert type(ip) is Panel
        assert ip.title == Text("1.1.1.1")
        assert ip.title.style == theme.panel_title

        # Sections
        vt_section = ip.renderable.renderables[0]
        geoasn_section = ip.renderable.renderables[2]
        shodan_section = ip.renderable.renderables[4]
        urlhaus_section = ip.renderable.renderables[6]
        other_section = ip.renderable.renderables[8]

        # Line breaks between sections
        assert ip.renderable.renderables[1] == ""
        assert ip.renderable.renderables[3] == ""
        assert ip.renderable.renderables[5] == ""

        #
        # VT section
        #

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
                    Span(0, 8, "link https://virustotal.com/gui/ip-address/1.1.1.1")
                ],
            ),
            "Reputation:",
            "Updated:",
        ]
        assert table.columns[1].style == theme.table_value
        assert table.columns[1].justify == "left"
        assert table.columns[1]._cells == [
            Text(
                (
                    "4/94 malicious\nCMC Threat Intelligence, Comodo Valkyrie Verdict, "
                    "CRDF, Blueliv"
                ),
                spans=[
                    Span(0, 14, theme.error),
                    Span(15, 38, theme.vendor_list),
                    Span(38, 40, "default"),
                    Span(40, 63, theme.vendor_list),
                    Span(63, 65, "default"),
                    Span(65, 69, theme.vendor_list),
                    Span(69, 71, "default"),
                    Span(71, 78, theme.vendor_list),
                ],
            ),
            Text("134"),
            display_timestamp("2022-09-03T06:47:04Z"),
        ]

        #
        # IP location and ASN section
        #

        # Heading
        assert geoasn_section.renderables[0] == Text("IPWhois")
        assert geoasn_section.renderables[0].style == theme.heading_h1

        # Table
        table = geoasn_section.renderables[1]
        assert type(table) is Table
        assert table.columns[0].style == theme.table_field
        assert table.columns[0].justify == "left"
        assert table.columns[0]._cells == [
            "ASN:",
            "ISP:",
            "Location:",
        ]
        assert table.columns[1].style == theme.table_value
        assert table.columns[1].justify == "left"
        assert table.columns[1]._cells == [
            Text(
                "13335 (APNIC and Cloudflare DNS Resolver project)",
                spans=[Span(7, 48, theme.asn_org)],
            ),
            "Cloudflare, Inc.",
            Text(
                "Sydney, New South Wales, Australia",
                spans=[
                    Span(6, 8, "default"),
                    Span(23, 25, "default"),
                ],
            ),
        ]

        #
        # Shodan section
        #

        # Heading
        assert shodan_section.renderables[0] == Text("Shodan")
        assert shodan_section.renderables[0].style == theme.heading_h1

        # Table
        table = shodan_section.renderables[1]
        assert type(table) is Table
        assert table.columns[0].style == theme.table_field
        assert table.columns[0].justify == "left"
        assert table.columns[0]._cells == [
            Text(
                "Services:",
                spans=[Span(0, 8, "link https://www.shodan.io/host/1.1.1.1")],
            ),
            "Last Scan:",
        ]
        assert table.columns[1].style == theme.table_value
        assert table.columns[1].justify == "left"
        assert table.columns[1]._cells == [
            Text(
                (
                    "Cisco router tftpd (69/udp)\n"
                    "CloudFlare (80/tcp, 8080/tcp, 8880/tcp)\n"
                    "DrayTek Vigor Router (443/tcp)\n"
                    "Other (53/tcp, 53/udp, 161/udp, 2082/tcp, 2083/tcp, 2086/tcp, "
                    "2087/tcp, 8443/tcp)"
                ),
                spans=[
                    Span(0, 18, theme.product),
                    Span(20, 22, theme.port),
                    Span(22, 26, theme.transport),
                    Span(28, 38, theme.product),
                    Span(40, 42, theme.port),
                    Span(42, 46, theme.transport),
                    Span(46, 48, "default"),
                    Span(48, 52, theme.port),
                    Span(52, 56, theme.transport),
                    Span(56, 58, "default"),
                    Span(58, 62, theme.port),
                    Span(62, 66, theme.transport),
                    Span(68, 88, theme.product),
                    Span(90, 93, theme.port),
                    Span(93, 97, theme.transport),
                    Span(99, 104, theme.product),
                    Span(106, 108, theme.port),
                    Span(108, 112, theme.transport),
                    Span(112, 114, "default"),
                    Span(114, 116, theme.port),
                    Span(116, 120, theme.transport),
                    Span(120, 122, "default"),
                    Span(122, 125, theme.port),
                    Span(125, 129, theme.transport),
                    Span(129, 131, "default"),
                    Span(131, 135, theme.port),
                    Span(135, 139, theme.transport),
                    Span(139, 141, "default"),
                    Span(141, 145, theme.port),
                    Span(145, 149, theme.transport),
                    Span(149, 151, "default"),
                    Span(151, 155, theme.port),
                    Span(155, 159, theme.transport),
                    Span(159, 161, "default"),
                    Span(161, 165, theme.port),
                    Span(165, 169, theme.transport),
                    Span(169, 171, "default"),
                    Span(171, 175, theme.port),
                    Span(175, 179, theme.transport),
                ],
            ),
            display_timestamp("2022-09-04T01:03:56Z"),
        ]

        #
        # Urlhaus section
        #

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
                spans=[Span(0, 12, "link https://urlhaus.abuse.ch/host/1.1.1.1/")],
            ),
            "Blocklists:",
            "Tags:",
        ]
        assert table.columns[1].style == theme.table_value
        assert table.columns[1].justify == "left"
        print(table.columns[1])
        assert table.columns[1]._cells == [
            Text(
                "10 online (10 total)",
                spans=[
                    Span(0, 9, theme.error),
                    Span(9, 20, theme.table_value),
                ],
            ),
            Text(
                "not listed in spamhaus\nnot listed in surbl",
                spans=[
                    Span(0, 10, theme.urlhaus_bl_low),
                    Span(14, 22, theme.urlhaus_bl_name),
                    Span(23, 33, theme.urlhaus_bl_low),
                    Span(37, 42, theme.urlhaus_bl_name),
                ],
            ),
            Text(
                "elf, mirai",
                spans=[
                    Span(0, 3, theme.tags),
                    Span(3, 5, "default"),
                    Span(5, 10, theme.tags),
                ],
            ),
        ]

        #
        # Other section
        #

        # Heading
        assert other_section.renderables[0] == Text("Other")
        assert other_section.renderables[0].style == theme.heading_h1

        # Table
        table = other_section.renderables[1]
        assert type(table) is Table
        assert table.columns[0].style == theme.table_field
        assert table.columns[0].justify == "left"
        assert table.columns[0]._cells == [
            Text(
                "GreyNoise:",
                spans=[Span(0, 9, "link https://viz.greynoise.io/riot/1.1.1.1")],
            ),
            Text(
                "AbuseIPDB:",
                spans=[Span(0, 9, "link https://www.abuseipdb.com/check/1.1.1.1")],
            ),
        ]
        assert table.columns[1].style == theme.table_value
        assert table.columns[1].justify == "left"
        assert table.columns[1]._cells == [
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

    def test_whois_panel(self, view01, theme):
        whois = view01.whois_panel()
        assert type(whois) is Panel
        assert whois.title is None

        # Sections
        title = whois.renderable.renderables[0]
        content = whois.renderable.renderables[1]

        # Title
        assert title == Text("Whois")
        assert title.style == theme.heading_h1

        # Heading
        assert content.renderables[0] == Text(
            "one.one",
            spans=[Span(0, 7, theme.heading_h2)],
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
            "Country:",
            "Postcode:",
            "Nameservers:",
            "DNSSEC:",
            "Registered:",
            "Updated:",
            "Expires:",
        ]
        assert table.columns[1].style == theme.table_value
        assert table.columns[1].justify == "left"
        assert [str(c) for c in table.columns[1]._cells] == [
            "One.com A/S - ONE",
            "One.com A/S",
            "REDACTED FOR PRIVACY",
            (
                "Please query the RDDS service of the Registrar of Record identified in "
                "this output for information on how to contact the Registrant, Admin, or "
                "Tech contact of the queried domain name."
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
        assert ip.title == Text("1.1.1.1")

        # Sections
        vt_section = ip.renderable.renderables[0]
        geoasn_section = ip.renderable.renderables[2]
        shodan_section = ip.renderable.renderables[4]
        other_section = ip.renderable.renderables[6]

        # Line breaks between sections
        assert ip.renderable.renderables[1] == ""
        assert ip.renderable.renderables[3] == ""

        #
        # VT section
        #

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
                    Span(0, 8, "link https://virustotal.com/gui/ip-address/1.1.1.1")
                ],
            ),
            "Reputation:",
            "Updated:",
        ]
        assert table.columns[1].style == theme.table_value
        assert table.columns[1].justify == "left"
        assert table.columns[1]._cells == [
            Text(
                (
                    "4/94 malicious\nCMC Threat Intelligence, Comodo Valkyrie Verdict, "
                    "CRDF, Blueliv"
                ),
                spans=[
                    Span(0, 14, theme.error),
                    Span(15, 38, theme.vendor_list),
                    Span(38, 40, "default"),
                    Span(40, 63, theme.vendor_list),
                    Span(63, 65, "default"),
                    Span(65, 69, theme.vendor_list),
                    Span(69, 71, "default"),
                    Span(71, 78, theme.vendor_list),
                ],
            ),
            Text("134"),
            display_timestamp("2022-09-03T06:47:04Z"),
        ]

        #
        # IP location and ASN section
        #

        # Heading
        assert geoasn_section.renderables[0] == Text("IPWhois")
        assert geoasn_section.renderables[0].style == theme.heading_h1

        # Table
        table = geoasn_section.renderables[1]
        assert type(table) is Table
        assert table.columns[0].style == theme.table_field
        assert table.columns[0].justify == "left"
        assert table.columns[0]._cells == [
            "ASN:",
            "ISP:",
            "Location:",
        ]
        assert table.columns[1].style == theme.table_value
        assert table.columns[1].justify == "left"
        assert table.columns[1]._cells == [
            Text(
                "13335 (APNIC and Cloudflare DNS Resolver project)",
                spans=[Span(7, 48, theme.asn_org)],
            ),
            "Cloudflare, Inc.",
            Text(
                "Sydney, New South Wales, Australia",
                spans=[Span(6, 8, "default"), Span(23, 25, "default")],
            ),
        ]

        #
        # Shodan section
        #

        # Heading
        assert shodan_section.renderables[0] == Text("Shodan")
        assert shodan_section.renderables[0].style == theme.heading_h1

        # Table
        table = shodan_section.renderables[1]
        assert type(table) is Table
        assert table.columns[0].style == theme.table_field
        assert table.columns[0].justify == "left"
        assert table.columns[0]._cells == [
            Text(
                "Services:",
                spans=[Span(0, 8, "link https://www.shodan.io/host/1.1.1.1")],
            ),
            "Last Scan:",
        ]
        assert table.columns[1].style == theme.table_value
        assert table.columns[1].justify == "left"
        assert table.columns[1]._cells == [
            Text(
                (
                    "Cisco router tftpd (69/udp)\n"
                    "CloudFlare (80/tcp, 8080/tcp, 8880/tcp)\n"
                    "DrayTek Vigor Router (443/tcp)\nOther (53/tcp, 53/udp, 161/udp, "
                    "2082/tcp, 2083/tcp, 2086/tcp, 2087/tcp, 8443/tcp)"
                ),
                spans=[
                    Span(0, 18, theme.product),
                    Span(20, 22, theme.port),
                    Span(22, 26, theme.transport),
                    Span(28, 38, theme.product),
                    Span(40, 42, theme.port),
                    Span(42, 46, theme.transport),
                    Span(46, 48, "default"),
                    Span(48, 52, theme.port),
                    Span(52, 56, theme.transport),
                    Span(56, 58, "default"),
                    Span(58, 62, theme.port),
                    Span(62, 66, theme.transport),
                    Span(68, 88, theme.product),
                    Span(90, 93, theme.port),
                    Span(93, 97, theme.transport),
                    Span(99, 104, theme.product),
                    Span(106, 108, theme.port),
                    Span(108, 112, theme.transport),
                    Span(112, 114, "default"),
                    Span(114, 116, theme.port),
                    Span(116, 120, theme.transport),
                    Span(120, 122, "default"),
                    Span(122, 125, theme.port),
                    Span(125, 129, theme.transport),
                    Span(129, 131, "default"),
                    Span(131, 135, theme.port),
                    Span(135, 139, theme.transport),
                    Span(139, 141, "default"),
                    Span(141, 145, theme.port),
                    Span(145, 149, theme.transport),
                    Span(149, 151, "default"),
                    Span(151, 155, theme.port),
                    Span(155, 159, theme.transport),
                    Span(159, 161, "default"),
                    Span(161, 165, theme.port),
                    Span(165, 169, theme.transport),
                    Span(169, 171, "default"),
                    Span(171, 175, theme.port),
                    Span(175, 179, theme.transport),
                ],
            ),
            display_timestamp("2022-09-04T01:03:56Z"),
        ]

        #
        # Other section
        #

        # Heading
        assert other_section.renderables[0] == Text("Other")
        assert other_section.renderables[0].style == theme.heading_h1

        # Table
        table = other_section.renderables[1]
        assert type(table) is Table
        assert table.columns[0].style == theme.table_field
        assert table.columns[0].justify == "left"
        assert table.columns[0]._cells == [
            Text(
                "GreyNoise:",
                spans=[Span(0, 9, "link https://viz.greynoise.io/riot/1.1.1.1")],
            ),
        ]
        assert table.columns[1].style == theme.table_value
        assert table.columns[1].justify == "left"
        assert table.columns[1]._cells == [
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

        # Content
        assert content.renderables[0] == Text(
            "one.one",
            spans=[Span(0, 7, "bold yellow")],
        )

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
            "Country:",
            "Postcode:",
            "Nameservers:",
            "DNSSEC:",
            "Registered:",
            "Updated:",
            "Expires:",
        ]
        assert table.columns[1].style == theme.table_value
        assert table.columns[1].justify == "left"
        assert [str(c) for c in table.columns[1]._cells] == [
            "One.com A/S - ONE",
            "One.com A/S",
            "REDACTED FOR PRIVACY",
            (
                "Please query the RDDS service of the Registrar of Record identified "
                "in this output for information on how to contact the Registrant, "
                "Admin, or Tech contact of the queried domain name."
            ),
            "REDACTED FOR PRIVACY",
            "REDACTED FOR PRIVACY",
            "REDACTED FOR PRIVACY",
            "dk",
            "REDACTED FOR PRIVACY",
            (
                "* a response from the service that a domain name is 'available', does "
                "not guarantee that is able to be registered,, * we may restrict, "
                "suspend or terminate your access to the service at any time, and, "
                "* the copying, compilation, repackaging, dissemination or other use "
                "of the information provided by the service is not permitted, without "
                "our express written consent., this information has been prepared and "
                "published in order to represent administrative and technical "
                "management of the tld., we may discontinue or amend any part or the "
                "whole of these terms of service from time to time at our absolute "
                "discretion."
            ),
            "signedDelegation",
            "2015-05-20T12:15:44Z",
            "2021-07-04T12:15:49Z",
            "2022-05-20T12:15:44Z",
        ]


class TestView04:
    def test_ip_panel(self, view04, theme, display_timestamp):
        ip = view04.ip_panel()
        assert type(ip) is Panel
        assert ip.title == Text("142.251.220.110")

        # Sections
        vt_section = ip.renderable.renderables[0]

        #
        # VT section
        #

        # Heading
        assert vt_section.renderables[0] == Text("VirusTotal")

        # Table
        table = vt_section.renderables[1]
        assert type(table) is Table
        assert table.columns[0].style == theme.table_field
        assert table.columns[0].justify == "left"
        assert table.columns[0]._cells == [
            Text(
                "Analysis:",
                spans=[
                    Span(
                        0,
                        8,
                        "link https://virustotal.com/gui/ip-address/142.251.220.110",
                    )
                ],
            ),
            "Reputation:",
            "Updated:",
        ]
        assert table.columns[1].style == theme.table_value
        assert table.columns[1].justify == "left"
        assert table.columns[1]._cells == [
            Text("0/93 malicious", spans=[Span(0, 14, theme.info)]),
            Text("0"),
            display_timestamp("2022-09-03T16:58:45Z"),
        ]


class TestView05:
    def test_ip_panel_greynoise_only(self, view05, theme):
        ip = view05.ip_panel()

        other_section = ip.renderable.renderables[2]

        # Table
        table = other_section.renderables[1]
        assert table.columns[1]._cells[-1] == Text(
            "✗ riot  ✓ noise  ! malicious",
            spans=[
                Span(0, 1, theme.warn),
                Span(2, 6, theme.tags),
                Span(8, 9, theme.info),
                Span(10, 15, theme.tags),
                Span(17, 18, theme.error),
                Span(19, 28, theme.tags_red),
            ],
        )


class TestView06:
    def test_ip_panel_greynoise_only(self, view06, theme):
        ip = view06.ip_panel()

        other_section = ip.renderable.renderables[2]

        # Table
        table = other_section.renderables[1]
        assert table.columns[1]._cells[-1] == Text(
            "✓ riot  ✗ noise  ? unknown",
            spans=[
                Span(0, 1, theme.info),
                Span(2, 6, theme.tags),
                Span(8, 9, theme.warn),
                Span(10, 15, theme.tags),
                Span(19, 26, theme.tags),
            ],
        )


class TestAbuseIpDbOnly:
    def test_abuseipdb_green(self, view07, theme):
        ip = view07.ip_panel()

        other_section = ip.renderable.renderables[2]

        # Table
        table = other_section.renderables[1]
        assert table.columns[1]._cells[-1] == Text(
            "0 confidence score",
            spans=[
                Span(0, 1, theme.info),
                Span(1, 18, "green"),
            ],
        )

    def test_abuseipdb_yellow(self, view08, theme):
        ip = view08.ip_panel()

        other_section = ip.renderable.renderables[2]

        # Table
        table = other_section.renderables[1]
        assert table.columns[1]._cells[-1] == Text(
            "30 confidence score (567 reports)",
            spans=[
                Span(0, 2, theme.warn),
                Span(2, 19, "yellow"),
                Span(19, 33, theme.table_value),
            ],
        )
