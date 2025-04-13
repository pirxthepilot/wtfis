import abc
from typing import Any, Generator, List, Optional, Tuple, Union

from rich.console import Console, Group, RenderableType, group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from wtfis.exceptions import WtfisException
from wtfis.models.abuseipdb import AbuseIpDb, AbuseIpDbMap
from wtfis.models.base import WhoisBase
from wtfis.models.greynoise import GreynoiseIp, GreynoiseIpMap
from wtfis.models.shodan import ShodanIp, ShodanIpMap
from wtfis.models.types import IpGeoAsnMapType, IpGeoAsnType
from wtfis.models.urlhaus import UrlHaus, UrlHausMap
from wtfis.models.virustotal import LastAnalysisStats, PopularityRanks
from wtfis.ui.theme import Theme
from wtfis.utils import Timestamp, is_ip, smart_join


class BaseView(abc.ABC):
    """
    Handles the look of the output
    """

    vt_gui_baseurl_domain = "https://virustotal.com/gui/domain"
    vt_gui_baseurl_ip = "https://virustotal.com/gui/ip-address"
    pt_gui_baseurl = "https://community.riskiq.com/search"
    shodan_gui_baseurl = "https://www.shodan.io/host"

    def __init__(
        self,
        console: Console,
        entity: Any,
        geoasn: IpGeoAsnMapType,
        whois: Optional[WhoisBase],
        shodan: ShodanIpMap,
        greynoise: GreynoiseIpMap,
        abuseipdb: AbuseIpDbMap,
        urlhaus: UrlHausMap,
    ) -> None:
        self.console = console
        self.entity = entity
        self.geoasn = geoasn
        self.whois = whois
        self.shodan = shodan
        self.greynoise = greynoise
        self.abuseipdb = abuseipdb
        self.urlhaus = urlhaus
        self.theme = Theme()

    def _vendors_who_flagged_malicious(self) -> List[str]:
        vendors = []
        for (
            key,
            result,
        ) in self.entity.data.attributes.last_analysis_results.root.items():
            if result.category == "malicious":
                vendors.append(key)
        return vendors

    def _gen_heading_text(
        self, heading: str, hyperlink: Optional[str] = None, type: Optional[str] = "h1"
    ) -> Text:
        """Heading text
        Generates 2 types:
            "h1": Style is applied across the entire line
            "h2": Style is applied to the text only
        """
        link_style = f" link {hyperlink}" if hyperlink else ""
        if type == "h1":
            return Text(
                heading, style=f"{self.theme.heading_h1}{link_style}", justify="center"
            )
        elif type == "h2":
            text = Text(justify="center")
            return text.append(heading, style=f"{self.theme.heading_h2}{link_style}")
        else:  # pragma: no cover
            raise WtfisException(f'Invalid heading type "{type}"')

    def _gen_linked_field_name(self, name: str, hyperlink: str) -> Text:
        text = Text(style=self.theme.table_field)
        text.append(name, style=f"link {hyperlink}")
        text.append(":")
        return text

    def _gen_table(
        self, *params: Tuple[Union[Text, str], Union[RenderableType, None]]
    ) -> Union[Table, str]:
        """Each param should be a tuple of (field, value)"""
        # Set up table
        grid = Table.grid(expand=False, padding=(0, 1))
        grid.add_column(style=self.theme.table_field)  # Field
        grid.add_column(
            style=self.theme.table_value, max_width=38, overflow="fold"
        )  # Value

        # Populate rows
        valid_rows = 0
        for item in params:
            field, value = item
            if value is None or str(value) == "":  # Skip if no value
                continue
            grid.add_row(field, value)
            valid_rows += 1

        # Return empty string if no rows generated
        return grid if valid_rows > 0 else ""

    @group()
    def _gen_group(self, content: List[RenderableType]) -> Generator:
        for item in content:
            yield item

    @staticmethod
    def _gen_section(
        body: RenderableType, heading: Optional[Text] = None
    ) -> RenderableType:
        """A section is a subset of a panel, with its own title and content"""
        return Group(heading, body) if heading else body

    def _gen_panel(
        self,
        renderable: RenderableType,
        title: Optional[str] = None,
    ) -> Panel:
        if title is not None:
            panel_title = Text(title, style=self.theme.panel_title)
            return Panel(renderable, title=panel_title, expand=False)
        return Panel(renderable, expand=False)

    def _gen_vt_analysis_stats(
        self, stats: LastAnalysisStats, vendors: Optional[List[str]] = None
    ) -> Text:
        # Custom style
        stats_style = self.theme.error if stats.malicious >= 1 else self.theme.info

        # Total count
        total = (
            stats.harmless
            + stats.malicious
            + stats.suspicious
            + stats.timeout
            + stats.undetected
        )

        # Text
        text = Text()
        text.append(Text(f"{stats.malicious}/{total} malicious", style=stats_style))

        # Include list of vendors that flagged malicious
        if vendors:
            text.append("\n")
            text.append(smart_join(*vendors, style=self.theme.vendor_list))

        return text

    def _gen_vt_reputation(self, reputation: int) -> Text:
        # Custom style
        def rep_style(reputation: int) -> str:
            if reputation > 0:
                return self.theme.info
            elif reputation < 0:
                return self.theme.error
            return "default"

        return Text(str(reputation), style=rep_style(reputation))

    def _gen_vt_popularity(self, popularity_ranks: PopularityRanks) -> Optional[Text]:
        if len(popularity_ranks.root) == 0:
            return None

        text = Text()
        for source, popularity in popularity_ranks.root.items():
            text.append(source, style=self.theme.popularity_source)
            text.append(" (")
            text.append(str(popularity.rank), style=self.theme.inline_stat)
            text.append(")")
            if source != list(popularity_ranks.root.keys())[-1]:
                text.append("\n")
        return text

    def _gen_shodan_services(self, ip: ShodanIp) -> Optional[Union[Text, str]]:
        if len(ip.data) == 0:
            return None

        # Styling for port/transport list
        def ports_stylized(ports: list) -> Generator:
            for port in ports:
                yield (
                    Text()
                    .append(str(port.port), style=self.theme.port)
                    .append(f"/{port.transport}", style=self.theme.transport)
                )

        # Grouped list
        grouped = ip.group_ports_by_product()

        # Return a simple port list if no identified ports
        if len(list(grouped.keys())) == 1 and list(grouped.keys())[0] == "Other":
            return smart_join(*ports_stylized(grouped["Other"]))

        # Return grouped display of there are identified ports
        text = Text()
        for product, ports in grouped.items():
            text.append(product, style=self.theme.product)
            text.append(" (")
            text.append(smart_join(*ports_stylized(ports)))
            text.append(")")
            if product != list(grouped.keys())[-1]:
                text.append("\n")
        return text

    def _gen_greynoise_tuple(self, ip: GreynoiseIp) -> Tuple[Text, Text]:
        #
        # Title
        #
        title = self._gen_linked_field_name("GreyNoise", hyperlink=ip.link)

        #
        # Content
        #
        text_style = self.theme.tags
        true_style = self.theme.info
        false_style = self.theme.warn

        text = Text()

        # RIOT
        riot_icon = (
            Text("✓", style=true_style)
            if ip.riot is True
            else Text("✗", style=false_style)
        )
        (
            text.append(riot_icon)
            .append(" ")
            .append(Text("riot", style=text_style))
            .append("  ")
        )

        # Noise
        noise_icon = (
            Text("✓", style=true_style)
            if ip.noise is True
            else Text("✗", style=false_style)
        )
        (text.append(noise_icon).append(" ").append(Text("noise", style=text_style)))

        # Classification
        if ip.classification:
            text.append("  ")
            if ip.classification == "benign":
                (
                    text.append(Text("✓", style=self.theme.info))
                    .append(" ")
                    .append(Text("benign", style=self.theme.tags_green))
                )
            elif ip.classification == "malicious":
                (
                    text.append(Text("!", style=self.theme.error))
                    .append(" ")
                    .append(Text("malicious", style=self.theme.tags_red))
                )
            else:
                (text.append("? ").append(Text(ip.classification, style=text_style)))

        return title, text

    def _gen_abuseipdb_tuple(self, ip: AbuseIpDb) -> Tuple[Text, Text]:

        #
        # Title
        #
        title = self._gen_linked_field_name(
            "AbuseIPDB", hyperlink=f"https://www.abuseipdb.com/check/{ip.ip_address}"
        )

        #
        # Content
        #

        if ip.abuse_confidence_score == 0:
            style = self.theme.info
        elif ip.abuse_confidence_score <= 30:
            style = self.theme.warn
        else:
            style = self.theme.error

        text = Text()
        (
            text.append(Text(str(ip.abuse_confidence_score), style=style)).append(
                " confidence score", style=style.replace("bold ", "")
            )
        )

        if ip.abuse_confidence_score > 0:
            text.append(f" ({ip.total_reports} reports)", style=self.theme.table_value)

        return title, text

    def _gen_asn_text(
        self,
        asn: Optional[str],
        org: Optional[RenderableType],
    ) -> Optional[RenderableType]:
        if asn == "0" or not asn:
            return None

        text = Text()
        (
            text.append(f"{asn.replace('AS', '')} (")
            .append(str(org), style=self.theme.asn_org)
            .append(")")
        )
        return text

    def _get_geoasn_enrichment(self, ip: str) -> Optional[IpGeoAsnType]:
        return self.geoasn.root[ip] if ip in self.geoasn.root.keys() else None

    def _get_shodan_enrichment(self, ip: str) -> Optional[ShodanIp]:
        return self.shodan.root[ip] if ip in self.shodan.root.keys() else None

    def _get_greynoise_enrichment(self, ip: str) -> Optional[GreynoiseIp]:
        return self.greynoise.root[ip] if ip in self.greynoise.root.keys() else None

    def _get_abuseipdb_enrichment(self, ip: str) -> Optional[AbuseIpDb]:
        return self.abuseipdb.root[ip] if ip in self.abuseipdb.root.keys() else None

    def _get_urlhaus_enrichment(self, entity: str) -> Optional[UrlHaus]:
        return self.urlhaus.root[entity] if entity in self.urlhaus.root.keys() else None

    def _gen_vt_section(self) -> RenderableType:
        """Virustotal section. Applies to both domain and IP views"""
        attributes = self.entity.data.attributes
        baseurl = (
            self.vt_gui_baseurl_ip
            if is_ip(self.entity.data.id_)
            else self.vt_gui_baseurl_domain
        )

        # Analysis (IP and domain)
        analysis = self._gen_vt_analysis_stats(
            attributes.last_analysis_stats, self._vendors_who_flagged_malicious()
        )
        analysis_field = self._gen_linked_field_name(
            "Analysis", hyperlink=f"{baseurl}/{self.entity.data.id_}"
        )

        # Reputation (IP and domain)
        reputation = self._gen_vt_reputation(attributes.reputation)

        data: List[Tuple[Union[str, Text], Union[RenderableType, None]]] = [
            (analysis_field, analysis),
            ("Reputation:", reputation),
        ]

        # Popularity (Domain only)
        if hasattr(attributes, "popularity_ranks"):
            data += [
                ("Popularity:", self._gen_vt_popularity(attributes.popularity_ranks))
            ]

        # Categories (Domain only)
        if hasattr(attributes, "categories"):
            data += [
                (
                    "Categories:",
                    (
                        smart_join(*attributes.categories, style=self.theme.tags)
                        if attributes.categories
                        else None
                    ),
                )
            ]

        # Updated (IP and domain)
        data += [("Updated:", Timestamp(attributes.last_modification_date).render)]

        # Last seen (Domain only)
        if hasattr(attributes, "last_dns_records_date"):
            data += [("Last Seen:", Timestamp(attributes.last_dns_records_date).render)]

        return self._gen_section(
            self._gen_table(*data), self._gen_heading_text("VirusTotal")
        )

    def _gen_geoasn_section(self) -> Optional[RenderableType]:
        """IP location and ASN section. Applies to IP views only"""
        enrich = self._get_geoasn_enrichment(self.entity.data.id_)

        data: List[Tuple[Union[str, Text], Union[RenderableType, None]]] = []

        if enrich:
            section_title = enrich.source
            asn = self._gen_asn_text(enrich.asn, enrich.org)
            data += [
                ("ASN:", asn),
                ("ISP:", enrich.isp),
                ("Location:", smart_join(enrich.city, enrich.region, enrich.country)),
            ]
            return self._gen_section(
                self._gen_table(*data), self._gen_heading_text(section_title)
            )

        return None  # No enrichment data

    def _gen_shodan_section(self) -> Optional[RenderableType]:
        """Shodan section. Applies to IP views only"""
        enrich = self._get_shodan_enrichment(self.entity.data.id_)

        data: List[Tuple[Union[str, Text], Union[RenderableType, None]]] = []

        if enrich:
            section_title = "Shodan"
            tags = (
                smart_join(*enrich.tags, style=self.theme.tags) if enrich.tags else None
            )
            services_field = self._gen_linked_field_name(
                "Services",
                hyperlink=f"{self.shodan_gui_baseurl}/{self.entity.data.id_}",
            )
            data += [
                ("OS:", enrich.os),
                (services_field, self._gen_shodan_services(enrich)),
                ("Tags:", tags),
                (
                    "Last Scan:",
                    Timestamp(f"{enrich.last_update}+00:00").render,
                ),  # Timestamps are UTC
                # (source: Google)
            ]

            return self._gen_section(
                self._gen_table(*data), self._gen_heading_text(section_title)
            )

        return None  # No enrichment data

    def _gen_urlhaus_section(self) -> Optional[RenderableType]:
        """URLhaus"""

        def bl_text(blocklist: str, status: str) -> Text:
            # https://urlhaus-api.abuse.ch/#hostinfo
            text = Text()
            if status == "not listed":
                text.append(status, self.theme.urlhaus_bl_low)
            elif status.startswith("abused_"):
                text.append(status, self.theme.urlhaus_bl_med)
            elif status.endswith("_domain") or status == "listed":
                text.append(status, self.theme.urlhaus_bl_high)
            else:  # pragma: no cover
                raise WtfisException(f"Invalid URLhaus BL status: {status}")
            text.append(" in ").append(blocklist, style=self.theme.urlhaus_bl_name)
            return text

        enrich = self._get_urlhaus_enrichment(self.entity.data.id_)

        data: List[Tuple[Union[str, Text], Union[RenderableType, None]]] = []

        if enrich:
            malware_urls_field: Union[Text, str] = (
                self._gen_linked_field_name(
                    "Malware URLs",
                    hyperlink=enrich.urlhaus_reference,
                )
                if enrich.urlhaus_reference
                else "Malware URLs:"
            )

            malware_urls_value = Text()
            (
                malware_urls_value.append(
                    (
                        str(enrich.online_url_count)
                        if enrich.url_count and enrich.url_count <= 100
                        else f"{enrich.online_url_count}+"
                    )
                    + " online",
                    style=(
                        self.theme.error
                        if enrich.online_url_count > 0
                        else self.theme.warn
                    ),
                ).append(
                    f" ({enrich.url_count} total)",
                    style=self.theme.table_value,
                )
            )

            tags = (
                smart_join(*enrich.tags, style=self.theme.tags) if enrich.tags else None
            )

            data += [
                (malware_urls_field, malware_urls_value),
                (
                    "Blocklists:",
                    (
                        bl_text(
                            "spamhaus",
                            enrich.blacklists.spamhaus_dbl if enrich.blacklists else "",
                        )
                        + "\n"
                        + bl_text(
                            "surbl",
                            enrich.blacklists.surbl if enrich.blacklists else "",
                        )
                    ),
                ),
                ("Tags:", tags),
            ]

            return self._gen_section(
                self._gen_table(*data), self._gen_heading_text("URLhaus")
            )

        return None  # No enrichment data

    def _gen_ip_other_section(self) -> Optional[RenderableType]:
        """Other section for IP views"""
        data: List[Tuple[Union[str, Text], Union[RenderableType, None]]] = []

        # Greynoise
        greynoise = self._get_greynoise_enrichment(self.entity.data.id_)
        if greynoise:
            data.append(self._gen_greynoise_tuple(greynoise))

        # abuseIPDB
        abuseipdb = self._get_abuseipdb_enrichment(ip=self.entity.data.id_)
        if abuseipdb:
            data.append(self._gen_abuseipdb_tuple(abuseipdb))

        if data:
            return self._gen_section(
                self._gen_table(*data), self._gen_heading_text("Other")
            )

        return None  # No other data

    def whois_panel(self) -> Optional[Panel]:
        # Do nothing if no whois
        if self.whois is None:
            return None

        heading = (
            self._gen_heading_text(
                self.whois.domain,
                hyperlink=None,
                type="h2",
            )
            if self.whois.domain
            else None
        )

        organization = (
            Text(self.whois.organization, style=self.theme.whois_org)
            if self.whois.organization
            else None
        )
        body = self._gen_table(
            ("Registrar:", self.whois.registrar),
            ("Organization:", organization),
            ("Name:", self.whois.name),
            ("Email:", self.whois.email),
            ("Phone:", self.whois.phone),
            ("Street:", self.whois.street),
            ("City:", self.whois.city),
            ("State:", self.whois.state),
            ("Country:", self.whois.country),
            ("Postcode:", self.whois.postal_code),
            (
                "Nameservers:",
                smart_join(*self.whois.name_servers, style=self.theme.nameserver_list),
            ),
            ("DNSSEC:", self.whois.dnssec),
            ("Registered:", Timestamp(self.whois.date_created).render),
            ("Updated:", Timestamp(self.whois.date_changed).render),
            ("Expires:", Timestamp(self.whois.date_expires).render),
        )

        content: List[RenderableType] = [self._gen_heading_text("Whois")]

        if body:
            content.append(self._gen_section(body, heading))
        else:
            content.append(Text("No WHOIS data was found", style=self.theme.disclaimer))
        return self._gen_panel(self._gen_group(content))

    @abc.abstractmethod
    def print(self, one_column: bool = False) -> None:  # pragma: no cover
        pass
