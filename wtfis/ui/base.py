import abc

from rich.console import (
    Console,
    Group,
    RenderableType,
    group,
)
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from typing import Any, Generator, List, Optional, Tuple, Union

from wtfis.models.common import WhoisBase
from wtfis.models.greynoise import GreynoiseIp, GreynoiseIpMap
from wtfis.models.ipwhois import IpWhois, IpWhoisMap
from wtfis.models.shodan import ShodanIp, ShodanIpMap
from wtfis.models.virustotal import (
    LastAnalysisStats,
    PopularityRanks,
)
from wtfis.ui.theme import Theme
from wtfis.utils import Timestamp, smart_join


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
        whois: Optional[WhoisBase],
        ip_enrich: Union[IpWhoisMap, ShodanIpMap],
        greynoise: GreynoiseIpMap,
    ) -> None:
        self.console = console
        self.entity = entity
        self.whois = whois
        self.ip_enrich = ip_enrich
        self.greynoise = greynoise
        self.theme = Theme()

    def _vendors_who_flagged_malicious(self) -> List[str]:
        vendors = []
        for key, result in self.entity.data.attributes.last_analysis_results.root.items():
            if result.category == "malicious":
                vendors.append(key)
        return vendors

    def _gen_heading_text(self, heading: str, hyperlink: Optional[str] = None) -> Text:
        text = Text(justify="center", end="\n")
        style = f"{self.theme.heading} link {hyperlink}" if hyperlink else self.theme.heading
        return text.append(heading, style=style)

    def _gen_linked_field_name(self, name: str, hyperlink: str) -> Text:
        text = Text(style=self.theme.table_field)
        text.append(name, style=f"link {hyperlink}")
        text.append(":")
        return text

    def _gen_table(self, *params: Tuple[Union[Text, str], Union[RenderableType, None]]) -> Union[Table, str]:
        """ Each param should be a tuple of (field, value) """
        # Set up table
        grid = Table.grid(expand=False, padding=(0, 1))
        grid.add_column(style=self.theme.table_field)                                 # Field
        grid.add_column(style=self.theme.table_value, max_width=38, overflow="fold")  # Value

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
    def _gen_info(body: RenderableType, heading: Optional[Text] = None) -> RenderableType:
        return Group(heading, body) if heading else body

    def _gen_panel(self, title: str, renderable: RenderableType) -> Panel:
        panel_title = Text(title, style=self.theme.panel_title)
        return Panel(renderable, title=panel_title, expand=False)

    def _gen_vt_analysis_stats(
        self,
        stats: LastAnalysisStats,
        vendors: Optional[List[str]] = None
    ) -> Text:
        # Custom style
        stats_style = self.theme.error if stats.malicious >= 1 else self.theme.info

        # Total count
        total = stats.harmless + stats.malicious + stats.suspicious + stats.timeout + stats.undetected

        # Text
        text = Text(f"{stats.malicious}/{total} malicious", style=stats_style)

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
        if (
            len(list(grouped.keys())) == 1 and
            list(grouped.keys())[0] == "Other"
        ):
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
        title = self._gen_linked_field_name("Greynoise", hyperlink=ip.link)

        #
        # Content
        #
        text_style = self.theme.tags
        true_style = self.theme.info
        false_style = self.theme.warn

        text = Text()

        # RIOT
        riot_icon = (Text("✓", style=true_style)
                     if ip.riot is True
                     else Text("✗", style=false_style))
        (text
         .append(riot_icon)
         .append(" ")
         .append(Text("riot", style=text_style))
         .append("  "))

        # Noise
        noise_icon = (Text("✓", style=true_style)
                      if ip.noise is True
                      else Text("✗", style=false_style))
        (text
         .append(noise_icon)
         .append(" ")
         .append(Text("noise", style=text_style)))

        # Classification
        if ip.classification:
            text.append("  ")
            if ip.classification == "benign":
                (text
                 .append(Text("✓", style=self.theme.info))
                 .append(" ")
                 .append(Text("benign", style=self.theme.tags_green)))
            elif ip.classification == "malicious":
                (text
                 .append(Text("!", style=self.theme.error))
                 .append(" ")
                 .append(Text("malicious", style=self.theme.tags_red)))
            else:
                (text
                 .append("? ")
                 .append(Text(ip.classification, style=text_style)))

        return title, text

    def _gen_asn_text(
        self,
        asn: Optional[str],
        org: Optional[RenderableType],
    ) -> Optional[RenderableType]:
        if not asn:
            return None

        text = Text(f"{asn.replace('AS', '')} (")
        text.append(str(org), style=self.theme.asn_org)
        text.append(")")
        return text

    def _get_ip_enrichment(self, ip: str) -> Optional[Union[IpWhois, ShodanIp]]:
        return self.ip_enrich.root[ip] if ip in self.ip_enrich.root.keys() else None

    def _get_greynoise_enrichment(self, ip: str) -> Optional[GreynoiseIp]:
        return self.greynoise.root[ip] if ip in self.greynoise.root.keys() else None

    def whois_panel(self) -> Optional[Panel]:
        # Do nothing if no whois
        if self.whois is None:
            return None

        if self.whois.source == "passivetotal":  # PT
            hyperlink = f"{self.pt_gui_baseurl}/{self.whois.domain}/whois"
        else:  # VT
            hyperlink = None

        heading = self._gen_heading_text(
            self.whois.domain,
            hyperlink=hyperlink,
        ) if self.whois.domain else None

        organization = (Text(self.whois.organization, style=self.theme.whois_org)
                        if self.whois.organization else None)
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
            ("Nameservers:", smart_join(*self.whois.name_servers, style=self.theme.nameserver_list)),
            ("DNSSEC:", self.whois.dnssec),
            ("Registered:", Timestamp(self.whois.date_created).render),
            ("Updated:", Timestamp(self.whois.date_changed).render),
            ("Expires:", Timestamp(self.whois.date_expires).render),
        )

        # Return message if no whois data
        if body:
            return self._gen_panel("whois", self._gen_info(body, heading))
        else:
            return self._gen_panel("whois", Text("No whois data found", style=self.theme.disclaimer))

    @abc.abstractmethod
    def print(self, one_column: bool = False) -> None:  # pragma: no cover
        pass
