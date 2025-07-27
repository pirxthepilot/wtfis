from dataclasses import dataclass
from typing import List, Optional, Tuple, Union

from rich.columns import Columns
from rich.console import Group, RenderableType
from rich.padding import Padding
from rich.panel import Panel
from rich.text import Text

from wtfis.models.virustotal import Resolutions
from wtfis.ui.base import BaseView
from wtfis.utils import Timestamp, smart_join


@dataclass
class DomainView(BaseView):
    """
    Handler for FQDN and domain lookup output
    """

    resolutions: Optional[Resolutions]
    max_resolutions: int = 3

    def domain_panel(self) -> Panel:
        content = [self._gen_vt_section()]  # VT section
        for section in (self._gen_urlhaus_section(),):  # URLhaus section
            if section is not None:
                content.append("")
                content.append(section)

        return self._gen_panel(self._gen_group(content), self.entity.data.id_)

    def resolutions_panel(self) -> Optional[Panel]:
        # Skip if no resolutions data
        if not self.resolutions:
            return None

        content: List[RenderableType] = [self._gen_heading_text("Resolutions")]

        for idx, ip in enumerate(self.resolutions.data):
            if idx == self.max_resolutions:
                break
            attributes = ip.attributes

            # Analysis
            analysis = self._gen_vt_analysis_stats(
                attributes.ip_address_last_analysis_stats
            )
            analysis_field = self._gen_linked_field_name(
                "Analysis",
                hyperlink=f"{self.vt_gui_baseurl_ip}/{attributes.ip_address}",
            )

            # Content
            heading = self._gen_heading_text(
                attributes.ip_address,
                # hyperlink=f"{self.vt_gui_baseurl_ip}/{attributes.ip_address}",
                type="h2",
            )
            data: List[Tuple[Union[str, Text], Union[RenderableType, None]]] = [
                (analysis_field, analysis),
                ("Resolved:", Timestamp(attributes.date).render),
            ]

            # IP geolocation and ASN
            geoasn = self._get_geoasn_enrichment(attributes.ip_address)
            if geoasn:
                asn_field: Union[Text, str] = (
                    self._gen_linked_field_name("ASN", hyperlink=geoasn.link)
                    if geoasn.link
                    else "ASN:"
                )
                asn = self._gen_asn_text(geoasn.asn, geoasn.org)
                data += [
                    (asn_field, asn),
                    ("ISP:", geoasn.isp),
                    (
                        "Location:",
                        smart_join(geoasn.city, geoasn.region, geoasn.country),
                    ),
                    ("Hostname:", geoasn.hostname),
                    ("Proxy:", geoasn.is_proxy),
                    ("Anycast:", geoasn.is_anycast),
                ]

            # Shodan
            shodan = self._get_shodan_enrichment(attributes.ip_address)
            if shodan:
                tags = (
                    smart_join(*shodan.tags, style=self.theme.tags)
                    if shodan.tags
                    else None
                )
                services_field = self._gen_linked_field_name(
                    "Services",
                    hyperlink=f"{self.shodan_gui_baseurl}/{attributes.ip_address}",
                )
                data += [
                    ("OS:", shodan.os),
                    (services_field, self._gen_shodan_services(shodan)),
                    ("Tags:", tags),
                    # Timestamps are UTC (source: Google)
                    # ("Last Scan:", Timestamp(f"{shodan.last_update}+00:00").render),
                ]

            # Greynoise
            greynoise = self._get_greynoise_enrichment(attributes.ip_address)
            if greynoise:
                data += [self._gen_greynoise_tuple(greynoise)]

            # AbuseIPDB
            abuseipdb = self._get_abuseipdb_enrichment(attributes.ip_address)
            if abuseipdb:
                data += [self._gen_abuseipdb_tuple(abuseipdb)]

            # Include a disclaimer if last seen is older than 1 year
            # Note: Disabled for now because I originally understood that the
            # resolution date was the last time the domain was resolved, but it may
            # actually be he first time the IP itself was seen with the domain.
            # if enrich and older_than(attributes.date, 365):
            #     body = Group(
            #         self._gen_table(*data),
            #         Text(
            #             "**Enrichment data may be inaccurate",
            #              style=self.theme.disclaimer
            #         ),
            #     )  # type: Union[Group, Table, str]
            # else:
            #     body = self._gen_table(*data)

            body = self._gen_table(*data)
            content.append(self._gen_section(body, heading))

            # Add extra line break if not last item in list
            if idx < self.max_resolutions - 1 and idx < len(self.resolutions.data) - 1:
                content.append("")

        # Info about how many more IPs were not shown
        if self.max_resolutions < self.resolutions.meta.count:
            content.append("")
            content.append(
                Text(justify="center", end="\n").append(
                    f"+{self.resolutions.meta.count - self.max_resolutions} more",
                    style=(
                        f"{self.theme.footer} "
                        f"link {self.vt_gui_baseurl_domain}/{self.entity.data.id_}"
                        "/relations"
                    ),
                )
            )

        # Render results, if existent
        if len(content) > 1:
            return self._gen_panel(self._gen_group(content))

        # No result
        return None

    def print(self, one_column: bool = False) -> None:
        renderables = [
            i
            for i in (
                self.domain_panel(),
                self.resolutions_panel(),
                self.whois_panel(),
            )
            if i is not None
        ]

        if one_column:
            self.console.print(Group(*([""] + renderables)))  # type: ignore
        else:
            self.console.print(Padding(Columns(renderables), (1, 0)))


class IpAddressView(BaseView):
    """
    Handler for IP Address lookup output
    """

    def ip_panel(self) -> Panel:
        content = [self._gen_vt_section()]  # VT section
        for section in (
            self._gen_geoasn_section(),  # IP location and ASN section
            self._gen_shodan_section(),  # Shodan section
            self._gen_urlhaus_section(),  # URLhaus section
            self._gen_ip_other_section(),  # Other section
        ):
            if section is not None:
                content.append("")
                content.append(section)

        return self._gen_panel(self._gen_group(content), self.entity.data.id_)

    def print(self, one_column: bool = False) -> None:
        renderables = [
            i
            for i in (
                self.ip_panel(),
                self.whois_panel(),
            )
            if i is not None
        ]

        if one_column:
            self.console.print(Group(*([""] + renderables)))  # type: ignore
        else:
            self.console.print(Padding(Columns(renderables), (1, 0)))
