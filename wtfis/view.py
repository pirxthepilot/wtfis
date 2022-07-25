from rich.columns import Columns
from rich.console import Console, Group
from rich.padding import Padding
from rich.panel import Panel
from rich.text import Text
from typing import Optional

from wtfis.models.passivetotal import Whois
from wtfis.models.virustotal import Domain
from wtfis.utils import iso_date


class View:
    """
    Handles the look of the output
    """
    def __init__(self, whois: Whois, vt_domain: Domain):
        self.console = Console()
        self.whois = whois
        self.vt = vt_domain

    def _gen_heading_text(self, heading: str) -> Text:
        heading_style = "bold yellow"
        return Text(heading, style=heading_style, justify="center", end="\n")

    def _gen_fv_text(self, *params) -> Text:
        """ Each param should be a tuple of (field, value, value_style_overrides) """
        field_style = "bold magenta"
        text = Text()
        for idx, item in enumerate(params):
            value_style = None
            if len(item) == 3:
                field, value, value_style = item
            else:
                field, value = item
            text.append(field + " ", style=field_style)
            text.append(str(value), style=value_style)
            if not idx == len(params) - 1:
                text.append("\n")
        return text

    def _gen_panel(self, title: str, body: Text, heading: Optional[Text] = None) -> Panel:
        renderable = Group(heading, body) if heading else body
        return Panel(renderable, title=title, expand=False)

    def whois_panel(self) -> Panel:
        heading = self._gen_heading_text(self.whois.domain)
        body = "foo"
        return self._gen_panel("whois", body, heading)

    def vt_panel(self) -> Panel:
        heading = self._gen_heading_text("goo.bar.baz")
        body = self._gen_fv_text(
            ("Reputation:", self.vt.reputation),
            ("Registrar:", self.vt.registrar),
        )

        return self._gen_panel("virustotal", body, heading)

    def print(self):
        renderables = [
            self.vt_panel(),
            self.whois_panel(),
        ]
        self.console.print(Padding(Columns(renderables), (1, 0)))
