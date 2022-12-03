import re
import sys

from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from typing import Optional, Union

from rich.console import RenderableType
from rich.text import Text

from wtfis.ui.theme import Theme


class Timestamp:
    std_utc = "%Y-%m-%dT%H:%M:%SZ"
    ts_regex = re.compile(r"(?P<date>[0-9-]+)T(?P<time>[0-9:]+)Z")
    theme = Theme()

    def __init__(self, ts: Union[str, int, None]):
        self.timestamp = self._standardize(ts)

    def _standardize(self, ts: Union[str, int, None]) -> Optional[str]:
        """ Convert any time to a standard format """
        # Do nothing if ts is None
        if ts is None:
            return None

        # Return as is if format is already what we want
        try:
            datetime.strptime(str(ts), self.std_utc)
            return str(ts)
        except ValueError:
            pass

        # Attempt to detect epoch time in string format
        try:
            ts = int(ts)
        except ValueError:
            pass

        if isinstance(ts, int):
            return datetime.fromtimestamp(ts, tz=timezone.utc).strftime(self.std_utc)
        elif isinstance(ts, str):
            # Try to convert other possible date formats
            for fmt in [
                "%Y-%m-%dT%H:%M:%S.00Z",
                "%Y-%m-%dT%H:%M:%S%z",
            ]:
                try:
                    return datetime.strptime(ts, fmt).strftime(self.std_utc)
                except ValueError:
                    pass

            # No explicit timezone - return date as is (le sigh)
            for fmt in [
                "%Y-%m-%d %H:%M:%S",
            ]:
                try:
                    datetime.strptime(ts, fmt)
                    return ts
                except ValueError:
                    pass

            # Default
            try:
                return datetime.fromisoformat(ts).astimezone(timezone.utc).strftime(self.std_utc)
            except ValueError:  # Cannot convert; fail open
                return ts

    @property
    def render(self) -> Optional[RenderableType]:
        if self.timestamp is None:  # Return None if no ts to begin with
            return None

        match = self.ts_regex.match(self.timestamp) if self.timestamp else None
        if not match:  # Return ts as is if it does not match our regex
            return self.timestamp

        text = Text(match.group("date"), style=self.theme.timestamp_date)
        text.append("T", style=self.theme.timestamp_t)
        text.append(match.group("time"), style=self.theme.timestamp_time)
        text.append("Z", style=self.theme.timestamp_z)
        return text


def older_than(ts: int, days: int) -> bool:
    """ Tells if a timestamp is older than X days. "ts" must be epoch format """
    return datetime.fromtimestamp(ts) < datetime.now() - timedelta(days=days)


def smart_join(
    *items: Optional[Union[Text, str]],
    style: Optional[str] = None
) -> Union[Text, str]:
    text = Text()
    for idx, item in enumerate(items):
        if item:
            if isinstance(item, Text):
                text.append(item)
            else:
                text.append(item, style=style)
            if idx < len(items) - 1:
                text.append(", ", style="default")
    return text if str(text) != "" else ""


def error_and_exit(message: str, status: int = 1):
    print(message, file=sys.stderr)
    raise SystemExit(status)


def refang(text: str) -> str:
    """ Strip []s out of text """
    return text.replace("[", "").replace("]", "")


def is_ip(text: str) -> bool:
    """ Detect whether text is IPv4 or not """
    try:
        return ip_address(refang(text)).is_global
    except ValueError:
        return False
