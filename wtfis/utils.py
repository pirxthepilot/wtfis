import sys

from datetime import datetime, timedelta, timezone
from typing import Optional, Union

from rich.text import Text


def iso_date(ts: Optional[Union[str, int]]) -> Optional[str]:
    """ Convert any time to a standard format """
    std_utc = "%Y-%m-%dT%H:%M:%SZ"
    if isinstance(ts, int):
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime(std_utc)
    elif isinstance(ts, str):
        return datetime.fromisoformat(ts).astimezone(timezone.utc).strftime(std_utc)
    return None


def older_than(ts: int, days: int) -> bool:
    """ Tells if a timestamp is older than X days. "ts" must be epoch format """
    return datetime.fromtimestamp(ts) < datetime.now() - timedelta(days=days)


def smart_join(*items: Optional[str], style: Optional[str] = None) -> Union[Text, str]:
    text = Text()
    for idx, item in enumerate(items):
        if item:
            text.append(item, style=style)
            if idx < len(items) - 1:
                text.append(", ", style="default")
    return text if str(text) != "" else ""


def error_and_exit(message: str, status: int = 1):
    print(message, file=sys.stderr)
    raise SystemExit(status)
