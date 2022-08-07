import sys

from datetime import datetime, timezone
from typing import Optional, Union

from rich.text import Text


def iso_date(ts: Union[str, int]) -> str:
    """ Convert any time to a standard format """
    std_utc = "%Y-%m-%dT%H:%M:%SZ"
    if isinstance(ts, int):
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime(std_utc)
    elif isinstance(ts, str):
        return datetime.fromisoformat(ts).astimezone(timezone.utc).strftime(std_utc)


def smart_join(*items: str, style: Optional[str] = None) -> Optional[Text]:
    text = Text()
    for item in items:
        if item:
            text.append(item, style=style)
        if item != items[-1]:
            text.append(", ", style="default")
    return text if str(text) != "" else None


def error_and_exit(message: str, status: int = 1):
    print(message, file=sys.stderr)
    raise SystemExit(status)
