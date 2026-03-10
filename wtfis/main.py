from typing import Optional

from rich.console import Console
from rich.progress import Progress, TaskID

from wtfis.config import Config
from wtfis.exceptions import HandlerException, WtfisException
from wtfis.handlers.base import BaseHandler
from wtfis.handlers.domain import DomainHandler
from wtfis.handlers.ip import IpAddressHandler
from wtfis.ui.base import BaseView
from wtfis.ui.progress import get_progress
from wtfis.ui.view import DomainView, IpAddressView
from wtfis.utils import error_and_exit, is_ip


def generate_entity_handler(
    config: Config,
    console: Console,
) -> BaseHandler:
    # Domain / FQDN handler
    if not is_ip(config.entity):
        handler: BaseHandler = DomainHandler(
            entity=config.entity,
            console=console,
            vt_client=config.vt_client,
            ip_geoasn_client=config.ip_geoasn_client,
            whois_client=config.whois_client,
            shodan_client=config.shodan_client,
            greynoise_client=config.greynoise_client,
            abuseipdb_client=config.abuseipdb_client,
            urlhaus_client=config.urlhaus_client,
            max_resolutions=config.max_resolutions,
        )
    # IP address handler
    else:
        handler = IpAddressHandler(
            entity=config.entity,
            console=console,
            vt_client=config.vt_client,
            ip_geoasn_client=config.ip_geoasn_client,
            whois_client=config.whois_client,
            shodan_client=config.shodan_client,
            greynoise_client=config.greynoise_client,
            abuseipdb_client=config.abuseipdb_client,
            urlhaus_client=config.urlhaus_client,
        )

    return handler


def generate_view(
    config: Config,
    console: Console,
    handler: BaseHandler,
) -> BaseView:
    # Output display
    if isinstance(handler, DomainHandler):
        view: BaseView = DomainView(
            console,
            handler.entity,
            handler.vt_info,
            handler.geoasn,
            handler.whois,
            handler.shodan,
            handler.greynoise,
            handler.abuseipdb,
            handler.urlhaus,
            handler.resolutions,
            max_resolutions=config.max_resolutions,
        )
    elif isinstance(handler, IpAddressHandler):
        view = IpAddressView(
            console,
            handler.entity,
            handler.vt_info,
            handler.geoasn,
            handler.whois,
            handler.shodan,
            handler.greynoise,
            handler.abuseipdb,
            handler.urlhaus,
        )
    else:
        raise WtfisException("Unsupported entity!")

    return view


def fetch_data(
    progress: Progress,
    handler: BaseHandler,
):

    def _finish_task():
        if task is not None:
            progress.update(task, completed=100)

    task: Optional[TaskID] = None
    with progress:
        try:
            for x in handler.fetch_data():
                if isinstance(x, tuple):  # (str, int)
                    _finish_task()
                    descr, adv = x
                    task = progress.add_task(descr)
                    progress.update(task, advance=adv)
                elif isinstance(x, int) and task is not None:
                    progress.update(task, advance=x)
            _finish_task()
        except HandlerException as e:
            progress.stop()
            error_and_exit(str(e))


def main():
    # Load config
    config = Config()

    # Instantiate the console
    console = Console(no_color=True) if config.no_color else Console()

    # Progress animation controller
    progress = get_progress(console)

    # Entity handler
    handler = generate_entity_handler(config, console)

    # Fetch data
    fetch_data(progress, handler)

    # Print fetch warnings, if any
    handler.print_warnings()

    # Output display
    view = generate_view(config, console, handler)

    # Finally, print output
    view.print(one_column=config.one_column)
