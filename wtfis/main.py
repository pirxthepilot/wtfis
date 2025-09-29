from typing import Optional

from rich.console import Console
from rich.progress import Progress, TaskID

from wtfis.config import Config
from wtfis.exceptions import HandlerException, WtfisException
from wtfis.handlers.base import BaseHandler
from wtfis.handlers.domain import DomainHandler
from wtfis.handlers.ip import IpAddressHandler
from wtfis.models.virustotal import Domain, IpAddress
from wtfis.ui.base import BaseView
from wtfis.ui.progress import get_progress
from wtfis.ui.view import DomainView, IpAddressView
from wtfis.utils import error_and_exit, is_ip
import json 

def generate_entity_handler(
    config: Config,
    console: Console,
) -> BaseHandler:
    # Domain / FQDN handler
    if not is_ip(config.entity):
        entity: BaseHandler = DomainHandler(
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
        entity = IpAddressHandler(
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

    return entity


def generate_view(
    config: Config,
    console: Console,
    entity: BaseHandler,
) -> BaseView:
    # Output display
    if isinstance(entity, DomainHandler) and isinstance(entity.vt_info, Domain):
        print("here domain instance")
        view: BaseView = DomainView(
            console,
            entity.vt_info,
            entity.geoasn,
            entity.whois,
            entity.shodan,
            entity.greynoise,
            entity.abuseipdb,
            entity.urlhaus,
            entity.resolutions,
            max_resolutions=config.max_resolutions,
        )
    elif isinstance(entity, IpAddressHandler) and isinstance(entity.vt_info, IpAddress):
        print("here ip instance")
        view = IpAddressView(
            console,
            entity.vt_info,
            entity.geoasn,
            entity.whois,
            entity.shodan,
            entity.greynoise,
            entity.abuseipdb,
            entity.urlhaus,
        )
    else:
        raise WtfisException("Unsupported entity!")

    return view


def fetch_data(
    progress: Progress,
    entity: BaseHandler,
):

    def _finish_task():
        if task is not None:
            progress.update(task, completed=100)

    task: Optional[TaskID] = None
    with progress:
        try:
            for x in entity.fetch_data():
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

# print("Here")
def main():
    # Load config
    print("HER1E")
    config = Config()

    # Instantiate the console
    console = Console(no_color=True) if config.no_color else Console()

    # Progress animation controller
    progress = get_progress(console)

    # Entity handler
    entity = generate_entity_handler(config, console)

    # Fetch data
    fetch_data(progress, entity)

    # Print fetch warnings, if any
    entity.print_warnings()

    # obj = entity.to_dict()
    # with open('ip_logs.json', 'r+') as file:
    #     try:
    #         # Load existing data
    #         data = json.load(file)
    #     except json.JSONDecodeError:
    #         # If the file is empty or not a valid JSON, initialize an empty list
    #         data = []

    #     # Append the new object
    #     data.append(obj)

    #     # Move the cursor to the beginning of the file
    #     file.seek(0)

    #     # Write the updated data back to the file with indentation for readability
    #     json.dump(data, file, indent=4)
    # print("THIS IS OBJ",obj)

    # Output display
    view = generate_view(config, console, entity)

    obj = view.to_json_dict()
    with open('ip_logs.json', 'r+') as file:
        try:
            # Load existing data
            data = json.load(file)
        except json.JSONDecodeError:
            # If the file is empty or not a valid JSON, initialize an empty list
            data = []

        # Append the new object
        data.append(obj)

        # Move the cursor to the beginning of the file
        file.seek(0)

        # Write the updated data back to the file with indentation for readability
        json.dump(data, file, indent=4)
    print("thisisobj",obj)

    # Finally, print output
    view.print(one_column=config.one_column)
