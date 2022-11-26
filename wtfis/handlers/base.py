import abc

from pydantic import ValidationError
from requests.exceptions import HTTPError, JSONDecodeError
from rich.console import Console
from rich.progress import Progress
from shodan.exception import APIError
from typing import Any, Callable

from wtfis.utils import error_and_exit


def common_exception_handler(func: Callable) -> Any:
    """ Decorator for handling common fetch errors """
    def inner(*args, **kwargs):
        progress: Progress = args[0].progress  # args[0] is the method's self input
        try:
            func(*args, **kwargs)
        except (HTTPError, JSONDecodeError, APIError) as e:
            progress.stop()
            error_and_exit(f"Error fetching data: {e}")
        except ValidationError as e:
            progress.stop()
            error_and_exit(f"Data model validation error: {e}")
    return inner


class BaseHandler(abc.ABC):
    def __init__(
        self,
        entity: str,
        console: Console,
        progress: Progress,
    ):
        self.entity = entity
        self.console = console
        self.progress = progress
        self.warnings = []

    @abc.abstractmethod
    def fetch_data(self) -> None:
        """ Main method that controls what get fetched """
        return NotImplemented
