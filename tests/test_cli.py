import json
import os
import pytest
from dotenv import load_dotenv
from pathlib import Path
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TimeElapsedColumn,
    TextColumn,
)
from unittest.mock import patch, MagicMock

from wtfis.clients.greynoise import GreynoiseClient
from wtfis.clients.ip2whois import Ip2WhoisClient
from wtfis.clients.ipwhois import IpWhoisClient
from wtfis.clients.passivetotal import PTClient
from wtfis.clients.shodan import ShodanClient
from wtfis.clients.virustotal import VTClient
from wtfis.handlers.domain import DomainHandler
from wtfis.handlers.ip import IpAddressHandler
from wtfis.main import (
    generate_entity_handler,
    generate_view,
    main,
    parse_args,
    parse_env,
)
from wtfis.models.virustotal import Domain, IpAddress
from wtfis.ui.view import DomainView, IpAddressView


POSSIBLE_ENV_VARS = [
    "VT_API_KEY",
    "PT_API_KEY",
    "PT_API_USER",
    "IP2WHOIS_API_KEY",
    "SHODAN_API_KEY",
    "GREYNOISE_API_KEY",
    "WTFIS_DEFAULTS",
]


def unset_env_vars():
    for var in POSSIBLE_ENV_VARS:
        try:
            del os.environ[var]
        except KeyError:
            pass


def fake_load_dotenv(tmp_path, fake_env_vars):
    content = [f"{k} = {v}" for k, v in fake_env_vars.items()]
    path = tmp_path / ".env.wtfis"
    path.write_text("\n".join(content))

    def fake(*_):
        load_dotenv(path)

    return fake


def simulate_progress(console):
    return Progress(
        SpinnerColumn(finished_text="[green]✓"),
        TextColumn("[bold]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    )


@pytest.fixture()
def fake_load_dotenv_1(tmp_path):
    fake_env_vars = {
        "VT_API_KEY": "foo",
        "PT_API_KEY": "bar",
        "PT_API_USER": "baz@example.com",
        "IP2WHOIS_API_KEY": "alice",
        "SHODAN_API_KEY": "hunter2",
        "GREYNOISE_API_KEY": "upupdowndown",
    }
    return fake_load_dotenv(tmp_path, fake_env_vars)


@pytest.fixture()
def fake_load_dotenv_2(tmp_path):
    fake_env_vars = {
        "VT_API_KEY": "foo",
        "SHODAN_API_KEY": "hunter2",
        "WTFIS_DEFAULTS": "-s -1",
    }
    return fake_load_dotenv(tmp_path, fake_env_vars)


@pytest.fixture()
def fake_load_dotenv_3(tmp_path):
    fake_env_vars = {
        "VT_API_KEY": "foo",
        "WTFIS_DEFAULTS": "--no-color",
    }
    return fake_load_dotenv(tmp_path, fake_env_vars)


@pytest.fixture()
def fake_load_dotenv_4(tmp_path):
    fake_env_vars = {
        "VT_API_KEY": "foo",
        "GREYNOISE_API_KEY": "bar",
        "WTFIS_DEFAULTS": "-g",
    }
    return fake_load_dotenv(tmp_path, fake_env_vars)


@pytest.fixture()
def fake_load_dotenv_vt_whois(tmp_path):
    fake_env_vars = {
        "VT_API_KEY": "foo",
    }
    return fake_load_dotenv(tmp_path, fake_env_vars)


@pytest.fixture()
def fake_load_dotenv_ip2whois(tmp_path):
    fake_env_vars = {
        "VT_API_KEY": "foo",
        "IP2WHOIS_API_KEY": "alice",
    }
    return fake_load_dotenv(tmp_path, fake_env_vars)


class TestArgs:
    def test_basic(self):
        with patch("sys.argv", [
            "main",
            "www.example.com",
        ]):
            args = parse_args()
            assert args.entity == "www.example.com"
            assert args.max_resolutions == 3
            assert args.no_color is False
            assert args.one_column is False
            assert args.use_shodan is False

    def test_display(self):
        with patch("sys.argv", [
            "main",
            "www.example.com",
            "-n",
            "-1",
        ]):
            args = parse_args()
            assert args.no_color is True
            assert args.one_column is True

    def test_max_resolutions_ok(self):
        with patch("sys.argv", [
            "main",
            "www.example.com",
            "-m",
            "8",
        ]):
            args = parse_args()
            assert args.max_resolutions == 8

    def test_max_resolutions_error_1(self, capsys):
        with pytest.raises(SystemExit) as e:
            with patch("sys.argv", [
                "main",
                "www.example.com",
                "-m",
                "11",
            ]):
                parse_args()

        capture = capsys.readouterr()

        assert capture.err == "usage: main [-h]\nmain: error: Maximum --max-resolutions value is 10\n"
        assert e.type == SystemExit
        assert e.value.code == 2

    def test_max_resolutions_error_2(self, capsys):
        with pytest.raises(SystemExit) as e:
            with patch("sys.argv", [
                "main",
                "1.1.1.1",
                "-m",
                "5",
            ]):
                parse_args()

        capture = capsys.readouterr()

        assert capture.err == "usage: main [-h]\nmain: error: --max-resolutions is not applicable to IPs\n"
        assert e.type == SystemExit
        assert e.value.code == 2

    def test_shodan_ok(self):
        os.environ["SHODAN_API_KEY"] = "foo"
        with patch("sys.argv", [
            "main",
            "www.example.com",
            "-s",
        ]):
            args = parse_args()
            assert args.use_shodan is True
        del os.environ["SHODAN_API_KEY"]

    def test_shodan_error(self, capsys):
        with pytest.raises(SystemExit) as e:
            with patch("sys.argv", [
                "main",
                "www.example.com",
                "-s",
            ]):
                parse_args()

        capture = capsys.readouterr()

        assert capture.err == "usage: main [-h]\nmain: error: SHODAN_API_KEY is not set\n"
        assert e.type == SystemExit
        assert e.value.code == 2

    def test_greynoise_ok(self):
        os.environ["GREYNOISE_API_KEY"] = "foo"
        with patch("sys.argv", [
            "main",
            "www.example.com",
            "-g",
        ]):
            args = parse_args()
            assert args.use_greynoise is True
        del os.environ["GREYNOISE_API_KEY"]

    def test_greynoise_error(self, capsys):
        with pytest.raises(SystemExit) as e:
            with patch("sys.argv", [
                "main",
                "www.example.com",
                "-g",
            ]):
                parse_args()

        capture = capsys.readouterr()

        assert capture.err == "usage: main [-h]\nmain: error: GREYNOISE_API_KEY is not set\n"
        assert e.type == SystemExit
        assert e.value.code == 2


class TestEnvs:
    def test_env_file(self, fake_load_dotenv_1):
        with patch("wtfis.main.load_dotenv", fake_load_dotenv_1):
            parse_env()
            assert os.environ["VT_API_KEY"] == "foo"
            assert os.environ["PT_API_KEY"] == "bar"
            assert os.environ["PT_API_USER"] == "baz@example.com"
            assert os.environ["IP2WHOIS_API_KEY"] == "alice"
            assert os.environ["SHODAN_API_KEY"] == "hunter2"
            assert os.environ["GREYNOISE_API_KEY"] == "upupdowndown"
        unset_env_vars()

    @patch("wtfis.main.load_dotenv", MagicMock())
    def test_required_env_vars(self):
        os.environ["VT_API_KEY"] = "foo"
        parse_env()
        unset_env_vars()

    @patch("wtfis.main.load_dotenv", MagicMock())
    @patch("wtfis.main.Path.exists")
    def test_error(self, mock_exists, capsys):
        mock_exists.return_value = False

        with pytest.raises(SystemExit) as e:
            parse_env()

        capture = capsys.readouterr()

        assert capture.err == (
            "Error: Environment variable VT_API_KEY not set\n"
            f"Env file {Path().home() / '.env.wtfis'} was not found either. Did you forget?\n"
        )
        assert e.type == SystemExit
        assert e.value.code == 1


class TestDefaults:
    def test_defaults_1(self, fake_load_dotenv_2):
        with patch("wtfis.main.load_dotenv", fake_load_dotenv_2):
            with patch("sys.argv", [
                "main",
                "www.example.com",
            ]):
                parse_env()
                args = parse_args()
                assert args.entity == "www.example.com"
                assert args.max_resolutions == 3
                assert args.no_color is False
                assert args.one_column is True
                assert args.use_shodan is True
                assert args.use_greynoise is False
        unset_env_vars()

    def test_defaults_2(self, fake_load_dotenv_2):
        with patch("wtfis.main.load_dotenv", fake_load_dotenv_2):
            with patch("sys.argv", [
                "main",
                "www.example.com",
                "-s",
            ]):
                parse_env()
                args = parse_args()
                assert args.entity == "www.example.com"
                assert args.max_resolutions == 3
                assert args.no_color is False
                assert args.one_column is True
                assert args.use_shodan is False
                assert args.use_greynoise is False
        unset_env_vars()

    def test_defaults_3(self, fake_load_dotenv_3):
        with patch("wtfis.main.load_dotenv", fake_load_dotenv_3):
            with patch("sys.argv", [
                "main",
                "www.example.com",
            ]):
                parse_env()
                args = parse_args()
                assert args.entity == "www.example.com"
                assert args.max_resolutions == 3
                assert args.no_color is True
                assert args.one_column is False
                assert args.use_shodan is False
                assert args.use_greynoise is False
        unset_env_vars()

    def test_defaults_4(self, fake_load_dotenv_4):
        with patch("wtfis.main.load_dotenv", fake_load_dotenv_4):
            with patch("sys.argv", [
                "main",
                "1.1.1.1",
            ]):
                parse_env()
                args = parse_args()
                assert args.entity == "1.1.1.1"
                assert args.no_color is False
                assert args.one_column is False
                assert args.use_shodan is False
                assert args.use_greynoise is True
        unset_env_vars()


class TestGenEntityHandler:
    """ Tests for the generate_entity_handler function """
    @patch("sys.argv", ["main", "www.example[.]com"])
    def test_handler_domain_1(self, fake_load_dotenv_1):
        """ Domain with default params """
        with patch("wtfis.main.load_dotenv", fake_load_dotenv_1):
            parse_env()
            console = Console()
            progress = simulate_progress(console),
            entity = generate_entity_handler(parse_args(), console, progress)
        assert isinstance(entity, DomainHandler)
        assert entity.entity == "www.example.com"
        assert entity.max_resolutions == 3
        assert entity.console == console
        assert entity.progress == progress
        assert isinstance(entity._vt, VTClient)
        assert isinstance(entity._enricher, IpWhoisClient)
        assert isinstance(entity._whois, PTClient)
        assert entity._greynoise is None
        unset_env_vars()

    @patch("sys.argv", ["main", "www.example[.]com", "-s", "-g", "-m", "5"])
    def test_handler_domain_2(self, fake_load_dotenv_1):
        """ Domain with Shodan and Greynoise and non-default max_resolutions """
        with patch("wtfis.main.load_dotenv", fake_load_dotenv_1):
            parse_env()
            console = Console()
            progress = simulate_progress(console),
            entity = generate_entity_handler(parse_args(), console, progress)
        assert entity.max_resolutions == 5
        assert isinstance(entity._enricher, ShodanClient)
        assert isinstance(entity._whois, PTClient)
        assert isinstance(entity._greynoise, GreynoiseClient)
        unset_env_vars()

    @patch("sys.argv", ["main", "www.example[.]com"])
    def test_handler_domain_3(self, fake_load_dotenv_vt_whois):
        """ Domain using default Ip2Whois for whois """
        with patch("wtfis.main.load_dotenv", fake_load_dotenv_vt_whois):
            parse_env()
            console = Console()
            progress = simulate_progress(console),
            entity = generate_entity_handler(parse_args(), console, progress)
        assert isinstance(entity._whois, VTClient)
        unset_env_vars()

    @patch("sys.argv", ["main", "www.example[.]com"])
    def test_handler_domain_4(self, fake_load_dotenv_ip2whois):
        """ Domain using default Ip2Whois for whois """
        with patch("wtfis.main.load_dotenv", fake_load_dotenv_ip2whois):
            parse_env()
            console = Console()
            progress = simulate_progress(console),
            entity = generate_entity_handler(parse_args(), console, progress)
        assert isinstance(entity._whois, Ip2WhoisClient)
        unset_env_vars()

    @patch("sys.argv", ["main", "1[.]1[.]1[.]1"])
    def test_handler_ip_1(self, fake_load_dotenv_1):
        """ IP with default params """
        with patch("wtfis.main.load_dotenv", fake_load_dotenv_1):
            parse_env()
            console = Console()
            progress = simulate_progress(console),
            entity = generate_entity_handler(parse_args(), console, progress)
        assert isinstance(entity, IpAddressHandler)
        assert entity.entity == "1.1.1.1"
        assert entity.console == console
        assert entity.progress == progress
        assert isinstance(entity._vt, VTClient)
        assert isinstance(entity._enricher, IpWhoisClient)
        assert isinstance(entity._whois, PTClient)
        assert entity._greynoise is None
        unset_env_vars()


class TestGenView:
    """ Tests for the generate_view function """
    @patch("wtfis.main.DomainView", return_value=MagicMock(spec=DomainView))
    def test_view_domain_1(self, m_domain_view, test_data):
        """ Domain view with default params """
        entity = DomainHandler(
            entity=MagicMock(),
            console=MagicMock(),
            progress=MagicMock(),
            vt_client=MagicMock(),
            ip_enricher_client=MagicMock(),
            whois_client=MagicMock(),
            greynoise_client=MagicMock(),
        )
        entity.vt_info = Domain.model_validate(json.loads(test_data("vt_domain_gist.json")))
        entity.whois = MagicMock()
        entity.ip_enrich = MagicMock()
        view = generate_view(MagicMock(), MagicMock(), entity)
        assert isinstance(view, DomainView)

    @patch("wtfis.main.IpAddressView", return_value=MagicMock(spec=IpAddressView))
    def test_view_ip_1(self, m_ip_view, test_data):
        """ IP address view with default params """
        entity = IpAddressHandler(
            entity=MagicMock(),
            console=MagicMock(),
            progress=MagicMock(),
            vt_client=MagicMock(),
            ip_enricher_client=MagicMock(),
            whois_client=MagicMock(),
            greynoise_client=MagicMock(),
        )
        entity.vt_info = IpAddress.model_validate(json.loads(test_data("vt_ip_1.1.1.1.json")))
        entity.whois = MagicMock()
        entity.ip_enrich = MagicMock()
        view = generate_view(MagicMock(), MagicMock(), entity)
        assert isinstance(view, IpAddressView)

    def test_view_error(self):
        """ IP address view with default params """
        with pytest.raises(Exception):
            generate_view(MagicMock(), MagicMock(), "foobar")


class TestMain:
    @patch("sys.argv", ["main", "www.example.com"])
    @patch("wtfis.main.Console", return_value=Console())
    @patch("wtfis.main.parse_args")
    @patch("wtfis.main.get_progress")
    @patch("wtfis.main.generate_entity_handler", return_value=MagicMock())
    @patch("wtfis.main.generate_view", return_value=MagicMock())
    def test_main_default(self, m_view, m_handler, m_progress, m_args, m_console, fake_load_dotenv_1):
        """ Test all calls with default values """
        m_args.return_value = parse_args()
        m_progress.return_value = simulate_progress(m_console())
        with patch("wtfis.main.load_dotenv", fake_load_dotenv_1):
            main()
        m_args.assert_called_once_with()
        m_handler.assert_called_once_with(m_args(), m_console(), m_progress())
        m_handler().fetch_data.assert_called_once_with()
        m_handler().print_warnings.assert_called_once_with()
        m_view.assert_called_once_with(m_args(), m_console(), m_handler())
        m_view().print.assert_called_once_with(one_column=False)
        unset_env_vars()
