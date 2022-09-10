import os
import pytest
from dotenv import load_dotenv
from pathlib import Path
from unittest.mock import patch, MagicMock

from wtfis.main import parse_args, parse_env


FAKE_ENV_VARS = {
    "VT_API_KEY": "foo",
    "PT_API_KEY": "bar",
    "PT_API_USER": "baz@example.com",
    "SHODAN_API_KEY": "hunter2"
}


def unset_env_vars():
    for var in FAKE_ENV_VARS.keys():
        try:
            del os.environ[var]
        except KeyError:
            pass


@pytest.fixture()
def fake_load_dotenv(tmp_path):
    content = [f"{k} = {v}" for k, v in FAKE_ENV_VARS.items()]
    path = tmp_path / ".env.wtfis"
    path.write_text("\n".join(content))
    def fake(*_):
        load_dotenv(path)
    return fake


class TestArgs:
    def test_basic(self):
        with patch("sys.argv",[
            "main",
            "www.example.com",
        ]):
            args = parse_args()
            assert args.entity == "www.example.com"
            assert args.max_resolutions == 3
            assert args.no_color == False
            assert args.one_column == False
            assert args.use_shodan == False

    def test_display(self):
        with patch("sys.argv",[
            "main",
            "www.example.com",
            "-n",
            "-1",
        ]):
            args = parse_args()
            assert args.no_color == True
            assert args.one_column == True

    def test_max_resolutions_ok(self):
        with patch("sys.argv",[
            "main",
            "www.example.com",
            "-m",
            "8",
        ]):
            args = parse_args()
            assert args.max_resolutions == 8

    def test_max_resolutions_error_1(self, capsys):
        with pytest.raises(SystemExit) as e:
            with patch("sys.argv",[
                "main",
                "www.example.com",
                "-m",
                "11",
            ]):
                args = parse_args()
        
        capture = capsys.readouterr()

        assert capture.err == "usage: main [-h]\nmain: error: Maximum --max-resolutions value is 10\n"
        assert e.type == SystemExit
        assert e.value.code == 2

    def test_max_resolutions_error_2(self, capsys):
        with pytest.raises(SystemExit) as e:
            with patch("sys.argv",[
                "main",
                "1.1.1.1",
                "-m",
                "5",
            ]):
                args = parse_args()
        
        capture = capsys.readouterr()

        assert capture.err == "usage: main [-h]\nmain: error: --max-resolutions is not applicable to IPs\n"
        assert e.type == SystemExit
        assert e.value.code == 2

    def test_shodan_ok(self):
        os.environ["SHODAN_API_KEY"] = "foo"
        with patch("sys.argv",[
            "main",
            "www.example.com",
            "-s",
        ]):
            args = parse_args()
            assert args.use_shodan == True
        del os.environ["SHODAN_API_KEY"]

    def test_shodan_error(self, capsys):
        with pytest.raises(SystemExit) as e:
            with patch("sys.argv",[
                "main",
                "www.example.com",
                "-s",
            ]):
                args = parse_args()
        
        capture = capsys.readouterr()

        assert capture.err == "usage: main [-h]\nmain: error: SHODAN_API_KEY is not set\n"
        assert e.type == SystemExit
        assert e.value.code == 2


class TestEnvs:
    def test_env_file(self, fake_load_dotenv):
        with patch("wtfis.main.load_dotenv", fake_load_dotenv):
            parse_env()
            assert os.environ["VT_API_KEY"] == "foo"
            assert os.environ["PT_API_KEY"] == "bar"
            assert os.environ["PT_API_USER"] == "baz@example.com"
            assert os.environ["SHODAN_API_KEY"] == "hunter2"
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
    