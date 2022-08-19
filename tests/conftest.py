import pytest
from pathlib import Path


def open_test_data(fname: str) -> str:
    path = Path(__file__).parent.resolve() / "test_data" / fname
    with open(path) as f:
        return f.read()


@pytest.fixture(scope="module")
def test_data():
    return open_test_data
