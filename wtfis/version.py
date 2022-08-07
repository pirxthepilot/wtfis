from importlib.metadata import version


def get_version() -> str:
    return version("wtfis")
