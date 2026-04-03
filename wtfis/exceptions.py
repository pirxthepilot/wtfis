class WtfisException(Exception):
    """Custom wtfis exception"""


class HandlerException(WtfisException): ...


class ModelException(WtfisException): ...
