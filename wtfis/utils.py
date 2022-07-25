import datetime


def iso_date(unix_time: int) -> str:
    """ Convert epoch time to ISO 8601 """
    return datetime.datetime.utcfromtimestamp(unix_time).isoformat()
