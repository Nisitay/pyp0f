import time


def get_unix_time_seconds() -> int:
    """
    Get Unix timestamp in seconds.
    """
    return time.time_ns() // 10**9


def get_unix_time_ms() -> int:
    """
    Get Unix timestamp in milliseconds.
    """
    return time.time_ns() // 10**6
