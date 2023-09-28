from dataclasses import dataclass

from pyp0f.database import DATABASE, Database


@dataclass
class Options:
    database: Database = DATABASE
    """p0f signatures database."""

    max_dist: int = 35
    """Maximum TTL distance for non-fuzzy signature matching."""

    special_mss: int = 1331
    """Special MSS used by p0f-sendsyn, and detected by p0f."""
    special_window: int = 1337
    """Special window size used by p0f-sendsyn, and detected by p0f."""

    min_timestamp_scale: float = 0.7
    """
    Minimum frequency for timestamp clock (Hz).

    Note that RFC 1323 permits 1 - 1000 Hz . At 1000 Hz, the 32-bit counter
    overflows after about 50 days.
    """
    max_timestamp_scale: float = 1500
    """
    Maximum frequency for timestamp clock (Hz).
    """

    min_timestamp_wait: int = 25
    """
    Minimum interval (ms) for measuring timestamp progrssion. This
    is used to make sure the timestamps are fresh enough to be of any value,
    and that the measurement is not affected by network performance too severely.
    """
    max_timestamp_wait: int = 1000 * 60 * 10
    """
    Maximum interval (ms) for measuring timestamp progrssion.
    """

    timestamp_grace: int = 100
    """
    Time window in which to tolerate timestamps going back slightly or otherwise misbehaving
    during NAT checks (ms)
    """


OPTIONS = Options()
