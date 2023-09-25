from dataclasses import dataclass

from pyp0f.database import DATABASE, Database


@dataclass
class Options:
    database: Database = DATABASE
    """p0f signatures database"""

    max_dist: int = 35
    """Maximum TTL distance for non-fuzzy signature matching"""

    special_mss: int = 1331
    """Special MSS used by p0f-sendsyn, and detected by p0f"""
    special_window: int = 1337
    """Special window size used by p0f-sendsyn, and detected by p0f"""


OPTIONS = Options()
