from dataclasses import dataclass

from pyp0f.database import Database, DATABASE


@dataclass
class Options:
    # p0f signatures database
    database: Database = DATABASE

    # Maximum TTL distance for non-fuzzy signature matching.
    max_dist: int = 35

    # Special window size and MSS used by p0f-sendsyn, and detected by p0f.
    special_mss: int = 1331
    special_window: int = 1337


OPTIONS = Options()
