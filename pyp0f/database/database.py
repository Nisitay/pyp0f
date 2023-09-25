from pyp0f.database.parse.parser import parse_file
from pyp0f.database.records_database import RecordsDatabase
from pyp0f.utils.path import ROOT_DIR, PathLike, always_path

# Default location of p0f.fp.
DEFAULT_DATABASE_PATH = ROOT_DIR / "data" / "p0f.fp"


class Database(RecordsDatabase):
    """
    p0f database.
    Loads records from a database file (p0f.fp)
    """

    def load(self, filepath: PathLike = DEFAULT_DATABASE_PATH):
        """
        Loads a database file (p0f.fp).
        Note: This will override the underlying datastructure of any existing records (if loaded already).

        Args:
            filepath: Database file path. Defaults to DEFAULT_DATABASE_PATH.

        Raises:
            DatabaseError: Error while parsing the database
        """
        self._replace(parse_file(always_path(filepath)))


DATABASE = Database()
