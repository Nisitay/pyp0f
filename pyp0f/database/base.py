from pyp0f.utils.path import ROOT_DIR, PathLike, always_path

from .parser import parse_file
from .storage import RecordStorage

# Default location of p0f.fp.
DATABASE_PATH = ROOT_DIR / "data" / "p0f.fp"


class Database(RecordStorage):
    """
    ``RecordStorage`` wrapper to load records from a database file (p0f.fp)
    """

    def load(self, filepath: PathLike = DATABASE_PATH):
        """
        Load the p0f database from a database file (p0f.fp).
        Note: This will override the underlying datastructure of existing records.

        Args:
            filepath: Database file path. Defaults to DATABASE_PATH.

        Raises:
            DatabaseError: Error while parsing the database
        """
        self._update(parse_file(always_path(filepath)))


DATABASE = Database()
