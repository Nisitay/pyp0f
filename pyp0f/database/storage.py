from typing import Iterator, Union, Optional, Sized, TypeVar, Type, Dict, List, Any

from pyp0f.exceptions import DatabaseError
from pyp0f.net.packet import Direction
from pyp0f.records import Record

T = TypeVar("T", bound=Record)

RecordList = List[Record]
DirectionalDict = Dict[Direction, RecordList]
RecordsDict = Dict[Type[Record], Union[RecordList, DirectionalDict]]


class RecordStorage(Sized):
    """
    Stores database records.
    Maps record types to a record list, or a dict that maps directions to record lists

    Basic usage:
        >>> storage = RecordStorage()
        >>> storage.create(...)
        >>> storage._records  # Underlying raw datastructure
        {
            MtuRecord: [<MtuRecord>, ...],
            TcpRecord: {
                Direction.CLI_TO_SRV: [<TcpRecord>, ...],
                Direction.SRV_TO_CLI: [<TcpRecord>, ...]
            },
            ...
        }
    """

    def __init__(self, records: Optional[RecordsDict] = None):
        self._records: Dict[Type[Record], Any] = records or {}

    def _update(self, other: "RecordStorage"):
        self._records = other._records

    def _get(
        self, record_cls: Type[T], direction: Optional[Direction] = None
    ) -> List[T]:
        """
        Get list of records and perform all logical checks.

        Args:
            record_cls: Record type
            direction: Direction of record list. Defaults to None.

        Raises:
            DatabaseError: Error in retrieving records

        Returns:
            List of records
        """
        if record_cls not in self._records:
            raise DatabaseError(
                f"Record type {type(record_cls).__name__!r} is not in the database"
            )

        if isinstance(self._records[record_cls], list):
            return self._records[record_cls]

        if direction is None:
            raise DatabaseError(
                f"Record type {type(record_cls).__name__!r} points at a "
                "directional dict, but no direction was given"
            )

        if direction not in self._records[record_cls]:
            raise DatabaseError(
                f"Record type {type(record_cls).__name__!r} points at a "
                "directional dict, but the given direction is not in it"
            )

        return self._records[record_cls][direction]

    def create(self, record_cls: Type[T], direction: Optional[Direction] = None):
        """
        Creates a new empty list of records.
        """
        if direction is not None:
            if record_cls not in self._records:
                self._records[record_cls] = {}
            self._records[record_cls][direction] = []
        else:
            self._records[record_cls] = []

    def add(self, record: Record, direction: Optional[Direction] = None):
        """
        Add a record to an existing list of records.
        """
        self._get(type(record), direction).append(record)

    def __len__(self) -> int:
        return sum(
            len(val) if isinstance(val, list) else sum(len(lst) for lst in val.values())
            for val in self._records.values()
        )

    def __call__(
        self, record_cls: Type[T], direction: Optional[Direction] = None
    ) -> Iterator[T]:
        """
        Safely iterate a list of records.
        """
        try:
            records = self._get(record_cls, direction)
        except DatabaseError:
            records = []
        return iter(records)
