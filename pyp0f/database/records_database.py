from typing import Iterator, List, MutableMapping, Optional, Sized, Type, TypeVar, Union

from pyp0f.database.records import Record
from pyp0f.exceptions import DatabaseError
from pyp0f.net.packet import Direction

T = TypeVar("T", bound=Record)

RecordsByDirection = MutableMapping[Direction, List[Record]]
RecordsMapping = MutableMapping[Type[Record], Union[List[Record], RecordsByDirection]]


class RecordsDatabase(Sized):
    """
    Maps record types to a records list of matching type, or to a dict that maps a direction to
    records list of matching type.
    """

    def __init__(self, items: Optional[RecordsMapping] = None) -> None:
        self._map: RecordsMapping = items or {}

    def _replace(self, other: "RecordsDatabase"):
        self._map = other._map

    def _get(self, key: Type[T], direction: Optional[Direction] = None) -> List[T]:
        """
        Get list of values and perform all logical checks.
        """
        if key not in self._map:
            raise DatabaseError(f"{key} does not exist in the database")

        value = self._map[key]

        if isinstance(value, list):
            return value  # type: ignore

        if direction is None:
            raise DatabaseError(
                f"{key} points at a directional dict, but no direction was given"
            )

        if direction not in value:
            raise DatabaseError(
                f"{direction} does not exist on directional dict of {key}"
            )

        return value[direction]  # type: ignore

    def create(self, key: Type[Record], direction: Optional[Direction] = None) -> None:
        """
        Create a new empty list of values.
        """
        if direction is not None:
            if key not in self._map:
                self._map[key] = {}
            self._map[key][direction] = []  # type: ignore
        else:
            self._map[key] = []

    def add(self, value: Record, direction: Optional[Direction] = None) -> None:
        """
        Add a value to an existing list of values.
        """
        values_list = self._get(type(value), direction)
        values_list.append(value)

    def iter_values(
        self, key: Type[T], direction: Optional[Direction] = None
    ) -> Iterator[T]:
        """
        Safely iterate a list of values.
        """
        try:
            values = self._get(key, direction)
        except DatabaseError:
            values = []

        return iter(values)

    def __len__(self) -> int:
        return sum(
            len(value)
            if isinstance(value, list)
            else sum(len(values_list) for values_list in value.values())
            for value in self._map.values()
        )