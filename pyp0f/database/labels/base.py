from abc import ABCMeta, abstractmethod
from dataclasses import dataclass
from typing import Type

from typing_extensions import Self

from pyp0f.utils.slots import add_slots


@add_slots
@dataclass
class DatabaseLabel(metaclass=ABCMeta):
    name: str

    @classmethod
    @abstractmethod
    def parse(cls: Type[Self], raw_label: str) -> Self:
        """
        Parse raw label and validate values.
        """

    def dump(self) -> str:
        """
        Dump label to p0f representation.
        """
        return self.name
