from abc import ABCMeta, abstractmethod
from dataclasses import dataclass
from typing import Type

from typing_extensions import Self

from pyp0f.utils.slots import add_slots


@add_slots
@dataclass
class DatabaseSignature(metaclass=ABCMeta):
    @classmethod
    @abstractmethod
    def parse(cls: Type[Self], raw_signature: str) -> Self:
        """
        Parse raw signature and validate values.
        """
