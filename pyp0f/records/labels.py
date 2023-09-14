from dataclasses import dataclass
from abc import ABCMeta, abstractmethod
from typing import Tuple, TypeVar, Type

from pyp0f.utils.slots import add_slots
from pyp0f.utils.parse import split_parts, fixed_options_parser

T = TypeVar("T", bound="DatabaseLabel")

_parse_type = fixed_options_parser({"s": False, "g": True})


@add_slots
@dataclass
class DatabaseLabel(metaclass=ABCMeta):
    name: str

    @classmethod
    @abstractmethod
    def parse(cls: Type[T], raw_label: str) -> T:
        """
        Parse raw label and validate values.
        Label syntax isn't validated, errors are only raised for invalid values.
        """
        pass


@add_slots
@dataclass
class MtuLabel(DatabaseLabel):
    @classmethod
    def parse(cls, raw_label: str):
        return cls(raw_label)


@add_slots
@dataclass
class Label(DatabaseLabel):
    is_generic: bool
    os_class: str
    flavor: str
    sys: Tuple[str, ...] = ()

    @property
    def is_user_app(self) -> bool:
        return self.os_class == "!"

    @classmethod
    def parse(cls, raw_label: str):
        _type, os_class, name, flavor = split_parts(raw_label, parts=4)
        return cls(
            name=name, is_generic=_parse_type(_type), os_class=os_class, flavor=flavor
        )

    def dump(self) -> str:
        """
        Dump label to p0f representation.
        """
        return ":".join(
            ("g" if self.is_generic else "s", self.os_class, self.name, self.flavor)
        )
