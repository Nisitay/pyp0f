from dataclasses import dataclass
from typing import Tuple

from pyp0f.database.parse.utils import fixed_options_parser, split_parts
from pyp0f.utils.slots import add_slots

from .base import DatabaseLabel


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
        type, os_class, name, flavor = split_parts(raw_label, parts=4)

        return cls(
            name=name, is_generic=_parse_type(type), os_class=os_class, flavor=flavor
        )

    def dump(self) -> str:
        return ":".join(
            ("g" if self.is_generic else "s", self.os_class, self.name, self.flavor)
        )


_parse_type = fixed_options_parser({"s": False, "g": True})
