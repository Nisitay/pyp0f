from dataclasses import dataclass

from pyp0f.utils.slots import add_slots

from .base import DatabaseLabel


@add_slots
@dataclass
class MTULabel(DatabaseLabel):
    @classmethod
    def parse(cls, raw_label: str):
        return cls(raw_label)
