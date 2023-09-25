from abc import ABCMeta
from dataclasses import dataclass
from typing import ClassVar, Generic, Type, TypeVar

from pyp0f.database.labels import DatabaseLabel, Label
from pyp0f.database.signatures import DatabaseSignature
from pyp0f.utils.slots import add_slots

TLabel = TypeVar("TLabel", bound=DatabaseLabel)
TSignature = TypeVar("TSignature", bound=DatabaseSignature)


@add_slots
@dataclass
class Record(Generic[TLabel, TSignature], metaclass=ABCMeta):
    """Database record metadata, consisting of a label and a signature"""

    label: TLabel
    """Record label"""

    signature: TSignature
    """Record signature"""

    raw_signature: str
    """Raw signature, as seen in database file"""

    line_number: int
    """Line number of record in database file"""

    _label_cls: ClassVar[Type[DatabaseLabel]]
    _signature_cls: ClassVar[Type[DatabaseSignature]]

    @property
    def is_generic(self) -> bool:
        return isinstance(self.label, Label) and self.label.is_generic
