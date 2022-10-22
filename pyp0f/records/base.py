from abc import ABCMeta
from dataclasses import dataclass
from typing import Type, TypeVar, Generic, Optional, ClassVar

from pyp0f.utils.slots import add_slots
from pyp0f.signatures import DatabaseSig, MtuSig, TcpSig, HttpSig

from .labels import DatabaseLabel, Label, MtuLabel

S = TypeVar("S", bound=DatabaseSig)
L = TypeVar("L", bound=DatabaseLabel)


@add_slots
@dataclass
class Record(Generic[S, L], metaclass=ABCMeta):
    label: L
    signature: S
    raw_signature: Optional[str] = None
    line_no: Optional[int] = None

    _label_cls: ClassVar[Type[DatabaseLabel]]
    _signature_cls: ClassVar[Type[DatabaseSig]]

    @property
    def is_generic(self) -> bool:
        return isinstance(self.label, Label) and self.label.is_generic


@add_slots
@dataclass
class MtuRecord(Record[MtuSig, MtuLabel]):
    _label_cls = MtuLabel
    _signature_cls = MtuSig


@add_slots
@dataclass
class TcpRecord(Record[TcpSig, Label]):
    _label_cls = Label
    _signature_cls = TcpSig


@add_slots
@dataclass
class HttpRecord(Record[HttpSig, Label]):
    _label_cls = Label
    _signature_cls = HttpSig
