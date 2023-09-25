from dataclasses import dataclass

from pyp0f.database.labels import Label
from pyp0f.database.signatures import TCPSignature
from pyp0f.utils.slots import add_slots

from .base import Record


@add_slots
@dataclass
class TCPRecord(Record[Label, TCPSignature]):
    _label_cls = Label
    _signature_cls = TCPSignature
