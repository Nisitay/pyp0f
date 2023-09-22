from dataclasses import dataclass

from pyp0f.database.labels import Label
from pyp0f.database.signatures import HTTPSignature
from pyp0f.utils.slots import add_slots

from .base import Record


@add_slots
@dataclass
class HTTPRecord(Record[Label, HTTPSignature]):
    _label_cls = Label
    _signature_cls = HTTPSignature
