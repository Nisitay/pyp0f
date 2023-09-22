from dataclasses import dataclass

from pyp0f.database.labels import MTULabel
from pyp0f.database.signatures import MTUSignature
from pyp0f.utils.slots import add_slots

from .base import Record


@add_slots
@dataclass
class MTURecord(Record[MTULabel, MTUSignature]):
    _label_cls = MTULabel
    _signature_cls = MTUSignature
