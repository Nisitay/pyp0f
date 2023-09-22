from dataclasses import dataclass

from pyp0f.database.records import MTURecord
from pyp0f.net.signatures import MTUPacketSignature
from pyp0f.utils.slots import add_slots

from .base import Result


@add_slots
@dataclass
class MTUResult(Result[MTURecord, MTUPacketSignature]):
    """
    MTU fingerprint result
    """
