from abc import ABCMeta, abstractmethod
from dataclasses import dataclass
from typing import Type

from typing_extensions import Self

from pyp0f.net.packet import Packet
from pyp0f.utils.slots import add_slots


@add_slots
@dataclass
class PacketSignature(metaclass=ABCMeta):
    @classmethod
    @abstractmethod
    def from_packet(cls: Type[Self], packet: Packet) -> Self:
        pass
