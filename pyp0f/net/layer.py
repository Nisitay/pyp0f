from abc import ABCMeta, abstractmethod
from typing import TypeVar, Type

from scapy.packet import Packet as ScapyPacket

T = TypeVar("T", bound="Layer")


class Layer(metaclass=ABCMeta):
    @classmethod
    @abstractmethod
    def from_packet(cls: Type[T], packet: ScapyPacket) -> T:
        """
        Parse Scapy packet into the layer object.
        """
        pass
