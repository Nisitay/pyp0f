from abc import ABCMeta, abstractmethod
from typing import Type

from scapy.packet import Packet as ScapyPacket
from typing_extensions import Self


class Layer(metaclass=ABCMeta):
    @classmethod
    @abstractmethod
    def from_packet(cls: Type[Self], packet: ScapyPacket) -> Self:
        """
        Parse Scapy packet into the layer object.
        """
