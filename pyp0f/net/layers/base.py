from abc import ABCMeta, abstractmethod
from typing import Type

from typing_extensions import Self

from pyp0f.net.scapy import ScapyPacket


class Layer(metaclass=ABCMeta):
    @classmethod
    @abstractmethod
    def from_packet(cls: Type[Self], packet: ScapyPacket) -> Self:
        """
        Parse Scapy packet into the layer object.
        """
