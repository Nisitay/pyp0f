from abc import ABCMeta, abstractmethod
from typing import TypeVar, Type

from pyp0f.net.packet import Packet

T = TypeVar("T", bound="DatabaseSig")


class DatabaseSig(metaclass=ABCMeta):
    __slots__ = ()

    @classmethod
    @abstractmethod
    def parse(cls: Type[T], raw_signature: str) -> T:
        """
        Parse raw signature and validate values.
        Signature syntax isn't validated, errors are only raised for invalid values.
        """
        pass


class PacketSig(metaclass=ABCMeta):
    __slots__ = ()

    @classmethod
    @abstractmethod
    def from_packet(cls, packet: Packet):
        pass
