
from __future__ import annotations

import socket
from abc import ABCMeta
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from socket import AddressFamily, SocketKind
from typing import Any, Optional, Tuple
from typing_extensions import Literal

__all__ = ['ProxyProtocolResult', 'ProxyProtocolResultLocal',
           'ProxyProtocolResultUnknown', 'ProxyProtocolResult4',
           'ProxyProtocolResult6', 'ProxyProtocolResultUnix']


@dataclass
class ProxyProtocolResult(metaclass=ABCMeta):
    """Base data class for PROXY protocol results.

    Attributes:
        source: The source address info for the connection.
        dest: The destination address info for the connection.
        protocol: The socket protocol for the connection.

    """

    source: Any
    dest: Any
    protocol: Optional[SocketKind] = None

    @property
    def family(self) -> AddressFamily:
        """The socket address family."""
        return socket.AF_UNSPEC

    @property
    def is_local(self) -> bool:
        """True if the connection should be treated as if it is not proxied."""
        return False

    @property
    def is_unknown(self) -> bool:
        """True if the source of the connection is unknown."""
        return False


@dataclass
class ProxyProtocolResultLocal(ProxyProtocolResult):
    """Indicates that the connection should be treated as if it is not proxied.
    The real socket :meth:`~socket.socket.getpeername` and
    :meth:`~socket.socket.getsockname` will provide the correct address
    information.

    """

    source: None = None
    dest: None = None

    @property
    def is_local(self) -> Literal[True]:
        return True


@dataclass
class ProxyProtocolResultUnknown(ProxyProtocolResult):
    """Indicates that the source of the connection is unknown."""

    source: None = None
    dest: None = None

    @property
    def is_unknown(self) -> Literal[True]:
        return True


@dataclass
class ProxyProtocolResult4(ProxyProtocolResult):
    """The original connection was made with an IPv4 socket. The
    :attr:`.source` and :attr:`.dest` properties will contain a tuple of an
    :class:`~ipaddress.IPv4Address` a port number.

    """

    source: Tuple[IPv4Address, int]
    dest: Tuple[IPv4Address, int]

    @property
    def family(self) -> AddressFamily:
        """Contains :attr:`~socket.AF_INET`."""
        return socket.AF_INET


@dataclass
class ProxyProtocolResult6(ProxyProtocolResult):
    """The original connection was made with an IPv6 socket. The
    :attr:`.source` and :attr:`.dest` properties will contain a tuple of an
    :class:`~ipaddress.IPv6Address` a port number.

    """
    source: Tuple[IPv6Address, int]
    dest: Tuple[IPv6Address, int]

    @property
    def family(self) -> AddressFamily:
        """Contains :attr:`~socket.AF_INET6`."""
        return socket.AF_INET6


@dataclass
class ProxyProtocolResultUnix(ProxyProtocolResult):
    """The original connection was made with a UNIX socket. The :attr:`.source`
    and :attr:`.dest` properties will contain a the full path to the socket
    file.

    """
    source: str
    dest: str

    @property
    def family(self) -> AddressFamily:
        """Contains :attr:`~socket.AF_UNIX`."""
        return socket.AF_UNIX
