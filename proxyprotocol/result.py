
from __future__ import annotations

import socket
from ipaddress import IPv4Address, IPv6Address
from socket import AddressFamily, SocketKind
from typing import Optional, Tuple
from typing_extensions import Literal

from . import ProxyProtocolResult
from .tlv import ProxyProtocolTLV

__all__ = ['ProxyProtocolResult', 'ProxyProtocolResultLocal',
           'ProxyProtocolResultUnknown', 'ProxyProtocolResultIPv4',
           'ProxyProtocolResultIPv6', 'ProxyProtocolResultUnix']


class ProxyProtocolResultLocal(ProxyProtocolResult):
    """Indicates that the connection should be treated as if it is not proxied.
    The real socket :meth:`~socket.socket.getpeername` and
    :meth:`~socket.socket.getsockname` will provide the correct address
    information.

    """

    __slots__ = ['_tlv']

    def __init__(self, tlv: ProxyProtocolTLV = ProxyProtocolTLV()) -> None:
        super().__init__()
        self._tlv = tlv

    @property
    def proxied(self) -> Literal[False]:
        return False

    @property
    def source(self) -> None:
        return None

    @property
    def dest(self) -> None:
        return None

    @property
    def tlv(self) -> ProxyProtocolTLV:
        return self._tlv


class ProxyProtocolResultUnknown(ProxyProtocolResult):
    """Indicates that the source of the connection is unknown."""

    __slots__ = ['_exception']

    def __init__(self, exception: Optional[Exception] = None) -> None:
        super().__init__()
        self._exception = exception

    @property
    def exception(self) -> Optional[Exception]:
        """An exception that occurred during reading or parsing the PROXY
        protocol header.

        """
        return self._exception

    @property
    def proxied(self) -> Literal[True]:
        return True

    @property
    def source(self) -> None:
        return None

    @property
    def dest(self) -> None:
        return None

    @property
    def tlv(self) -> ProxyProtocolTLV:
        return ProxyProtocolTLV()


class ProxyProtocolResultIPv4(ProxyProtocolResult):
    """The original connection was made with an IPv4 socket. The
    :attr:`.source` and :attr:`.dest` properties will contain a tuple of an
    :class:`~ipaddress.IPv4Address` and a port number.

    """

    __slots__ = ['_source', '_dest', '_protocol', '_tlv']

    def __init__(self, source: Tuple[IPv4Address, int],
                 dest: Tuple[IPv4Address, int], *,
                 protocol: Optional[SocketKind] = None,
                 tlv: ProxyProtocolTLV = ProxyProtocolTLV()) -> None:
        super().__init__()
        self._source = source
        self._dest = dest
        self._protocol = protocol
        self._tlv = tlv

    @property
    def proxied(self) -> Literal[True]:
        return True

    @property
    def source(self) -> Tuple[IPv4Address, int]:
        return self._source

    @property
    def dest(self) -> Tuple[IPv4Address, int]:
        return self._dest

    @property
    def family(self) -> AddressFamily:
        return socket.AF_INET

    @property
    def protocol(self) -> Optional[SocketKind]:
        return self._protocol

    @property
    def tlv(self) -> ProxyProtocolTLV:
        return self._tlv

    @property
    def _peername(self) -> Tuple[str, int]:
        return str(self.source[0]), self.source[1]

    @property
    def _sockname(self) -> Tuple[str, int]:
        return str(self.dest[0]), self.dest[1]

    def __str__(self) -> str:
        if self.protocol is None:
            return f'ProxyProtocolResultIPv4({self.source!r}, {self.dest!r})'
        else:
            return f'ProxyProtocolResultIPv4({self.source!r}, {self.dest!r},' \
                f' protocol=socket.{self.protocol.name})'


class ProxyProtocolResultIPv6(ProxyProtocolResult):
    """The original connection was made with an IPv6 socket. The
    :attr:`.source` and :attr:`.dest` properties will contain a tuple of an
    :class:`~ipaddress.IPv6Address` and a port number.

    """

    __slots__ = ['_source', '_dest', '_protocol', '_tlv']

    def __init__(self, source: Tuple[IPv6Address, int],
                 dest: Tuple[IPv6Address, int], *,
                 protocol: Optional[SocketKind] = None,
                 tlv: ProxyProtocolTLV = ProxyProtocolTLV()) -> None:
        super().__init__()
        self._source = source
        self._dest = dest
        self._protocol = protocol
        self._tlv = tlv

    @property
    def proxied(self) -> Literal[True]:
        return True

    @property
    def source(self) -> Tuple[IPv6Address, int]:
        return self._source

    @property
    def dest(self) -> Tuple[IPv6Address, int]:
        return self._dest

    @property
    def family(self) -> AddressFamily:
        return socket.AF_INET6

    @property
    def protocol(self) -> Optional[SocketKind]:
        return self._protocol

    @property
    def tlv(self) -> ProxyProtocolTLV:
        return self._tlv

    @property
    def _peername(self) -> Tuple[str, int, int, int]:
        return str(self.source[0]), self.source[1], 0, 0

    @property
    def _sockname(self) -> Tuple[str, int, int, int]:
        return str(self.dest[0]), self.dest[1], 0, 0

    def __str__(self) -> str:
        if self.protocol is None:
            return f'ProxyProtocolResultIPv6({self.source!r}, {self.dest!r})'
        else:
            return f'ProxyProtocolResultIPv6({self.source!r}, {self.dest!r},' \
                f' protocol=socket.{self.protocol.name})'


class ProxyProtocolResultUnix(ProxyProtocolResult):
    """The original connection was made with a UNIX socket. The :attr:`.source`
    and :attr:`.dest` properties will contain a the full path to the socket
    file.

    """

    __slots__ = ['_source', '_dest', '_protocol', '_tlv']

    def __init__(self, source: str, dest: str, *,
                 protocol: Optional[SocketKind] = None,
                 tlv: ProxyProtocolTLV = ProxyProtocolTLV()) -> None:
        super().__init__()
        self._source = source
        self._dest = dest
        self._protocol = protocol
        self._tlv = tlv

    @property
    def proxied(self) -> Literal[True]:
        return True

    @property
    def source(self) -> str:
        return self._source

    @property
    def dest(self) -> str:
        return self._dest

    @property
    def family(self) -> AddressFamily:
        return socket.AF_UNIX

    @property
    def protocol(self) -> Optional[SocketKind]:
        return self._protocol

    @property
    def tlv(self) -> ProxyProtocolTLV:
        return self._tlv

    @property
    def _peername(self) -> str:
        return self.source

    @property
    def _sockname(self) -> str:
        return self.dest

    def __str__(self) -> str:
        if self.protocol is None:
            return f'ProxyProtocolResultUnix({self.source!r}, {self.dest!r})'
        else:
            return f'ProxyProtocolResultUnix({self.source!r}, {self.dest!r},' \
                f' protocol=socket.{self.protocol.name})'
