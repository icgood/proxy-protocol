
from __future__ import annotations

from abc import abstractmethod
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Union, Optional, Tuple, Mapping
from typing_extensions import Protocol, TypeAlias

__all__ = ['SockAddr', 'Address', 'Cipher', 'PeerCert',
           'StreamReaderProtocol', 'TransportProtocol']

#: The types that can be retured by :meth:`~socket.socket.getsockname` and
#: :meth:`~socket.socket.getpeername`.
SockAddr: TypeAlias = Union[None,
                            str,
                            Tuple[str, int],
                            Tuple[str, int, int, int]]

#: The types that can be returned by address attributes on
#: :class:`~proxyprotocol.ProxyProtocolResult`.
Address: TypeAlias = Union[None,
                           str,
                           Tuple[IPv4Address, int],
                           Tuple[IPv6Address, int]]

#: The type returned by :meth:`ssl.SSLSocket.cipher`.
Cipher: TypeAlias = Tuple[str, str, Optional[int]]

#: The type returned by :meth:`ssl.SSLSocket.getpeercert`.
PeerCert: TypeAlias = Mapping[str, Any]


class StreamReaderProtocol(Protocol):
    """A typing abstraction intended to be compatible with
    :class:`~asyncio.StreamReader`..

    """

    @abstractmethod
    async def readexactly(self, n: int) -> bytes:
        ...

    @abstractmethod
    async def readline(self) -> bytes:
        ...


class TransportProtocol(Protocol):
    """A typing abstraction intended to be compatible with both
    :class:`~asyncio.BaseTransport` and :class:`~asyncio.StreamWriter`.

    """

    @abstractmethod
    def get_extra_info(self, name: str, default: Any = None) -> Any:
        ...
