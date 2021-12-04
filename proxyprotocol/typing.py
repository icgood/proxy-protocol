
from __future__ import annotations

from abc import abstractmethod
from typing import Any, Union, Optional, Tuple, Mapping
from typing_extensions import Protocol

__all__ = ['Address', 'PeerCert', 'Cipher',
           'StreamReaderProtocol', 'TransportProtocol']

#: The types that can be retured by :meth:`~socket.socket.getsockname` and
#: :meth:`~socket.socket.getpeername`.
Address = Union[None, str, Tuple[str, int], Tuple[str, int, int, int]]

#: The type returned by :meth:`ssl.SSLSocket.cipher`.
Cipher = Tuple[str, str, Optional[int]]

#: The type returned by :meth:`ssl.SSLSocket.getpeercert`.
PeerCert = Mapping[str, Any]


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
