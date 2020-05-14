
from __future__ import annotations

from abc import abstractmethod, ABCMeta
from typing_extensions import Protocol

from .result import ProxyProtocolResult

__all__ = ['ProxyProtocolError', 'DataReader', 'ProxyProtocol']


class ProxyProtocolError(ValueError):
    """Indicates a failure in parsing the PROXY protocol header.

    Warning:
        It is possible that the entire PROXY protocol header was not yet read
        from the stream before failure. The stream should be considered invalid
        and closed.

    """
    pass


class DataReader(Protocol):
    """A typing abstraction intended to be compatible with
    :class:`~asyncio.StreamReader`, which may not exist as-is in future Python
    versions.

    """

    @abstractmethod
    async def readexactly(self, n: int) -> bytes:
        ...

    @abstractmethod
    async def readuntil(self, separator: bytes) -> bytes:
        ...


class ProxyProtocol(metaclass=ABCMeta):
    """The base class for PROXY protocol implementations."""

    @abstractmethod
    async def read(self, reader: DataReader, *,
                   signature: bytes = b'') -> ProxyProtocolResult:
        """Read a PROXY protocol header from the given stream and return
        information about the original connection.

        Raises:
            :exc:`ProxyProtocolError`, :exc:`~asyncio.IncompleteReadError`

        """
        ...
