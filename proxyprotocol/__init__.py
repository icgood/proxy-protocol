
from __future__ import annotations

import socket
import pkg_resources
from abc import abstractmethod, ABCMeta
from socket import AddressFamily, SocketKind
from typing import Any, Optional, Sequence

from .typing import Address, StreamReaderProtocol

__all__ = ['__version__', 'ProxyProtocolError', 'ProxyProtocolResult',
           'ProxyProtocol']

#: The package version string.
__version__: str = pkg_resources.require('proxy-protocol')[0].version


class ProxyProtocolError(ValueError):
    """Indicates a failure in parsing the PROXY protocol header. This indicates
    a syntax issue in the header, not simply bad data.

    Warning:
        It is possible that the entire PROXY protocol header was not yet read
        from the stream before failure. The stream should be considered invalid
        and closed.

    """
    pass


class ProxyProtocolResult(metaclass=ABCMeta):
    """Base class for PROXY protocol results."""

    __slots__: Sequence[str] = []

    @property
    @abstractmethod
    def source(self) -> Any:
        """The original source address info for the connection."""
        ...

    @property
    @abstractmethod
    def dest(self) -> Any:
        """The original destination address info for the connection."""
        ...

    @property
    def family(self) -> AddressFamily:
        """The original socket address family."""
        return socket.AF_UNSPEC

    @property
    def protocol(self) -> Optional[SocketKind]:
        """The original socket protocol."""
        return None

    @property
    def use_socket(self) -> bool:
        """True if the result should be ignored in favor of the underlying
        socket information.

        """
        return False

    @property
    def _sockname(self) -> Address:
        return None

    @property
    def _peername(self) -> Address:
        return None

    def __str__(self) -> str:
        return f'{self.__class__.__name__!s}()'


class ProxyProtocol(metaclass=ABCMeta):
    """The base class for PROXY protocol implementations."""

    __slots__: Sequence[str] = []

    @abstractmethod
    def is_valid(self, signature: bytes) -> bool:
        """Returns True if the signature is valid for this implementation of
        the PROXY protocol header.

        Args:
            signature: The signature bytestring to check.

        """
        ...

    @abstractmethod
    async def read(self, reader: StreamReaderProtocol, *,
                   signature: bytes = b'') -> ProxyProtocolResult:
        """Read a PROXY protocol header from the given stream and return
        information about the original connection.

        Args:
            reader: The input stream.
            signature: Any data that has already been read from the stream.

        Raises:
            :exc:`~asyncio.IncompleteReadError`: The header failed to parse due
                to an EOF from the input stream.
            :exc:`ProxyProtocolError`: The header failed to parse due to a
                syntax error or unsupported format.
            :exc:`ValueError`: Malformed or out-of-range data was encountered
                in the header.

        """
        ...
