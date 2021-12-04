
from __future__ import annotations

import socket
import pkg_resources
from abc import abstractmethod, ABCMeta
from socket import AddressFamily, SocketKind
from ssl import SSLSocket, SSLObject
from typing import Any, Union, Optional, Sequence
from typing_extensions import Final

from .tlv import ProxyProtocolTLV
from .typing import Address

__all__ = ['__version__', 'ProxyProtocolSyntaxError',
           'ProxyProtocolChecksumError', 'ProxyProtocolIncompleteError',
           'ProxyProtocolWantRead', 'ProxyProtocolResult', 'ProxyProtocol']

#: The package version string.
__version__: str = pkg_resources.require('proxy-protocol')[0].version


class ProxyProtocolSyntaxError(ValueError):
    """Indicates a failure in parsing the PROXY protocol header. This indicates
    a syntax issue in the header, not simply bad data.

    Warning:
        It is possible that the entire PROXY protocol header was not yet read
        from the stream before failure. The stream should be considered invalid
        and closed.

    """

    __slots__: Sequence[str] = []


class ProxyProtocolChecksumError(ValueError):
    """The PROXY protocol header was parsed but contained a CRC32C checksum
    that did not match the expected value.

    Args:
        result: The PROXY protocol result.

    """

    __slots__ = ['result']

    def __init__(self, result: ProxyProtocolResult) -> None:
        super().__init__()
        self.result: Final = result


class ProxyProtocolIncompleteError(Exception):
    """Thrown when the PROXY protocol header cannot be parsed because the
    provided data is not enough to be parsed. The *want_read* conditions should
    be satisfied before trying to parse again.

    Args:
        want_read: Specifies what data is needed for parsing to continue.

    """

    __slots__ = ['want_read']

    def __init__(self, want_read: ProxyProtocolWantRead) -> None:
        super().__init__('Additional data needed')
        self.want_read: Final = want_read


class ProxyProtocolWantRead:
    """Specifies how much additional data must be read before PROXY protocol
    header parsing may be completed. Either *want_bytes* or *want_line* must be
    given, but not both.

    Args:
        want_bytes: Number of bytes needed before parsing may proceed.
        want_line: Additional data should be read until the end of a line.

    """

    __slots__ = ['want_bytes', 'want_line']

    def __init__(self, want_bytes: Optional[int] = None, *,
                 want_line: bool = False) -> None:
        super().__init__()
        self.want_bytes: Final = want_bytes
        self.want_line: Final = want_line


class ProxyProtocolResult(metaclass=ABCMeta):
    """Base class for PROXY protocol results."""

    __slots__: Sequence[str] = []

    @property
    @abstractmethod
    def proxied(self) -> bool:
        """True if the result should override the information in the underlying
        socket.

        """
        ...

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
    @abstractmethod
    def tlv(self) -> ProxyProtocolTLV:
        """Additional information about the connection."""
        ...

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
    def parse(self, data: bytes) -> ProxyProtocolResult:
        """Parse a PROXY protocol header from the given bytestring and return
        information about the original connection.

        Args:
            data: The bytestring read for the header thus far.

        Raises:
            :exc:`ProxyProtocolIncompleteError`: The header was incomplete and
                must be extended with additional bytes or lines to finish
                parsing.
            :exc:`ProxyProtocolSyntaxError`: The header failed to parse due to
                a syntax error or unsupported format.
            :exc:`ValueError`: Malformed or out-of-range data was encountered
                in the header.

        """
        ...

    @abstractmethod
    def build(self, source: Address, dest: Address, *, family: AddressFamily,
              protocol: Optional[SocketKind] = None,
              ssl: Union[None, SSLObject, SSLSocket] = None,
              unique_id: Optional[bytes] = None,
              proxied: bool = True,
              dnsbl: Optional[str] = None) -> bytes:
        """Builds a PROXY protocol v1 header that may be sent at the beginning
        of an outbound, client-side connection to indicate the original
        information about the connection.

        Args:
            source: The original source address of the connection.
            dest: The original destination address of the connection.
            family: The original socket family.
            protocol: The original socket protocol.
            ssl: The original socket SSL information.
            unique_id: The original connection unique identifier.
            proxied: True if the connection should be considered proxied.
            dnsbl: The DNSBL lookup result, if any.

        Raises:
            :exc:`KeyError`: This PROXY protocol header format does not support
                the socket information.
            :exc:`ValueError`: The address data could not be written to the
                PROXY protocol header format.

        """
        ...
