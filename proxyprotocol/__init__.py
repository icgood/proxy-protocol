
from __future__ import annotations

from abc import abstractmethod, ABCMeta
from typing import Optional, Sequence
from typing_extensions import Final

from .result import ProxyResult

__all__ = ['ProxyProtocolSyntaxError', 'ProxyProtocolChecksumError',
           'ProxyProtocolIncompleteError', 'ProxyProtocolWantRead',
           'ProxyProtocol']


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

    def __init__(self, result: ProxyResult) -> None:
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
    def unpack(self, data: bytes) -> ProxyResult:
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
    def pack(self, result: ProxyResult) -> bytes:
        """Builds a PROXY protocol header that may be sent at the beginning of
        an outbound, client-side connection to indicate the original
        information about the connection.

        Args:
            result: The PROXY protocol result to build into a header.

        Raises:
            :exc:`KeyError`: This PROXY protocol header format does not support
                the socket information.
            :exc:`ValueError`: The address data could not be written to the
                PROXY protocol header format.

        """
        ...
