
from __future__ import annotations

import socket
from abc import abstractmethod, ABCMeta
from ipaddress import IPv4Address, IPv6Address
from socket import AddressFamily, SocketKind
from typing import Optional, Sequence, Tuple
from typing_extensions import Literal, TypeGuard

from .tlv import ProxyProtocolTLV
from .typing import Address, SockAddr

__all__ = ['is_local', 'is_unknown', 'is_ipv4', 'is_ipv6', 'is_unix',
           'ProxyResult', 'ProxyResultLocal', 'ProxyResultUnknown',
           'ProxyResultIPv4', 'ProxyResultIPv6', 'ProxyResultUnix']

_empty_tlv = ProxyProtocolTLV()


def is_local(result: ProxyResult) \
        -> TypeGuard[ProxyResultLocal]:
    """Checks if the result is an unproxied local connection.

    Args:
        result: The proxy protocol result.

    """
    return not result.proxied


def is_unknown(result: ProxyResult) \
        -> TypeGuard[ProxyResultUnknown]:
    """Checks if the result is a proxied connection from an unknown origin.

    Args:
        result: The proxy protocol result.

    """
    return result.proxied and result.family == socket.AF_UNSPEC


def is_ipv4(result: ProxyResult) -> TypeGuard[ProxyResultIPv4]:
    """Checks if the result is a proxied IPv4 connection.

    Args:
        result: The proxy protocol result.

    """
    return result.proxied and result.family == socket.AF_INET


def is_ipv6(result: ProxyResult) -> TypeGuard[ProxyResultIPv6]:
    """Checks if the result is a proxied IPv6 connection.

    Args:
        result: The proxy protocol result.

    """
    return result.proxied and result.family == socket.AF_INET6


def is_unix(result: ProxyResult) -> TypeGuard[ProxyResultUnix]:
    """Checks if the result is a proxied UNIX connection.

    Args:
        result: The proxy protocol result.

    """
    return result.proxied and result.family == socket.AF_UNIX


class ProxyResult(metaclass=ABCMeta):
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
    def source(self) -> Address:
        """The original source address info for the connection."""
        ...

    @property
    @abstractmethod
    def dest(self) -> Address:
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
    @abstractmethod
    def peername(self) -> SockAddr:
        """The :attr:`.source` value in :data:`~proxyprotocol.typing.SockAddr`
        form.

        """
        ...

    @property
    @abstractmethod
    def sockname(self) -> SockAddr:
        """The :attr:`.dest` value in :data:`~proxyprotocol.typing.SockAddr`
        form.

        """
        ...

    @property
    def _repr_args(self) -> Sequence[str]:
        args = [f'{self.source!r}', f'{self.dest!r}']
        if self.protocol is not None:
            args.append(f'protocol=socket.{self.protocol.name}')
        if self.tlv:  # pragma: no cover
            args.append(f'tlv={self.tlv!r}')
        return args

    def __repr__(self) -> str:
        class_name = f'{self.__class__.__name__!s}'
        args = ', '.join(self._repr_args)
        return f'{class_name}({args})'


class ProxyResultLocal(ProxyResult):
    """Indicates that the connection should be treated as if it is not proxied.
    The real socket :meth:`~socket.socket.getpeername` and
    :meth:`~socket.socket.getsockname` will provide the correct address
    information.

    Args:
        tlv: Additional information about the connection.

    """

    __slots__ = ['_tlv']

    def __init__(self, *, tlv: ProxyProtocolTLV = _empty_tlv) -> None:
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
    def peername(self) -> None:
        return None

    @property
    def sockname(self) -> None:
        return None

    @property
    def tlv(self) -> ProxyProtocolTLV:
        return self._tlv

    @property
    def _repr_args(self) -> Sequence[str]:
        if self.tlv:  # pragma: no cover
            return [f'tlv={self.tlv!r}']
        else:
            return []


class ProxyResultUnknown(ProxyResult):
    """Indicates that the source of the connection is unknown.

    Args:
        exception: The exception that occurred, if any.
        tlv: Additional information about the connection.

    """

    __slots__ = ['_exception', '_tlv']

    def __init__(self, exception: Optional[Exception] = None, *,
                 tlv: ProxyProtocolTLV = _empty_tlv) -> None:
        super().__init__()
        self._exception = exception
        self._tlv = tlv

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
    def peername(self) -> None:
        return None

    @property
    def sockname(self) -> None:
        return None

    @property
    def tlv(self) -> ProxyProtocolTLV:
        return self._tlv

    @property
    def _repr_args(self) -> Sequence[str]:
        args = []
        if self.exception is not None:
            args.append(repr(self.exception))
        if self.tlv:  # pragma: no cover
            args.append(f'tlv={self.tlv!r}')
        return args


class ProxyResultIPv4(ProxyResult):
    """The original connection was made with an IPv4 socket. The
    :attr:`.source` and :attr:`.dest` properties will contain a tuple of an
    :class:`~ipaddress.IPv4Address` and a port number.

    Args:
        source: The source address of the connection.
        dest: The destination address of the connection.
        protocol: The socket protocol (or :attr:`~socket.socket.type`).
        tlv: Additional information about the connection.

    """

    __slots__ = ['_source', '_dest', '_protocol', '_tlv']

    def __init__(self, source: Tuple[IPv4Address, int],
                 dest: Tuple[IPv4Address, int], *,
                 protocol: Optional[SocketKind] = None,
                 tlv: ProxyProtocolTLV = _empty_tlv) -> None:
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
    def peername(self) -> Tuple[str, int]:
        return str(self.source[0]), self.source[1]

    @property
    def sockname(self) -> Tuple[str, int]:
        return str(self.dest[0]), self.dest[1]


class ProxyResultIPv6(ProxyResult):
    """The original connection was made with an IPv6 socket. The
    :attr:`.source` and :attr:`.dest` properties will contain a tuple of an
    :class:`~ipaddress.IPv6Address` and a port number.

    Args:
        source: The source address of the connection.
        dest: The destination address of the connection.
        protocol: The socket protocol (or :attr:`~socket.socket.type`).
        tlv: Additional information about the connection.

    """

    __slots__ = ['_source', '_dest', '_protocol', '_tlv']

    def __init__(self, source: Tuple[IPv6Address, int],
                 dest: Tuple[IPv6Address, int], *,
                 protocol: Optional[SocketKind] = None,
                 tlv: ProxyProtocolTLV = _empty_tlv) -> None:
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
    def peername(self) -> Tuple[str, int, int, int]:
        return str(self.source[0]), self.source[1], 0, 0

    @property
    def sockname(self) -> Tuple[str, int, int, int]:
        return str(self.dest[0]), self.dest[1], 0, 0


class ProxyResultUnix(ProxyResult):
    """The original connection was made with a UNIX socket. The :attr:`.source`
    and :attr:`.dest` properties will contain a the full path to the socket
    file.

    Args:
        source: The source address file of the connection.
        dest: The destination address file of the connection.
        protocol: The socket protocol (or :attr:`~socket.socket.type`).
        tlv: Additional information about the connection.

    """

    __slots__ = ['_source', '_dest', '_protocol', '_tlv']

    def __init__(self, source: str, dest: str, *,
                 protocol: Optional[SocketKind] = None,
                 tlv: ProxyProtocolTLV = _empty_tlv) -> None:
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
    def peername(self) -> str:
        return self.source

    @property
    def sockname(self) -> str:
        return self.dest
