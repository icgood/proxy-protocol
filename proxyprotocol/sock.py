
import socket
from ipaddress import ip_address, IPv4Address, IPv6Address
from socket import AddressFamily, SocketKind
from ssl import SSLContext
from typing import Any, Union, Optional, Container, Mapping
from typing_extensions import Final

from . import ProxyProtocolResult
from .result import ProxyProtocolResultLocal
from .typing import Address, TransportProtocol

__all__ = ['SocketInfo']

_missing = object()
_PeerCert = Mapping[str, Any]  # e.g. {'issuer': ...}
_IP = Union[None, IPv4Address, IPv6Address]


class SocketInfo(Container[str]):
    """Provides information about the connection, from either the underlying
    :mod:`asyncio` transport layer or overridden by the PROXY protocol result.

    Undocumented properties will pass through as calls to
    :meth:`~asyncio.BaseTransport.get_extra_info` and will raise
    :exc:`AttributeError` if there is no value available.

    Args:
        transport: The :class:`~asyncio.BaseTransport` or
            :class:`~asyncio.StreamWriter` for the connection.
        result: The PROXY protocol result.

    """

    __slots__ = ['_transport', 'pp_result']

    def __init__(self, transport: TransportProtocol,
                 result: Optional[ProxyProtocolResult] = None) -> None:
        super().__init__()
        self._transport = transport
        self.pp_result: Final = result or ProxyProtocolResultLocal()

    @property
    def socket(self) -> socket.socket:
        """The underlying socket object.

        See Also:
            :meth:`~asyncio.BaseTransport.get_extra_info`

        """
        ret: socket.socket = self._transport.get_extra_info('socket')
        return ret

    def _get_ip(self, addr: Address) -> _IP:
        if self.family in (socket.AF_INET, socket.AF_INET6):
            ip_str: str = addr[0]  # type: ignore
            ip: Union[IPv4Address, IPv6Address] = ip_address(ip_str)
            if isinstance(ip, IPv6Address) and ip.ipv4_mapped is not None:
                ip = ip_address(ip.ipv4_mapped)
            return ip
        return None

    def _get_port(self, addr: Address) -> Optional[int]:
        if self.family in (socket.AF_INET, socket.AF_INET6):
            port: int = addr[1]  # type: ignore
            return port
        return None

    def _get_str(self, addr: Address, ip: _IP,
                 port: Optional[int]) -> Optional[str]:
        if self.family in (socket.AF_INET, socket.AF_INET6):
            return f'[{ip!s}]:{port!s}'
        elif self.family == socket.AF_UNIX:
            addr_str: str = addr  # type: ignore
            return addr_str
        elif self.family == socket.AF_UNSPEC:
            return None
        else:  # pragma: no cover
            return str(addr)

    @property
    def sockname(self) -> Address:
        """The local address of the socket.

        See Also:
            :meth:`~socket.socket.getsockname`

        """
        if self.pp_result.proxied:
            return self.pp_result._sockname
        else:
            ret: Address = self._transport.get_extra_info('sockname')
            return ret

    @property
    def sockname_ip(self) -> Union[None, IPv4Address, IPv6Address]:
        """The IP address object from :attr:`.sockname`, for
        :attr:`~socket.AF_INET` or :attr:`~socket.AF_INET6` connections.

        """
        return self._get_ip(self.sockname)

    @property
    def sockname_port(self) -> Optional[int]:
        """The port number from :attr:`.sockname`, for
        :attr:`~socket.AF_INET` or :attr:`~socket.AF_INET6` connections.

        """
        return self._get_port(self.sockname)

    @property
    def sockname_str(self) -> Optional[str]:
        """The :attr:`.sockname` address as a string. For
        :attr:`~socket.AF_INET`/:attr:`~socket.AF_INET6` families, this is
        ``ip:port``.

        """
        return self._get_str(self.sockname, self.sockname_ip,
                             self.sockname_port)

    @property
    def peername(self) -> Address:
        """The remote address of the socket.

        See Also:
            :meth:`~socket.socket.getpeername`

        """
        if self.pp_result.proxied:
            return self.pp_result._peername
        else:
            ret: Address = self._transport.get_extra_info('peername')
            return ret

    @property
    def peername_ip(self) -> Union[None, IPv4Address, IPv6Address]:
        """The IP address object from :attr:`.peername`, for
        :attr:`~socket.AF_INET` or :attr:`~socket.AF_INET6` connections.

        """
        return self._get_ip(self.peername)

    @property
    def peername_port(self) -> Optional[int]:
        """The port number from :attr:`.peername`, for
        :attr:`~socket.AF_INET` or :attr:`~socket.AF_INET6` connections.

        """
        return self._get_port(self.peername)

    @property
    def peername_str(self) -> Optional[str]:
        """The :attr:`.peername` address as a string. For
        :attr:`~socket.AF_INET`/:attr:`~socket.AF_INET6` families, this is
        ``ip:port``.

        """
        return self._get_str(self.peername, self.peername_ip,
                             self.peername_port)

    @property
    def family(self) -> AddressFamily:
        """The socket address family.

        See Also:
            :attr:`socket.socket.family`

        """
        if self.pp_result.proxied:
            return self.pp_result.family
        else:
            return self.socket.family  # type: ignore

    @property
    def protocol(self) -> Optional[SocketKind]:
        """The socket protocol.

        See Also:
            :attr:`socket.socket.proto`

        """
        if self.pp_result.proxied:
            return self.pp_result.protocol
        else:
            return self.socket.proto  # type: ignore

    @property
    def peercert(self) -> Optional[_PeerCert]:
        """The peer certificate for the socket, if encrypted.

        See Also:
            :meth:`~asyncio.BaseTransport.get_extra_info`

        """
        ret: Optional[_PeerCert] = self._transport.get_extra_info('peercert')
        return ret

    @property
    def ssl_context(self) -> Optional[SSLContext]:
        """The SSL context for the socket, if encrypted.

        See Also:
            :meth:`~asyncio.BaseTransport.get_extra_info`

        """
        ret: Optional[SSLContext] = \
            self._transport.get_extra_info('sslcontext')
        return ret

    @property
    def from_localhost(self) -> bool:
        """True for local socket connections, if:

        * :attr:`.family` is :attr:`~socket.AF_UNIX`, or
        * :attr:`.peername_ip` has True
          :attr:`~ipaddress.IPv4Address.is_loopback` flag.

        To be specific, True for :attr:`~socket.AF_UNIX` connections and True
        for IPv4/IPv6 connections with True
        :attr:`~ipaddress.IPv4Address.is_loopback` flags.

        """
        if self.family == socket.AF_UNIX:
            return True
        ip = self.peername_ip
        if ip is None:
            return False
        return ip.is_loopback

    def __contains__(self, name: object) -> bool:
        if not isinstance(name, str):
            return False
        try:
            self[name]
        except KeyError:
            return False
        else:
            return True

    def __getitem__(self, name: str) -> Any:
        ret = self._transport.get_extra_info(name, _missing)
        if ret is _missing:
            raise KeyError(name)
        return ret

    def get(self, name: str, default: Any = None) -> Any:
        """Return the :meth:`~asyncio.BaseTransport.get_extra_info` data
        indicated by *name*, returning *default* if the data is not available.

        Note:
            This object also implements :meth:`~object.__getitem__`, which will
            throw :exc:`KeyError` if the data is not available.

        Args:
            name: The data name, e.g. ``cipher``.
            default: The object to return if the data is not available.

        """
        try:
            return self[name]
        except KeyError:
            return default

    def __str__(self) -> str:
        proxied = ' proxied=True' if self.pp_result.proxied else ''
        return '<SocketInfo peername=%r sockname=%r peercert=%r%s>' \
            % (self.peername_str, self.sockname_str, self.peercert, proxied)
