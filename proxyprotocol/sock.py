
from __future__ import annotations

import socket
from ipaddress import ip_address, IPv4Address, IPv6Address
from socket import AddressFamily, SocketKind
from ssl import SSLContext
from typing import Any, Union, Optional, Mapping

from . import ProxyProtocolResult
from .typing import Address, TransportProtocol

__all__ = ['SocketInfo']

_missing = object()
_PeerCert = Mapping[str, Any]  # e.g. {'issuer': ...}


class SocketInfo:
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

    __slots__ = ['_transport', '_result']

    def __init__(self, transport: TransportProtocol,
                 result: Optional[ProxyProtocolResult] = None) -> None:
        super().__init__()
        self._transport = transport
        self._result = result

    @property
    def socket(self) -> socket.socket:
        """The underlying socket object.

        See Also:
            :meth:`~asyncio.BaseTransport.get_extra_info`

        """
        ret: socket.socket = self._transport.get_extra_info('socket')
        return ret

    def _get_ip(self, addr: Address) -> Union[None, IPv4Address, IPv6Address]:
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

    @property
    def sockname(self) -> Address:
        """The local address of the socket.

        See Also:
            :meth:`~socket.socket.getsockname`

        """
        if self._result is None or self._result.use_socket:
            ret: Address = self._transport.get_extra_info('sockname')
            return ret
        else:
            return self._result._sockname

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
    def peername(self) -> Address:
        """The remote address of the socket.

        See Also:
            :meth:`~socket.socket.getpeername`

        """
        if self._result is None or self._result.use_socket:
            ret: Address = self._transport.get_extra_info('peername')
            return ret
        else:
            return self._result._peername

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
    def family(self) -> AddressFamily:
        """The socket address family.

        See Also:
            :attr:`socket.socket.family`

        """
        if self._result is None or self._result.use_socket:
            return self.socket.family  # type: ignore
        else:
            return self._result.family

    @property
    def protocol(self) -> Optional[SocketKind]:
        """The socket protocol.

        See Also:
            :attr:`socket.socket.proto`

        """
        if self._result is None or self._result.use_socket:
            return self.socket.proto  # type: ignore
        else:
            return self._result.protocol

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

    def __getattr__(self, name: str) -> Any:
        ret = self._transport.get_extra_info(name, _missing)
        if ret is _missing:
            raise AttributeError(name)
        return ret

    def __str__(self) -> str:
        return '<SocketInfo peername=%r sockname=%r peercert=%r>' \
            % (self.peername, self.sockname, self.peercert)
