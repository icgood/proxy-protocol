
from __future__ import annotations

import socket
from ipaddress import ip_address, IPv4Address, IPv6Address
from socket import AddressFamily, SocketKind
from typing import Union, Optional
from typing_extensions import Final

from . import ProxyProtocolResult
from .result import ProxyProtocolResultLocal
from .typing import Address, Cipher, PeerCert, TransportProtocol

__all__ = ['SocketInfo']

_IP = Union[None, IPv4Address, IPv6Address]


class SocketInfo:
    """Provides information about the connection, from either the underlying
    :mod:`asyncio` transport layer or overridden by the PROXY protocol result.

    Args:
        transport: The :class:`~asyncio.BaseTransport` or
            :class:`~asyncio.StreamWriter` for the connection.
        result: The PROXY protocol result.
        unique_id: A unique ID to associate with the connection, unless
            overridden by the PROXY protocol result.
        dnsbl: The DNSBL lookup result, if any.

    """

    __slots__ = ['transport', 'pp_result', '_unique_id', '_dnsbl']

    def __init__(self, transport: TransportProtocol,
                 result: Optional[ProxyProtocolResult] = None, *,
                 unique_id: bytes = b'', dnsbl: Optional[str] = None) -> None:
        super().__init__()
        self.transport: Final = transport
        self.pp_result: Final = result or ProxyProtocolResultLocal()
        self._unique_id = unique_id
        self._dnsbl = dnsbl

    @property
    def socket(self) -> socket.socket:
        """The underlying socket object.

        See Also:
            :meth:`~asyncio.BaseTransport.get_extra_info`

        """
        ret: socket.socket = self.transport.get_extra_info('socket')
        return ret

    def _get_ip(self, addr: Address) -> _IP:
        if self.family in (socket.AF_INET, socket.AF_INET6):
            assert isinstance(addr, tuple)
            ip_str: str = addr[0]
            ip: Union[IPv4Address, IPv6Address] = ip_address(ip_str)
            if isinstance(ip, IPv6Address) and ip.ipv4_mapped is not None:
                ip = ip_address(ip.ipv4_mapped)
            return ip
        return None

    def _get_port(self, addr: Address) -> Optional[int]:
        if self.family in (socket.AF_INET, socket.AF_INET6):
            assert isinstance(addr, tuple)
            port: int = addr[1]
            return port
        return None

    def _get_str(self, addr: Address, ip: _IP,
                 port: Optional[int]) -> Optional[str]:
        if self.family in (socket.AF_INET, socket.AF_INET6):
            return f'[{ip!s}]:{port!s}'
        elif self.family == socket.AF_UNIX:
            assert isinstance(addr, str)
            return addr
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
            ret: Address = self.transport.get_extra_info('sockname')
            return ret

    @property
    def sockname_ip(self) -> Union[None, IPv4Address, IPv6Address]:
        """The IP address object from :attr:`.sockname`, for
        :data:`~socket.AF_INET` or :data:`~socket.AF_INET6` connections.

        """
        return self._get_ip(self.sockname)

    @property
    def sockname_port(self) -> Optional[int]:
        """The port number from :attr:`.sockname`, for
        :data:`~socket.AF_INET` or :data:`~socket.AF_INET6` connections.

        """
        return self._get_port(self.sockname)

    @property
    def sockname_str(self) -> Optional[str]:
        """The :attr:`.sockname` address as a string. For
        :data:`~socket.AF_INET`/:data:`~socket.AF_INET6` families, this is
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
            ret: Address = self.transport.get_extra_info('peername')
            return ret

    @property
    def peername_ip(self) -> Union[None, IPv4Address, IPv6Address]:
        """The IP address object from :attr:`.peername`, for
        :data:`~socket.AF_INET` or :data:`~socket.AF_INET6` connections.

        """
        return self._get_ip(self.peername)

    @property
    def peername_port(self) -> Optional[int]:
        """The port number from :attr:`.peername`, for
        :data:`~socket.AF_INET` or :data:`~socket.AF_INET6` connections.

        """
        return self._get_port(self.peername)

    @property
    def peername_str(self) -> Optional[str]:
        """The :attr:`.peername` address as a string. For
        :data:`~socket.AF_INET`/:data:`~socket.AF_INET6` families, this is
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
            return AddressFamily(self.socket.family)

    @property
    def protocol(self) -> Optional[SocketKind]:
        """The socket protocol.

        See Also:
            :attr:`socket.socket.type`

        """
        if self.pp_result.proxied:
            return self.pp_result.protocol
        else:
            return SocketKind(self.socket.type)

    @property
    def compression(self) -> Optional[str]:
        """The :meth:`~ssl.SSLSocket.compression` value for encrypted
        connections.

        Note:
            For proxied connections, this data may be unavailable, depending on
            the server implementation and PROXY protocol version.

        """
        if self.pp_result.proxied:
            return self.pp_result.tlv.ext.compression
        else:
            ret: Optional[str] = self.transport.get_extra_info('compression')
            return ret

    @property
    def cipher(self) -> Optional[Cipher]:
        """The :meth:`~ssl.SSLSocket.cipher` value for encrypted connections.

        Note:
            For proxied connections, this data may be unavailable or partially
            available, depending on the server implementation and PROXY
            protocol version.

        """
        if self.pp_result.proxied:
            if self.pp_result.tlv.ssl.has_ssl:
                cipher = self.pp_result.tlv.ssl.cipher or ''
                version = self.pp_result.tlv.ssl.version or ''
                secret_bits = self.pp_result.tlv.ext.secret_bits or None
                return (cipher, version, secret_bits)
            else:
                return None
        else:
            ret: Optional[Cipher] = self.transport.get_extra_info('cipher')
            return ret

    @property
    def peercert(self) -> Optional[PeerCert]:
        """The :meth:`~ssl.SSLSocket.peercert` value for encrypted connections.

        Note:
            For proxied connections, this data may be unavailable, depending on
            the server implementation and PROXY protocol version.

        """
        if self.pp_result.proxied:
            return self.pp_result.tlv.ext.peercert
        else:
            ret: Optional[PeerCert] = self.transport.get_extra_info('peercert')
            return ret

    @property
    def unique_id(self) -> bytes:
        """A unique identifier for the connection. For proxied connections, the
        unique ID from the header (if any) is returned, otherwise returns the
        value passed in to the constructor.

        """
        if self.pp_result.proxied:
            return self.pp_result.tlv.unique_id
        else:
            return self._unique_id

    @property
    def from_localhost(self) -> bool:
        """True for local socket connections, if:

        * :attr:`.family` is :data:`~socket.AF_UNIX`, or
        * :attr:`.peername_ip` has True
          :attr:`~ipaddress.IPv4Address.is_loopback` flag.

        To be specific, True for :data:`~socket.AF_UNIX` connections and True
        for IPv4/IPv6 connections with True
        :attr:`~ipaddress.IPv4Address.is_loopback` flags.

        """
        if self.family == socket.AF_UNIX:
            return True
        ip = self.peername_ip
        if ip is None:
            return False
        return ip.is_loopback

    @property
    def dnsbl(self) -> Optional[str]:
        """The DNSBL lookup result of the connecting IP address, if any.

        This value is contextual to the DNSBL in use, but generally any value
        here other than ``None`` indicates the IP address should be blocked.

        """
        if self.pp_result.proxied:
            return self.pp_result.tlv.ext.dnsbl
        else:
            return self._dnsbl

    def __str__(self) -> str:
        proxied = ' proxied=True' if self.pp_result.proxied else ''
        return '<SocketInfo peername=%r sockname=%r%s>' \
            % (self.peername_str, self.sockname_str, proxied)
