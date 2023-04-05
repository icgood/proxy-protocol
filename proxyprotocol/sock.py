
from __future__ import annotations

import socket
from abc import abstractmethod, ABCMeta
from ipaddress import ip_address, IPv4Address, IPv6Address
from socket import AddressFamily, SocketKind
from typing import Dict, Optional, Union

from .result import is_unknown, ProxyResult
from .typing import SockAddr, Cipher, PeerCert, TransportProtocol

__all__ = ['SocketInfo', 'SocketInfoProxy', 'SocketInfoLocal']

_IP = Union[None, IPv4Address, IPv6Address]


class SocketInfo(metaclass=ABCMeta):
    """Provides information about the connection, from either the underlying
    :mod:`asyncio` transport layer or overridden by the PROXY protocol result.

    """

    __slots__ = ['_transport']

    def __init__(self, transport: TransportProtocol) -> None:
        super().__init__()
        self._transport = transport

    @classmethod
    def get(cls, transport: TransportProtocol, result: Optional[ProxyResult],
            *, unique_id: bytes = b'', dnsbl: Optional[str] = None) \
            -> SocketInfo:
        """Choose the :class:`SocketInfo` implementation based on whether the
        *result* indicates the connection is
        :attr:`~proxyprotocol.result.ProxyResult.proxied`.

        Args:
            transport: The :class:`~asyncio.BaseTransport` or
                :class:`~asyncio.StreamWriter` for the connection.
            result: The PROXY protocol result.
            unique_id: A unique ID to associate with the connection, unless
                overridden by the PROXY protocol result.
            dnsbl: The DNSBL lookup result, if any.

        """
        if result is not None and result.proxied:
            return SocketInfoProxy(transport, result)
        else:
            return SocketInfoLocal(transport, unique_id=unique_id, dnsbl=dnsbl)

    @property
    def socket(self) -> socket.socket:  # pragma: no cover
        """The underlying socket object."""
        ret: socket.socket = self._transport.get_extra_info('socket')
        return ret

    def _get_ip(self, addr: SockAddr) -> _IP:
        if self.family in (socket.AF_INET, socket.AF_INET6):
            assert isinstance(addr, tuple)
            ip_str: str = addr[0]
            ip: Union[IPv4Address, IPv6Address] = ip_address(ip_str)
            if isinstance(ip, IPv6Address) and ip.ipv4_mapped is not None:
                ip = ip_address(ip.ipv4_mapped)
            return ip
        return None

    def _get_port(self, addr: SockAddr) -> Optional[int]:
        if self.family in (socket.AF_INET, socket.AF_INET6):
            assert isinstance(addr, tuple)
            port: int = addr[1]
            return port
        return None

    def _get_str(self, addr: SockAddr, ip: _IP,
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
    @abstractmethod
    def sockname(self) -> SockAddr:
        """The local address of the socket.

        See Also:
            :meth:`~socket.socket.getsockname`

        """
        ...

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
    @abstractmethod
    def peername(self) -> SockAddr:
        """The remote address of the socket.

        See Also:
            :meth:`~socket.socket.getpeername`

        """
        ...

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
    @abstractmethod
    def family(self) -> AddressFamily:
        """The socket address family.

        See Also:
            :attr:`socket.socket.family`

        """
        ...

    @property
    @abstractmethod
    def protocol(self) -> Optional[SocketKind]:
        """The socket protocol.

        See Also:
            :attr:`socket.socket.type`

        """
        ...

    @property
    @abstractmethod
    def compression(self) -> Optional[str]:
        """The :meth:`~ssl.SSLSocket.compression` value for encrypted
        connections.

        Note:
            For proxied connections, this data may be unavailable, depending on
            the server implementation and PROXY protocol version.

        """
        ...

    @property
    @abstractmethod
    def cipher(self) -> Optional[Cipher]:
        """The :meth:`~ssl.SSLSocket.cipher` value for encrypted connections.

        Note:
            For proxied connections, this data may be unavailable or partially
            available, depending on the server implementation and PROXY
            protocol version.

        """
        ...

    @property
    @abstractmethod
    def peercert(self) -> Optional[PeerCert]:
        """The :meth:`~ssl.SSLSocket.peercert` value for encrypted connections.

        Note:
            For proxied connections, this data may be unavailable, depending on
            the server implementation and PROXY protocol version.

        """
        ...

    @property
    @abstractmethod
    def unique_id(self) -> bytes:
        """A unique identifier for the connection. For proxied connections, the
        unique ID from the header (if any) is returned, otherwise returns the
        value passed in to the constructor.

        """
        ...

    @property
    @abstractmethod
    def dnsbl(self) -> Optional[str]:
        """The DNSBL lookup result of the connecting IP address, if any.

        This value is contextual to the DNSBL in use, but generally any value
        here other than ``None`` indicates the IP address should be blocked.

        """
        ...

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

    @abstractmethod
    def __repr__(self) -> str:
        ...


class SocketInfoProxy(SocketInfo):
    """Provides information about the connection, overridden by the PROXY
    protocol result.

    Args:
        result: The PROXY protocol result.

    """

    __slots__ = ['_result']

    def __init__(self, transport: TransportProtocol,
                 result: ProxyResult) -> None:
        super().__init__(transport)
        self._result = result

    @property
    def sockname(self) -> SockAddr:
        return self._result.sockname

    @property
    def peername(self) -> SockAddr:
        return self._result.peername

    @property
    def family(self) -> AddressFamily:
        return self._result.family

    @property
    def protocol(self) -> Optional[SocketKind]:
        return self._result.protocol

    @property
    def compression(self) -> Optional[str]:
        return self._result.tlv.ext.compression

    @property
    def cipher(self) -> Optional[Cipher]:
        result = self._result
        if result.tlv.ssl.has_ssl:
            cipher = result.tlv.ssl.cipher or ''
            version = result.tlv.ssl.version or ''
            secret_bits = result.tlv.ext.secret_bits or None
            return (cipher, version, secret_bits)
        else:
            return None

    @property
    def peercert(self) -> Optional[PeerCert]:
        return self._result.tlv.ext.peercert

    @property
    def unique_id(self) -> bytes:
        return self._result.tlv.unique_id

    @property
    def dnsbl(self) -> Optional[str]:
        return self._result.tlv.ext.dnsbl

    def __repr__(self) -> str:
        data: Dict[str, object] = {'peername': self.peername_str,
                                   'sockname': self.sockname_str}
        if is_unknown(self._result):
            data['exc'] = self._result.exception
        data_str = ''.join(f' {k}={v!r}' for k, v in data.items()
                           if v is not None)
        return f'<SocketInfoProxy{data_str}>'


class SocketInfoLocal(SocketInfo):
    """Provides information about the connection, from the underlying
    :mod:`asyncio` transport layer.

    Args:
        transport: The :class:`~asyncio.BaseTransport` or
            :class:`~asyncio.StreamWriter` for the connection.
        unique_id: A unique ID to associate with the connection, unless
            overridden by the PROXY protocol result.
        dnsbl: The DNSBL lookup result, if any.

    """

    __slots__ = ['_transport', '_unique_id', '_dnsbl']

    def __init__(self, transport: TransportProtocol,
                 result: Optional[ProxyResult] = None, *,
                 unique_id: bytes = b'', dnsbl: Optional[str] = None) -> None:
        super().__init__(transport)
        self._unique_id = unique_id
        self._dnsbl = dnsbl

    @property
    def sockname(self) -> SockAddr:
        ret: SockAddr = self._transport.get_extra_info('sockname')
        return ret

    @property
    def peername(self) -> SockAddr:
        ret: SockAddr = self._transport.get_extra_info('peername')
        return ret

    @property
    def family(self) -> AddressFamily:
        return AddressFamily(self.socket.family)

    @property
    def protocol(self) -> Optional[SocketKind]:
        return SocketKind(self.socket.type)

    @property
    def compression(self) -> Optional[str]:
        ret: Optional[str] = self._transport.get_extra_info('compression')
        return ret

    @property
    def cipher(self) -> Optional[Cipher]:
        ret: Optional[Cipher] = self._transport.get_extra_info('cipher')
        return ret

    @property
    def peercert(self) -> Optional[PeerCert]:
        ret: Optional[PeerCert] = self._transport.get_extra_info('peercert')
        return ret

    @property
    def unique_id(self) -> bytes:
        return self._unique_id

    @property
    def dnsbl(self) -> Optional[str]:
        return self._dnsbl

    def __repr__(self) -> str:
        return f'<SocketInfoLocal peername={self.peername_str!r} ' \
            f'sockname={self.sockname_str!r}>'
