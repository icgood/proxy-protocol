
from __future__ import annotations

import socket
from ipaddress import IPv4Address, IPv6Address
from socket import AddressFamily, SocketKind
from ssl import SSLObject, SSLSocket
from typing import Optional, Union

from .result import ProxyResult, ProxyResultUnknown, ProxyResultIPv4, \
    ProxyResultIPv6, ProxyResultUnix
from .tlv import ProxyProtocolTLV, ProxyProtocolSSLTLV, ProxyProtocolExtTLV
from .typing import PeerCert, SockAddr, TransportProtocol

__all__ = ['build_socket_result', 'build_transport_result']


def build_socket_result(sock: socket.socket, *,
                        unique_id: Optional[bytes] = None,
                        dnsbl: Optional[str] = None) -> ProxyResult:
    """Build a :class:`~proxyprotocol.result.ProxyResult` from the given
    *sock* object.

    Args:
        sock: A connected socket object.

    """
    peername: SockAddr = sock.getpeername()
    sockname: SockAddr = sock.getsockname()
    ssl_sock: Optional[SSLSocket] = None
    if isinstance(sock, SSLSocket):
        ssl_sock = sock
    return _build_result(sock, peername, sockname, ssl_sock, unique_id, dnsbl)


def build_transport_result(transport: TransportProtocol, *,
                           unique_id: Optional[bytes] = None,
                           dnsbl: Optional[str] = None) -> ProxyResult:
    """Build a :class:`~proxyprotocol.result.ProxyResult` from the given
    *transport* object.

    Args:
        transport: A connected transport object.

    """
    sock: socket.socket = transport.get_extra_info('socket')
    peername: SockAddr = transport.get_extra_info('peername')
    sockname: SockAddr = transport.get_extra_info('sockname')
    ssl_obj: Optional[SSLObject] = transport.get_extra_info('ssl_object')
    return _build_result(sock, peername, sockname, ssl_obj, unique_id, dnsbl)


def _build_result(sock: socket.socket, peername: SockAddr, sockname: SockAddr,
                  ssl_obj: Union[None, SSLObject, SSLSocket],
                  unique_id: Optional[bytes], dnsbl: Optional[str]) \
        -> ProxyResult:
    family = AddressFamily(sock.family)
    protocol = SocketKind(sock.type)
    if family == socket.AF_INET:
        assert isinstance(peername, tuple)
        assert isinstance(sockname, tuple)
        tlv = _build_tlv(ssl_obj, unique_id, dnsbl)
        return ProxyResultIPv4((IPv4Address(peername[0]), peername[1]),
                               (IPv4Address(sockname[0]), sockname[1]),
                               protocol=protocol, tlv=tlv)
    elif family == socket.AF_INET6:
        assert isinstance(peername, tuple)
        assert isinstance(sockname, tuple)
        tlv = _build_tlv(ssl_obj, unique_id, dnsbl)
        return ProxyResultIPv6((IPv6Address(peername[0]), peername[1]),
                               (IPv6Address(sockname[0]), sockname[1]),
                               protocol=protocol, tlv=tlv)
    elif family == socket.AF_UNIX:
        assert isinstance(peername, str)
        assert isinstance(sockname, str)
        tlv = _build_tlv(ssl_obj, unique_id, dnsbl)
        return ProxyResultUnix(peername, sockname, protocol=protocol, tlv=tlv)
    else:
        return ProxyResultUnknown()


def _build_tlv(ssl_obj: Union[None, SSLObject, SSLSocket],
               unique_id: Optional[bytes],
               dnsbl: Optional[str]) -> ProxyProtocolTLV:
    ssl_tlv: Optional[ProxyProtocolSSLTLV] = None
    ext_tlv: Optional[ProxyProtocolExtTLV] = None
    if dnsbl is not None:
        ext_tlv = ProxyProtocolExtTLV(init=ext_tlv, dnsbl=dnsbl)
    if ssl_obj is not None:
        cipher, version, secret_bits = ssl_obj.cipher() or (None, None, None)
        peercert: Optional[PeerCert] = ssl_obj.getpeercert()
        ssl_tlv = ProxyProtocolSSLTLV(
            has_ssl=True, verify=True,
            has_cert_conn=(peercert is not None),
            cipher=cipher, version=version)
        ext_tlv = ProxyProtocolExtTLV(
            init=ext_tlv, compression=ssl_obj.compression(),
            secret_bits=secret_bits, peercert=peercert, dnsbl=dnsbl)
    return ProxyProtocolTLV(unique_id=unique_id, ssl=ssl_tlv, ext=ext_tlv)
