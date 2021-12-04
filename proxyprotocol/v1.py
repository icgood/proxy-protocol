
from __future__ import annotations

import socket
from ipaddress import IPv4Address, IPv6Address
from socket import AddressFamily, SocketKind
from ssl import SSLSocket, SSLObject
from typing import Union, Optional, Sequence

from . import ProxyProtocolWantRead, ProxyProtocolResult, ProxyProtocol, \
    ProxyProtocolSyntaxError, ProxyProtocolIncompleteError
from .result import ProxyProtocolResultUnknown, ProxyProtocolResultIPv4, \
    ProxyProtocolResultIPv6
from .typing import Address


class ProxyProtocolV1(ProxyProtocol):
    """Implements version 1 of the PROXY protocol."""

    __slots__: Sequence[str] = []

    def is_valid(self, signature: bytes) -> bool:
        return signature[0:6] == b'PROXY '

    def parse(self, data: bytes) -> ProxyProtocolResult:
        if data[-1:] != b'\n':
            want_read = ProxyProtocolWantRead(want_line=True)
            raise ProxyProtocolIncompleteError(want_read)
        return self.parse_line(data)

    def parse_line(self, data: bytes) -> ProxyProtocolResult:
        """Parse the PROXY protocol v1 header line.

        Args:
            data: The bytestring to parse.

        """
        if data[0:6] != b'PROXY ' or data[-2:] != b'\r\n':
            raise ProxyProtocolSyntaxError(
                'Invalid proxy protocol v1 signature')
        line = bytes(data[6:-2])
        parts = line.split(b' ')
        family_string = parts[0]
        if family_string == b'UNKNOWN':
            return ProxyProtocolResultUnknown()
        elif len(parts) != 5:
            raise ProxyProtocolSyntaxError(
                'Invalid proxy protocol header format')
        elif family_string == b'TCP4':
            source_addr4 = (self._get_ip4(parts[1]), self._get_port(parts[3]))
            dest_addr4 = (self._get_ip4(parts[2]), self._get_port(parts[4]))
            return ProxyProtocolResultIPv4(source_addr4, dest_addr4)
        elif family_string == b'TCP6':
            source_addr6 = (self._get_ip6(parts[1]), self._get_port(parts[3]))
            dest_addr6 = (self._get_ip6(parts[2]), self._get_port(parts[4]))
            return ProxyProtocolResultIPv6(source_addr6, dest_addr6)
        else:
            raise ProxyProtocolSyntaxError(
                'Invalid proxy protocol address family')

    def _get_ip4(self, ip_string: bytes) -> IPv4Address:
        return IPv4Address(ip_string.decode('ascii'))

    def _get_ip6(self, ip_string: bytes) -> IPv6Address:
        return IPv6Address(ip_string.decode('ascii'))

    def _get_port(self, port_string: bytes) -> int:
        port_num = int(port_string)
        if port_num < 0 or port_num > 65535:
            raise ValueError(port_num)
        return port_num

    def build(self, source: Address, dest: Address, *, family: AddressFamily,
              protocol: Optional[SocketKind] = None,
              ssl: Union[None, SSLSocket, SSLObject] = None,
              unique_id: Optional[bytes] = None,
              proxied: bool = True,
              dnsbl: Optional[str] = None) -> bytes:
        if not proxied:
            raise ValueError('proxied must be True in v1')
        family_b = self._build_family(family)
        if source is None or isinstance(source, str):
            source_ip: bytes = b''
            source_port: bytes = b''
        else:
            source_ip = source[0].encode('ascii')
            source_port = str(source[1]).encode('ascii')
        if dest is None or isinstance(dest, str):
            dest_ip: bytes = b''
            dest_port: bytes = b''
        else:
            dest_ip = dest[0].encode('ascii')
            dest_port = str(dest[1]).encode('ascii')
        return b'PROXY %b %b %b %b %b\r\n' % \
            (family_b, source_ip, dest_ip, source_port, dest_port)

    def _build_family(self, family: AddressFamily) -> bytes:
        if family == socket.AF_INET:
            return b'TCP4'
        elif family == socket.AF_INET6:
            return b'TCP6'
        elif family == socket.AF_UNSPEC:
            return b'UNKNOWN'
        else:
            raise KeyError(family)
