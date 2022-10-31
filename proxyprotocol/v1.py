
from __future__ import annotations

import socket
from ipaddress import IPv4Address, IPv6Address
from socket import AddressFamily
from typing import Sequence

from . import ProxyProtocolWantRead, ProxyProtocol, ProxyProtocolSyntaxError, \
    ProxyProtocolIncompleteError
from .result import is_ipv4, is_ipv6, ProxyResult, ProxyResultUnknown, \
    ProxyResultIPv4, ProxyResultIPv6


class ProxyProtocolV1(ProxyProtocol):
    """Implements version 1 of the PROXY protocol."""

    __slots__: Sequence[str] = []

    def is_valid(self, signature: bytes) -> bool:
        return signature[0:6] == b'PROXY '

    def unpack(self, data: bytes) -> ProxyResult:
        if data[-1:] != b'\n':
            want_read = ProxyProtocolWantRead(want_line=True)
            raise ProxyProtocolIncompleteError(want_read)
        return self.unpack_line(data)

    def unpack_line(self, data: bytes) -> ProxyResult:
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
            return ProxyResultUnknown()
        elif len(parts) != 5:
            raise ProxyProtocolSyntaxError(
                'Invalid proxy protocol header format')
        elif family_string == b'TCP4':
            source_addr4 = (self._get_ip4(parts[1]), self._get_port(parts[3]))
            dest_addr4 = (self._get_ip4(parts[2]), self._get_port(parts[4]))
            return ProxyResultIPv4(source_addr4, dest_addr4)
        elif family_string == b'TCP6':
            source_addr6 = (self._get_ip6(parts[1]), self._get_port(parts[3]))
            dest_addr6 = (self._get_ip6(parts[2]), self._get_port(parts[4]))
            return ProxyResultIPv6(source_addr6, dest_addr6)
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

    def pack(self, result: ProxyResult) -> bytes:
        if not result.proxied:
            raise ValueError('proxied must be True in v1')
        family_b = self._pack_family(result.family)
        if is_ipv4(result) or is_ipv6(result):
            source_ip: bytes = result.peername[0].encode('ascii')
            source_port: bytes = str(result.peername[1]).encode('ascii')
            dest_ip: bytes = result.sockname[0].encode('ascii')
            dest_port: bytes = str(result.sockname[1]).encode('ascii')
        else:
            source_ip = b''
            source_port = b''
            dest_ip = b''
            dest_port = b''
        return b'PROXY %b %b %b %b %b\r\n' % \
            (family_b, source_ip, dest_ip, source_port, dest_port)

    def _pack_family(self, family: AddressFamily) -> bytes:
        if family == socket.AF_INET:
            return b'TCP4'
        elif family == socket.AF_INET6:
            return b'TCP6'
        elif family == socket.AF_UNSPEC:
            return b'UNKNOWN'
        else:
            raise KeyError(family)
