
from __future__ import annotations

import socket
from ipaddress import IPv4Address, IPv6Address
from socket import AddressFamily, SocketKind
from struct import Struct
from typing import Optional, Sequence
from typing_extensions import Final

from . import ProxyProtocolWantRead, ProxyProtocol, ProxyProtocolSyntaxError, \
    ProxyProtocolChecksumError, ProxyProtocolIncompleteError
from .result import is_ipv4, is_ipv6, is_unix, ProxyResult, ProxyResultLocal, \
    ProxyResultUnknown, ProxyResultIPv4, ProxyResultIPv6, ProxyResultUnix
from .tlv import ProxyProtocolTLV

__all__ = ['ProxyProtocolV2Header', 'ProxyProtocolV2']


class ProxyProtocolV2Header:
    """The 16-byte header that precedes the source and destination address data
    in PROXY protocol v2.

    """

    __slots__ = ['command', 'family', 'protocol', 'data_len']

    def __init__(self, command: Optional[str], family: Optional[AddressFamily],
                 protocol: Optional[SocketKind], data_len: int) -> None:
        super().__init__()
        self.command: Final = command
        self.family: Final = family
        self.protocol: Final = protocol
        self.data_len: Final = data_len


class ProxyProtocolV2(ProxyProtocol):
    """Implements version 2 of the PROXY protocol."""

    __slots__: Sequence[str] = []

    _commands = [(0x00, 'local'),
                 (0x01, 'proxy')]
    _families = [(0x00, socket.AF_UNSPEC),
                 (0x10, socket.AF_INET),
                 (0x20, socket.AF_INET6),
                 (0x30, socket.AF_UNIX)]
    _protocols = [(0x00, None),
                  (0x01, socket.SOCK_STREAM),
                  (0x02, socket.SOCK_DGRAM)]
    _commands_l = {left: right for left, right in _commands}
    _commands_r = {right: left for left, right in _commands}
    _families_l = {left: right for left, right in _families}
    _families_r = {right: left for left, right in _families}
    _protocols_l = {left: right for left, right in _protocols}
    _protocols_r = {right: left for left, right in _protocols}

    _header_format = Struct('!BBH')
    _ipv4_format = Struct('!4s4sHH')
    _ipv6_format = Struct('!16s16sHH')
    _unix_format = Struct('!108s108s')
    _tlv_format = Struct('!BH')

    def is_valid(self, signature: bytes) -> bool:
        return signature[0:8] == b'\r\n\r\n\x00\r\nQ'

    def unpack(self, data: bytes) -> ProxyResult:
        if len(data) < 16:
            want_read = ProxyProtocolWantRead(16 - len(data))
            raise ProxyProtocolIncompleteError(want_read)
        header_data, data = data[0:16], data[16:]
        header = self.unpack_header(header_data)
        if len(data) < header.data_len:
            want_read = ProxyProtocolWantRead(header.data_len - len(data))
            raise ProxyProtocolIncompleteError(want_read)
        return self.unpack_data(header, header_data, data)

    def unpack_header(self, header_data: bytes) -> ProxyProtocolV2Header:
        """Parse the PROXY protocol v2 header.

        Args:
            header: The header bytestring to parse.

        """
        if header_data[0:12] != b'\r\n\r\n\x00\r\nQUIT\n':
            raise ProxyProtocolSyntaxError(
                'Invalid proxy protocol v2 signature')
        elif header_data[12] & 0xf0 != 0x20:
            raise ProxyProtocolSyntaxError('Invalid proxy protocol version')
        byte_12, byte_13, data_len = self._header_format.unpack_from(
            header_data, 12)
        command = self._commands_l.get(byte_12 & 0x0f)
        family = self._families_l.get(byte_13 & 0xf0)
        protocol = self._protocols_l.get(byte_13 & 0x0f)
        return ProxyProtocolV2Header(command=command, family=family,
                                     protocol=protocol, data_len=data_len)

    def unpack_data(self, header: ProxyProtocolV2Header,
                    header_data: bytes, data: bytes) \
            -> ProxyResult:
        """Parse the address information read from the stream after the v2
        header.

        Args:
            header: The version 2 header info.
            header_data: The header bytestring.
            data: The addresses bytestring to parse.

        Raises:
            :exc:`~proxyprotocol.ProxyProtocolChecksumError`

        """
        if header.command not in ('local', 'proxy'):
            raise ProxyProtocolSyntaxError('Invalid proxy protocol command')
        result: ProxyResult
        if header.command == 'local':
            addr_data, tlv_data = b'', data
            tlv = ProxyProtocolTLV(tlv_data)
            result = ProxyResultLocal(tlv=tlv)
        elif header.family == socket.AF_INET:
            addr_len = self._ipv4_format.size
            addr_data, tlv_data = data[:addr_len], data[addr_len:]
            source_ip, dest_ip, source_port, dest_port = \
                self._ipv4_format.unpack(addr_data)
            source_addr4 = (IPv4Address(source_ip), source_port)
            dest_addr4 = (IPv4Address(dest_ip), dest_port)
            tlv = ProxyProtocolTLV(tlv_data)
            result = ProxyResultIPv4(source_addr4, dest_addr4,
                                     protocol=header.protocol, tlv=tlv)
        elif header.family == socket.AF_INET6:
            addr_len = self._ipv6_format.size
            addr_data, tlv_data = data[:addr_len], data[addr_len:]
            source_ip, dest_ip, source_port, dest_port = \
                self._ipv6_format.unpack(addr_data)
            source_addr6 = (IPv6Address(source_ip), source_port)
            dest_addr6 = (IPv6Address(dest_ip), dest_port)
            tlv = ProxyProtocolTLV(tlv_data)
            result = ProxyResultIPv6(source_addr6, dest_addr6,
                                     protocol=header.protocol, tlv=tlv)
        elif header.family == socket.AF_UNIX:
            addr_len = self._unix_format.size
            addr_data, tlv_data = data[:addr_len], data[addr_len:]
            source_addr_b, dest_addr_b = self._unix_format.unpack(addr_data)
            source_addru = source_addr_b.rstrip(b'\x00').decode('ascii')
            dest_addru = dest_addr_b.rstrip(b'\x00').decode('ascii')
            tlv = ProxyProtocolTLV(tlv_data)
            result = ProxyResultUnix(source_addru, dest_addru,
                                     protocol=header.protocol, tlv=tlv)
        else:
            return ProxyResultUnknown()
        if not tlv.verify_checksum(header_data, addr_data):
            raise ProxyProtocolChecksumError(result)
        return result

    def pack(self, result: ProxyResult) -> bytes:
        addresses = self._pack_addresses(result)
        tlv = ProxyProtocolTLV(init=result.tlv, crc32c=None, auto_crc32c=True)
        data_len = len(addresses) + tlv.size
        header = self._pack_header(data_len, result)
        tlv = tlv.with_checksum(header, addresses)
        return header + addresses + bytes(tlv)

    def _pack_header(self, data_len: int, result: ProxyResult) \
            -> bytes:
        command = 'proxy' if result.proxied else 'local'
        family = result.family
        protocol = result.protocol
        byte_12 = 0x20 + self._commands_r[command]
        byte_13 = self._families_r[family] + self._protocols_r[protocol]
        return b'\r\n\r\n\x00\r\nQUIT\n%b' % \
            self._header_format.pack(byte_12, byte_13, data_len)

    def _pack_addresses(self, result: ProxyResult) -> bytes:
        if is_ipv4(result):
            source_ip = result.source[0].packed
            source_port = result.source[1]
            dest_ip = result.dest[0].packed
            dest_port = result.dest[1]
            return self._ipv4_format.pack(source_ip, dest_ip,
                                          source_port, dest_port)
        elif is_ipv6(result):
            source_ip = result.source[0].packed
            source_port = result.source[1]
            dest_ip = result.dest[0].packed
            dest_port = result.dest[1]
            return self._ipv6_format.pack(source_ip, dest_ip,
                                          source_port, dest_port)
        elif is_unix(result):
            source_b = result.source.encode('ascii')
            dest_b = result.dest.encode('ascii')
            return self._unix_format.pack(source_b, dest_b)
        else:
            return b''
