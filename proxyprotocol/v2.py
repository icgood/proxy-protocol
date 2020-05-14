
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from socket import AddressFamily, SocketKind
from typing import Optional

from .base import ProxyProtocolError, DataReader, ProxyProtocol
from .result import ProxyProtocolResult, ProxyProtocolResultLocal, \
    ProxyProtocolResultUnknown, ProxyProtocolResult4, ProxyProtocolResult6, \
    ProxyProtocolResultUnix

__all__ = ['ProxyProtocolV2Header', 'ProxyProtocolV2']


@dataclass
class ProxyProtocolV2Header:
    """The 16-byte header that precedes the source and destination address data
    in PROXY protocol v2.

    """
    command: Optional[str]
    family: Optional[AddressFamily]
    protocol: Optional[SocketKind]
    addr_len: int


class ProxyProtocolV2(ProxyProtocol):
    """Implements version 2 of the PROXY protocol."""

    _commands = {0x00: 'local',
                 0x01: 'proxy'}
    _families = {0x10: socket.AF_INET,
                 0x20: socket.AF_INET6,
                 0x30: socket.AF_UNIX}
    _protocols = {0x01: socket.SOCK_STREAM,
                  0x02: socket.SOCK_DGRAM}

    async def read(self, reader: DataReader, *,
                   signature: bytes = b'') \
            -> ProxyProtocolResult:  # pragma: no cover
        header_b = signature + await reader.readexactly(16 - len(signature))
        header = self.parse_header(header_b)
        addresses_b = await reader.readexactly(header.addr_len)
        return self.parse_addresses(addresses_b, header)

    def parse_header(self, header: bytes) -> ProxyProtocolV2Header:
        """Parse the PROXY protocol v2 header.

        Args:
            header: The header bytestring to parse.

        """
        assert header[0:12] == b'\r\n\r\n\x00\r\nQUIT\n', \
            'Invalid proxy protocol v2 signature'
        if header[12] & 0xf0 != 0x20:
            raise ProxyProtocolError('Invalid proxy protocol version')
        command = self._commands.get(header[12] & 0x0f)
        family = self._families.get(header[13] & 0xf0)
        protocol = self._protocols.get(header[13] & 0x0f)
        addr_len: int = struct.unpack('!H', header[14:16])[0]
        return ProxyProtocolV2Header(command=command, family=family,
                                     protocol=protocol, addr_len=addr_len)

    def parse_addresses(self, addresses: bytes,
                        header: ProxyProtocolV2Header) \
            -> ProxyProtocolResult:
        """Parse the address information read from the stream after the v2
        header.

        Args:
            addresses: The addresses bytestring to parse.

        """
        if header.command == 'local':
            return ProxyProtocolResultLocal()
        elif header.command != 'proxy':
            raise ProxyProtocolError('Invalid proxy protocol command')
        if header.family == socket.AF_INET:
            src_ip, dst_ip, src_port, dst_port = \
                struct.unpack('!4s4sHH', addresses)
            src_addr4 = (IPv4Address(src_ip), src_port)
            dest_addr4 = (IPv4Address(dst_ip), dst_port)
            return ProxyProtocolResult4(source=src_addr4, dest=dest_addr4,
                                        protocol=header.protocol)
        elif header.family == socket.AF_INET6:
            src_ip, dst_ip, src_port, dst_port = \
                struct.unpack('!16s16sHH', addresses)
            src_addr6 = (IPv6Address(src_ip), src_port)
            dest_addr6 = (IPv6Address(dst_ip), dst_port)
            return ProxyProtocolResult6(source=src_addr6, dest=dest_addr6,
                                        protocol=header.protocol)
        elif header.family == socket.AF_UNIX:
            src_addr_b, dest_addr_b = struct.unpack('!108s108s', addresses)
            src_addru = src_addr_b.rstrip(b'\x00').decode('ascii')
            dest_addru = dest_addr_b.rstrip(b'\x00').decode('ascii')
            return ProxyProtocolResultUnix(source=src_addru, dest=dest_addru,
                                           protocol=header.protocol)
        else:
            return ProxyProtocolResultUnknown()
