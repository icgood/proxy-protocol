
import socket
import struct
from ipaddress import IPv4Address, IPv6Address
from socket import AddressFamily, SocketKind
from typing import cast, Optional, Tuple, Sequence
from typing_extensions import Final

from . import ProxyProtocolError, ProxyProtocolResult, ProxyProtocol
from .result import ProxyProtocolResultLocal, ProxyProtocolResultUnknown, \
    ProxyProtocolResultIPv4, ProxyProtocolResultIPv6, ProxyProtocolResultUnix
from .typing import Address, StreamReaderProtocol

__all__ = ['ProxyProtocolV2Header', 'ProxyProtocolV2']


class ProxyProtocolV2Header:
    """The 16-byte header that precedes the source and destination address data
    in PROXY protocol v2.

    """

    __slots__ = ['command', 'family', 'protocol', 'addr_len']

    def __init__(self, command: Optional[str], family: Optional[AddressFamily],
                 protocol: Optional[SocketKind], addr_len: int) -> None:
        super().__init__()
        self.command: Final = command
        self.family: Final = family
        self.protocol: Final = protocol
        self.addr_len: Final = addr_len


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

    def is_valid(self, signature: bytes) -> bool:
        return signature.startswith(b'\r\n\r\n\x00\r\nQ')

    async def read(self, reader: StreamReaderProtocol, *,
                   signature: bytes = b'') \
            -> ProxyProtocolResult:  # pragma: no cover
        read_len = 16 - len(signature)
        try:
            header_b = signature + await reader.readexactly(read_len)
        except (EOFError, ConnectionResetError) as exc:
            return ProxyProtocolResultUnknown(exc)
        header = self.parse_header(header_b)
        try:
            addresses_b = await reader.readexactly(header.addr_len)
        except (EOFError, ConnectionResetError) as exc:
            return ProxyProtocolResultUnknown(exc)
        return self.parse_addresses(addresses_b, header)

    def parse_header(self, header: bytes) -> ProxyProtocolV2Header:
        """Parse the PROXY protocol v2 header.

        Args:
            header: The header bytestring to parse.

        """
        if not header.startswith(b'\r\n\r\n\x00\r\nQUIT\n'):
            raise ProxyProtocolError('Invalid proxy protocol v2 signature')
        elif header[12] & 0xf0 != 0x20:
            raise ProxyProtocolError('Invalid proxy protocol version')
        byte_12, byte_13, addr_len = struct.unpack('!BBH', header[12:16])
        command = self._commands_l.get(byte_12 & 0x0f)
        family = self._families_l.get(byte_13 & 0xf0)
        protocol = self._protocols_l.get(byte_13 & 0x0f)
        return ProxyProtocolV2Header(command=command, family=family,
                                     protocol=protocol, addr_len=addr_len)

    def parse_addresses(self, addresses: bytes,
                        header: ProxyProtocolV2Header) -> ProxyProtocolResult:
        """Parse the address information read from the stream after the v2
        header.

        Args:
            addresses: The addresses bytestring to parse.
            sock: The underlying socket for the connection.
            header: The version 2 header info.

        """
        if header.command == 'local':
            return ProxyProtocolResultLocal()
        elif header.command != 'proxy':
            raise ProxyProtocolError('Invalid proxy protocol command')
        if header.family == socket.AF_INET:
            source_ip, dest_ip, source_port, dest_port = \
                struct.unpack('!4s4sHH', addresses)
            source_addr4 = (IPv4Address(source_ip), source_port)
            dest_addr4 = (IPv4Address(dest_ip), dest_port)
            return ProxyProtocolResultIPv4(source_addr4, dest_addr4,
                                           protocol=header.protocol)
        elif header.family == socket.AF_INET6:
            source_ip, dest_ip, source_port, dest_port = \
                struct.unpack('!16s16sHH', addresses)
            source_addr6 = (IPv6Address(source_ip), source_port)
            dest_addr6 = (IPv6Address(dest_ip), dest_port)
            return ProxyProtocolResultIPv6(source_addr6, dest_addr6,
                                           protocol=header.protocol)
        elif header.family == socket.AF_UNIX:
            source_addr_b, dest_addr_b = struct.unpack('!108s108s', addresses)
            source_addru = source_addr_b.rstrip(b'\x00').decode('ascii')
            dest_addru = dest_addr_b.rstrip(b'\x00').decode('ascii')
            return ProxyProtocolResultUnix(source_addru, dest_addru,
                                           protocol=header.protocol)
        else:
            return ProxyProtocolResultUnknown()

    def build(self, source: Address, dest: Address, *, family: AddressFamily,
              protocol: Optional[SocketKind] = None,
              proxied: bool = True) -> bytes:
        addresses = self.build_addresses(source, dest, family=family)
        header = self.build_header(addresses, family=family, protocol=protocol,
                                   proxied=proxied)
        return header + addresses

    def build_header(self, addresses: bytes, *,
                     family: AddressFamily,
                     protocol: Optional[SocketKind] = None,
                     proxied: bool = True) -> bytes:
        """Builds the 16-byte block that begins every PROXY protocol v2 header.

        Args:
            addresses: The addresses block, as returned by
                :meth:`.build_addresses`.
            family: The original socket family.
            protocol: The original socket protocol.
            proxied: True if the connection should not be considered proxied.

        """
        byte_12 = 0x20 + self._commands_r['proxy' if proxied else 'local']
        byte_13 = self._families_r[family] + self._protocols_r[protocol]
        return b'\r\n\r\n\x00\r\nQUIT\n%b' % \
            struct.pack('!BBH', byte_12, byte_13, len(addresses))

    def build_addresses(self, source: Address, dest: Address, *,
                        family: AddressFamily) -> bytes:
        """Builds the block of address data is contained in a PROXY protocol v2
        header.

        Args:
            source: The original source address of the connection.
            dest: The original destination address of the connection.
            family: The original socket family.

        """
        if family == socket.AF_INET:
            source = cast(Tuple[str, int], source)
            dest = cast(Tuple[str, int], dest)
            source_ip = IPv4Address(source[0]).packed
            source_port = source[1]
            dest_ip = IPv4Address(dest[0]).packed
            dest_port = dest[1]
            return struct.pack('!4s4sHH', source_ip, dest_ip,
                               source_port, dest_port)
        elif family == socket.AF_INET6:
            source = cast(Tuple[str, int, int, int], source)
            dest = cast(Tuple[str, int, int, int], dest)
            source_ip = IPv6Address(source[0]).packed
            source_port = source[1]
            dest_ip = IPv6Address(dest[0]).packed
            dest_port = dest[1]
            return struct.pack('!16s16sHH', source_ip, dest_ip,
                               source_port, dest_port)
        elif family == socket.AF_UNIX:
            source = cast(str, source)
            dest = cast(str, dest)
            source_b = source.encode('ascii')
            dest_b = dest.encode('ascii')
            return struct.pack('!108s108s', source_b, dest_b)
        else:
            return b''
