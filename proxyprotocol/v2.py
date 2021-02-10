
import socket
from ipaddress import IPv4Address, IPv6Address
from socket import AddressFamily, SocketKind
from ssl import SSLSocket, SSLObject
from struct import Struct
from typing import cast, Union, Optional, Tuple, Sequence
from typing_extensions import Final

from . import ProxyProtocolError, ProxyProtocolWantRead, \
    ProxyProtocolResult, ProxyProtocol
from .result import ProxyProtocolResultLocal, ProxyProtocolResultUnknown, \
    ProxyProtocolResultIPv4, ProxyProtocolResultIPv6, ProxyProtocolResultUnix
from .tlv import ProxyProtocolTLV, ProxyProtocolSSLTLV, ProxyProtocolExtTLV
from .typing import Address, PeerCert

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

    def parse(self, data: bytes) -> ProxyProtocolResult:
        if len(data) < 16:
            raise ProxyProtocolWantRead(16 - len(data))
        header = self.parse_header(data[0:16])
        if len(data) < 16 + header.data_len:
            raise ProxyProtocolWantRead((16 + header.data_len) - len(data))
        return self.parse_data(header, data[16:])

    def parse_header(self, header: bytes) -> ProxyProtocolV2Header:
        """Parse the PROXY protocol v2 header.

        Args:
            header: The header bytestring to parse.

        """
        if header[0:12] != b'\r\n\r\n\x00\r\nQUIT\n':
            raise ProxyProtocolError('Invalid proxy protocol v2 signature')
        elif header[12] & 0xf0 != 0x20:
            raise ProxyProtocolError('Invalid proxy protocol version')
        byte_12, byte_13, data_len = self._header_format.unpack(header[12:16])
        command = self._commands_l.get(byte_12 & 0x0f)
        family = self._families_l.get(byte_13 & 0xf0)
        protocol = self._protocols_l.get(byte_13 & 0x0f)
        return ProxyProtocolV2Header(command=command, family=family,
                                     protocol=protocol, data_len=data_len)

    def parse_data(self, header: ProxyProtocolV2Header, data: bytes) \
            -> ProxyProtocolResult:
        """Parse the address information read from the stream after the v2
        header.

        Args:
            addresses: The addresses bytestring to parse.
            header: The version 2 header info.

        """
        if header.command == 'local':
            return ProxyProtocolResultLocal()
        elif header.command != 'proxy':
            raise ProxyProtocolError('Invalid proxy protocol command')
        if header.family == socket.AF_INET:
            addr_len = self._ipv4_format.size
            addr_b, tlv_b = data[:addr_len], data[addr_len:]
            source_ip, dest_ip, source_port, dest_port = \
                self._ipv4_format.unpack(addr_b)
            source_addr4 = (IPv4Address(source_ip), source_port)
            dest_addr4 = (IPv4Address(dest_ip), dest_port)
            tlv = ProxyProtocolTLV(tlv_b)
            return ProxyProtocolResultIPv4(source_addr4, dest_addr4,
                                           protocol=header.protocol, tlv=tlv)
        elif header.family == socket.AF_INET6:
            addr_len = self._ipv6_format.size
            addr_b, tlv_b = data[:addr_len], data[addr_len:]
            source_ip, dest_ip, source_port, dest_port = \
                self._ipv6_format.unpack(addr_b)
            source_addr6 = (IPv6Address(source_ip), source_port)
            dest_addr6 = (IPv6Address(dest_ip), dest_port)
            tlv = ProxyProtocolTLV(tlv_b)
            return ProxyProtocolResultIPv6(source_addr6, dest_addr6,
                                           protocol=header.protocol, tlv=tlv)
        elif header.family == socket.AF_UNIX:
            addr_len = self._unix_format.size
            addr_b, tlv_b = data[:addr_len], data[addr_len:]
            source_addr_b, dest_addr_b = self._unix_format.unpack(addr_b)
            source_addru = source_addr_b.rstrip(b'\x00').decode('ascii')
            dest_addru = dest_addr_b.rstrip(b'\x00').decode('ascii')
            tlv = ProxyProtocolTLV(tlv_b)
            return ProxyProtocolResultUnix(source_addru, dest_addru,
                                           protocol=header.protocol, tlv=tlv)
        else:
            return ProxyProtocolResultUnknown()

    def build(self, source: Address, dest: Address, *, family: AddressFamily,
              protocol: Optional[SocketKind] = None,
              ssl: Union[None, SSLSocket, SSLObject] = None,
              unique_id: Optional[bytes] = None,
              proxied: bool = True) -> bytes:
        addresses = self.build_addresses(source, dest, family=family)
        tlv = self.build_tlv(ssl, unique_id)
        data_len = len(addresses) + len(tlv)
        header = self.build_header(data_len, family=family, protocol=protocol,
                                   proxied=proxied)
        return header + addresses + tlv

    def build_header(self, data_len: int, *,
                     family: AddressFamily,
                     protocol: Optional[SocketKind] = None,
                     proxied: bool = True) -> bytes:
        """Builds the 16-byte block that begins every PROXY protocol v2 header.

        Args:
            data_len: The length of the data (addresses + TLV).
            family: The original socket family.
            protocol: The original socket protocol.
            proxied: True if the connection should be considered proxied.

        """
        byte_12 = 0x20 + self._commands_r['proxy' if proxied else 'local']
        byte_13 = self._families_r[family] + self._protocols_r[protocol]
        return b'\r\n\r\n\x00\r\nQUIT\n%b' % \
            self._header_format.pack(byte_12, byte_13, data_len)

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
            return self._ipv4_format.pack(source_ip, dest_ip,
                                          source_port, dest_port)
        elif family == socket.AF_INET6:
            source = cast(Tuple[str, int, int, int], source)
            dest = cast(Tuple[str, int, int, int], dest)
            source_ip = IPv6Address(source[0]).packed
            source_port = source[1]
            dest_ip = IPv6Address(dest[0]).packed
            dest_port = dest[1]
            return self._ipv6_format.pack(source_ip, dest_ip,
                                          source_port, dest_port)
        elif family == socket.AF_UNIX:
            source = cast(str, source)
            dest = cast(str, dest)
            source_b = source.encode('ascii')
            dest_b = dest.encode('ascii')
            return self._unix_format.pack(source_b, dest_b)
        else:
            return b''

    def build_tlv(self, ssl: Union[None, SSLSocket, SSLObject],
                  unique_id: Optional[bytes]) -> bytes:
        """Builds the TLV data written after the PROXY protocol v2 address
        data.

        Args:
            ssl: The SSL information for the connection.
            unique_id: The unique ID of the connection.

        """
        if ssl is not None:
            cipher, version, secret_bits = ssl.cipher() or (None, None, None)
            peercert: Optional[PeerCert] = ssl.getpeercert()
            ssl_tlv: Optional[ProxyProtocolSSLTLV] = ProxyProtocolSSLTLV(
                has_ssl=True, verify=True,
                has_cert_conn=(peercert is not None),
                cipher=cipher, version=version)
            ext_tlv: Optional[ProxyProtocolExtTLV] = ProxyProtocolExtTLV(
                compression=ssl.compression(),
                secret_bits=secret_bits, peercert=peercert)
        else:
            ssl_tlv = None
            ext_tlv = None
        tlv = ProxyProtocolTLV(unique_id=unique_id, ssl=ssl_tlv, ext=ext_tlv)
        return bytes(tlv)
