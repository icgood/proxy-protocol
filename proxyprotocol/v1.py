
from ipaddress import IPv4Address, IPv6Address
from typing import Sequence

from . import ProxyProtocolError, ProxyProtocolResult, ProxyProtocol
from .result import ProxyProtocolResultUnknown, ProxyProtocolResultIPv4, \
    ProxyProtocolResultIPv6
from .typing import StreamReaderProtocol


class ProxyProtocolV1(ProxyProtocol):
    """Implements version 1 of the PROXY protocol."""

    __slots__: Sequence[str] = []

    def is_valid(self, signature: bytes) -> bool:
        return signature.startswith(b'PROXY ')

    async def read(self, reader: StreamReaderProtocol, *,
                   signature: bytes = b'') \
            -> ProxyProtocolResult:  # pragma: no cover
        try:
            line = signature + await reader.readuntil(b'\r\n')
        except (EOFError, ConnectionResetError) as exc:
            return ProxyProtocolResultUnknown(exc)
        return self.parse_line(line)

    def parse_line(self, line: bytes) -> ProxyProtocolResult:
        """Parse the PROXY protocol v1 header line.

        Args:
            line: The line bytestring to parse.

        """
        if not line.startswith(b'PROXY ') or not line.endswith(b'\r\n'):
            raise ProxyProtocolError('Invalid proxy protocol v1 signature')
        line = line[6:-2]
        parts = line.split(b' ')
        family_string = parts[0]
        if family_string == b'UNKNOWN':
            return ProxyProtocolResultUnknown()
        elif len(parts) != 5:
            raise ProxyProtocolError('Invalid proxy protocol header format')
        elif family_string == b'TCP4':
            source_addr4 = (self._get_ip4(parts[1]), self._get_port(parts[3]))
            dest_addr4 = (self._get_ip4(parts[2]), self._get_port(parts[4]))
            return ProxyProtocolResultIPv4(source_addr4, dest_addr4)
        elif family_string == b'TCP6':
            source_addr6 = (self._get_ip6(parts[1]), self._get_port(parts[3]))
            dest_addr6 = (self._get_ip6(parts[2]), self._get_port(parts[4]))
            return ProxyProtocolResultIPv6(source_addr6, dest_addr6)
        else:
            raise ProxyProtocolError('Invalid proxy protocol address family')

    def _get_ip4(self, ip_string: bytes) -> IPv4Address:
        return IPv4Address(ip_string.decode('ascii'))

    def _get_ip6(self, ip_string: bytes) -> IPv6Address:
        return IPv6Address(ip_string.decode('ascii'))

    def _get_port(self, port_string: bytes) -> int:
        port_num = int(port_string)
        if port_num < 0 or port_num > 65535:
            raise ValueError(port_num)
        return port_num
