
from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address, AddressValueError

from .base import ProxyProtocolError, DataReader, ProxyProtocol
from .result import ProxyProtocolResult, ProxyProtocolResultUnknown, \
    ProxyProtocolResult4, ProxyProtocolResult6


class ProxyProtocolV1(ProxyProtocol):
    """Implements version 1 of the PROXY protocol."""

    async def read(self, reader: DataReader, *,
                   signature: bytes = b'') \
            -> ProxyProtocolResult:  # pragma: no cover
        line = signature + await reader.readuntil(b'\r\n')
        return self.parse_line(line)

    def parse_line(self, line: bytes) -> ProxyProtocolResult:
        """Parse the PROXY protocol v1 header line.

        Args:
            line: The line bytestring to parse.

        """
        assert line.startswith(b'PROXY ') and line.endswith(b'\r\n'), \
            'Invalid proxy protocol v1 signature'
        line = line[6:-2]
        parts = line.split(b' ')
        family_string = parts[0]
        if family_string == b'UNKNOWN':
            return ProxyProtocolResultUnknown()
        elif len(parts) != 5:
            raise ProxyProtocolError('Invalid proxy protocol header format')
        elif family_string == b'TCP4':
            source_addr4 = (self._get_ip4(parts[1], 'source'),
                            self._get_port(parts[3], 'source'))
            dest_addr4 = (self._get_ip4(parts[2], 'destination'),
                          self._get_port(parts[4], 'destination'))
            return ProxyProtocolResult4(source=source_addr4, dest=dest_addr4)
        elif family_string == b'TCP6':
            source_addr6 = (self._get_ip6(parts[1], 'source'),
                            self._get_port(parts[3], 'source'))
            dest_addr6 = (self._get_ip6(parts[2], 'destination'),
                          self._get_port(parts[4], 'destination'))
            return ProxyProtocolResult6(source=source_addr6, dest=dest_addr6)
        else:
            raise ProxyProtocolError('Invalid proxy protocol address family')

    def _get_ip4(self, ip_string: bytes, which: str) -> IPv4Address:
        try:
            return IPv4Address(ip_string.decode('ascii'))
        except (UnicodeDecodeError, AddressValueError) as exc:
            msg = 'Invalid proxy protocol {0} IPv4 address'.format(which)
            raise ProxyProtocolError(msg) from exc

    def _get_ip6(self, ip_string: bytes, which: str) -> IPv6Address:
        try:
            return IPv6Address(ip_string.decode('ascii'))
        except (UnicodeDecodeError, AddressValueError) as exc:
            msg = 'Invalid proxy protocol {0} IPv6 address'.format(which)
            raise ProxyProtocolError(msg) from exc

    def _get_port(self, port_string: bytes, which: str) -> int:
        try:
            port_num = int(port_string)
        except ValueError as exc:
            msg = 'Invalid proxy protocol {0} port format'.format(which)
            raise ProxyProtocolError(msg) from exc
        if port_num < 0 or port_num > 65535:
            msg = 'Proxy protocol {0} port out of range'.format(which)
            raise ProxyProtocolError(msg)
        return port_num
