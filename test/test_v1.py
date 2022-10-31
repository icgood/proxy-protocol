
import unittest
from ipaddress import IPv4Address, IPv6Address

from proxyprotocol import ProxyProtocolSyntaxError, \
    ProxyProtocolIncompleteError
from proxyprotocol.version import ProxyProtocolVersion
from proxyprotocol.result import ProxyResultLocal, ProxyResultUnknown, \
    ProxyResultIPv4, ProxyResultIPv6, ProxyResultUnix
from proxyprotocol.v1 import ProxyProtocolV1


class TestProxyProtocolV1(unittest.TestCase):

    def test_version(self) -> None:
        pp = ProxyProtocolVersion.get('V1')
        self.assertIsInstance(pp, ProxyProtocolV1)

    def test_unpack_incomplete(self) -> None:
        pp = ProxyProtocolV1()
        with self.assertRaises(ProxyProtocolIncompleteError) as raised:
            pp.unpack(b'PROXY')
        self.assertIsNone(raised.exception.want_read.want_bytes)
        self.assertTrue(raised.exception.want_read.want_line)

    def test_unpack(self) -> None:
        pp = ProxyProtocolV1()
        res = pp.unpack(b'PROXY UNKNOWN ...\r\n')
        self.assertIsInstance(res, ProxyResultUnknown)

    def test_unpack_line_bad(self) -> None:
        pp = ProxyProtocolV1()
        with self.assertRaises(ProxyProtocolSyntaxError):
            pp.unpack_line(b'bad\r\n')
        with self.assertRaises(ProxyProtocolSyntaxError):
            pp.unpack_line(b'PROXY \n')
        with self.assertRaises(ProxyProtocolSyntaxError):
            pp.unpack_line(b'PROXY one two three four\r\n')
        with self.assertRaises(ProxyProtocolSyntaxError):
            pp.unpack_line(b'PROXY one two three four five\r\n')
        with self.assertRaises(ProxyProtocolSyntaxError):
            pp.unpack_line(b'PROXY one two three four five six\r\n')

    def test_unpack_line_tcp4(self) -> None:
        pp = ProxyProtocolV1()
        res = pp.unpack_line(b'PROXY TCP4 1.2.3.4 5.6.7.8 10 20\r\n')
        if not isinstance(res, ProxyResultIPv4):
            self.fail('expected ProxyResult4 instance')
        self.assertIsInstance(res.source[0], IPv4Address)
        self.assertIsInstance(res.dest[0], IPv4Address)
        self.assertEqual('1.2.3.4', str(res.source[0]))
        self.assertEqual(10, res.source[1])
        self.assertEqual('5.6.7.8', str(res.dest[0]))
        self.assertEqual(20, res.dest[1])

    def test_unpack_line_tcp4_bad(self) -> None:
        pp = ProxyProtocolV1()
        with self.assertRaises(ValueError):
            pp.unpack_line(b'PROXY TCP4 abcd efgh 10 20\r\n')
        with self.assertRaises(ValueError):
            pp.unpack_line(b'PROXY TCP4 1.2.3.4 5.6.7.8 ab cd\r\n')
        with self.assertRaises(ValueError):
            pp.unpack_line(b'PROXY TCP4 1.2.3.4 5.6.7.8 -1 -1\r\n')

    def test_unpack_line_tcp6(self) -> None:
        pp = ProxyProtocolV1()
        res = pp.unpack_line(b'PROXY TCP6 ::1 ::2 10 20\r\n')
        if not isinstance(res, ProxyResultIPv6):
            self.fail('expected ProxyResult6 instance')
        self.assertIsInstance(res.source[0], IPv6Address)
        self.assertIsInstance(res.dest[0], IPv6Address)
        self.assertEqual('::1', str(res.source[0]))
        self.assertEqual(10, res.source[1])
        self.assertEqual('::2', str(res.dest[0]))
        self.assertEqual(20, res.dest[1])

    def test_unpack_line_tcp6_bad(self) -> None:
        pp = ProxyProtocolV1()
        with self.assertRaises(ValueError):
            pp.unpack_line(b'PROXY TCP6 abcd efgh 10 20\r\n')
        with self.assertRaises(ValueError):
            pp.unpack_line(b'PROXY TCP6 ::1 ::2 ab cd\r\n')
        with self.assertRaises(ValueError):
            pp.unpack_line(b'PROXY TCP6 ::1 ::2 -1 -1\r\n')

    def test_pack_tcp4(self) -> None:
        pp = ProxyProtocolV1()
        result = ProxyResultIPv4(
            (IPv4Address('1.2.3.4'), 10),
            (IPv4Address('5.6.7.8'), 20))
        header = pp.pack(result)
        self.assertEqual(b'PROXY TCP4 1.2.3.4 5.6.7.8 10 20\r\n', header)

    def test_pack_tcp6(self) -> None:
        pp = ProxyProtocolV1()
        result = ProxyResultIPv6(
            (IPv6Address('::1'), 10),
            (IPv6Address('::2'), 20))
        header = pp.pack(result)
        self.assertEqual(b'PROXY TCP6 ::1 ::2 10 20\r\n', header)

    def test_pack_unix(self) -> None:
        pp = ProxyProtocolV1()
        result = ProxyResultUnix('source', 'dest')
        with self.assertRaises(KeyError):
            pp.pack(result)

    def test_pack_unknown(self) -> None:
        pp = ProxyProtocolV1()
        header = pp.pack(ProxyResultUnknown())
        self.assertEqual(b'PROXY UNKNOWN    \r\n', header)

    def test_pack_not_proxied(self) -> None:
        pp = ProxyProtocolV1()
        result = ProxyResultLocal()
        with self.assertRaises(ValueError):
            pp.pack(result)
