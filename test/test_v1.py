
import socket
import unittest
from ipaddress import IPv4Address, IPv6Address

from proxyprotocol import ProxyProtocolSyntaxError, \
    ProxyProtocolIncompleteError
from proxyprotocol.version import ProxyProtocolVersion
from proxyprotocol.result import ProxyProtocolResultUnknown, \
    ProxyProtocolResultIPv4, ProxyProtocolResultIPv6
from proxyprotocol.v1 import ProxyProtocolV1


class TestProxyProtocolV1(unittest.TestCase):

    def test_version(self) -> None:
        pp = ProxyProtocolVersion.get('V1')
        self.assertIsInstance(pp, ProxyProtocolV1)

    def test_parse_incomplete(self) -> None:
        pp = ProxyProtocolV1()
        with self.assertRaises(ProxyProtocolIncompleteError) as raised:
            pp.parse(b'PROXY')
        self.assertIsNone(raised.exception.want_read.want_bytes)
        self.assertTrue(raised.exception.want_read.want_line)

    def test_parse(self) -> None:
        pp = ProxyProtocolV1()
        res = pp.parse(b'PROXY UNKNOWN ...\r\n')
        self.assertIsInstance(res, ProxyProtocolResultUnknown)

    def test_parse_line_bad(self) -> None:
        pp = ProxyProtocolV1()
        with self.assertRaises(ProxyProtocolSyntaxError):
            pp.parse_line(b'bad\r\n')
        with self.assertRaises(ProxyProtocolSyntaxError):
            pp.parse_line(b'PROXY \n')
        with self.assertRaises(ProxyProtocolSyntaxError):
            pp.parse_line(b'PROXY one two three four\r\n')
        with self.assertRaises(ProxyProtocolSyntaxError):
            pp.parse_line(b'PROXY one two three four five\r\n')
        with self.assertRaises(ProxyProtocolSyntaxError):
            pp.parse_line(b'PROXY one two three four five six\r\n')

    def test_parse_line_tcp4(self) -> None:
        pp = ProxyProtocolV1()
        res = pp.parse_line(b'PROXY TCP4 1.2.3.4 5.6.7.8 10 20\r\n')
        if not isinstance(res, ProxyProtocolResultIPv4):
            self.fail('expected ProxyProtocolResult4 instance')
        self.assertIsInstance(res.source[0], IPv4Address)
        self.assertIsInstance(res.dest[0], IPv4Address)
        self.assertEqual('1.2.3.4', str(res.source[0]))
        self.assertEqual(10, res.source[1])
        self.assertEqual('5.6.7.8', str(res.dest[0]))
        self.assertEqual(20, res.dest[1])

    def test_parse_line_tcp4_bad(self) -> None:
        pp = ProxyProtocolV1()
        with self.assertRaises(ValueError):
            pp.parse_line(b'PROXY TCP4 abcd efgh 10 20\r\n')
        with self.assertRaises(ValueError):
            pp.parse_line(b'PROXY TCP4 1.2.3.4 5.6.7.8 ab cd\r\n')
        with self.assertRaises(ValueError):
            pp.parse_line(b'PROXY TCP4 1.2.3.4 5.6.7.8 -1 -1\r\n')

    def test_parse_line_tcp6(self) -> None:
        pp = ProxyProtocolV1()
        res = pp.parse_line(b'PROXY TCP6 ::1 ::2 10 20\r\n')
        if not isinstance(res, ProxyProtocolResultIPv6):
            self.fail('expected ProxyProtocolResult6 instance')
        self.assertIsInstance(res.source[0], IPv6Address)
        self.assertIsInstance(res.dest[0], IPv6Address)
        self.assertEqual('::1', str(res.source[0]))
        self.assertEqual(10, res.source[1])
        self.assertEqual('::2', str(res.dest[0]))
        self.assertEqual(20, res.dest[1])

    def test_parse_line_tcp6_bad(self) -> None:
        pp = ProxyProtocolV1()
        with self.assertRaises(ValueError):
            pp.parse_line(b'PROXY TCP6 abcd efgh 10 20\r\n')
        with self.assertRaises(ValueError):
            pp.parse_line(b'PROXY TCP6 ::1 ::2 ab cd\r\n')
        with self.assertRaises(ValueError):
            pp.parse_line(b'PROXY TCP6 ::1 ::2 -1 -1\r\n')

    def test_build_tcp4(self) -> None:
        pp = ProxyProtocolV1()
        header = pp.build(('1.2.3.4', 10), ('5.6.7.8', 20),
                          family=socket.AF_INET)
        self.assertEqual(b'PROXY TCP4 1.2.3.4 5.6.7.8 10 20\r\n', header)

    def test_build_tcp6(self) -> None:
        pp = ProxyProtocolV1()
        header = pp.build(('::1', 10, 0, 0), ('::2', 20, 0, 0),
                          family=socket.AF_INET6)
        self.assertEqual(b'PROXY TCP6 ::1 ::2 10 20\r\n', header)

    def test_build_unix(self) -> None:
        pp = ProxyProtocolV1()
        with self.assertRaises(KeyError):
            pp.build('source', 'dest', family=socket.AF_UNIX)

    def test_build_unknown(self) -> None:
        pp = ProxyProtocolV1()
        header = pp.build(None, None, family=socket.AF_UNSPEC)
        self.assertEqual(b'PROXY UNKNOWN    \r\n', header)

    def test_build_not_proxied(self) -> None:
        pp = ProxyProtocolV1()
        with self.assertRaises(ValueError):
            pp.build(None, None, family=socket.AF_UNSPEC, proxied=False)
