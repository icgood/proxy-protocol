
import unittest
from ipaddress import IPv4Address, IPv6Address

from proxyprotocol.base import ProxyProtocolError
from proxyprotocol.result import ProxyProtocolResultUnknown, \
    ProxyProtocolResult4, ProxyProtocolResult6
from proxyprotocol.v1 import ProxyProtocolV1


class TestProxyProtocolV1(unittest.TestCase):

    def test_parse_line_unknown(self) -> None:
        pp = ProxyProtocolV1()
        res = pp.parse_line(b'PROXY UNKNOWN ...\r\n')
        self.assertIsInstance(res, ProxyProtocolResultUnknown)

    def test_parse_line_bad(self) -> None:
        pp = ProxyProtocolV1()
        with self.assertRaises(ProxyProtocolError):
            pp.parse_line(b'PROXY one two three four\r\n')
        with self.assertRaises(ProxyProtocolError):
            pp.parse_line(b'PROXY one two three four five\r\n')
        with self.assertRaises(ProxyProtocolError):
            pp.parse_line(b'PROXY one two three four five six\r\n')

    def test_parse_line_tcp4(self) -> None:
        pp = ProxyProtocolV1()
        res = pp.parse_line(b'PROXY TCP4 1.2.3.4 5.6.7.8 10 20\r\n')
        if not isinstance(res, ProxyProtocolResult4):
            self.fail('expected ProxyProtocolResult4 instance')
        self.assertIsInstance(res.source[0], IPv4Address)
        self.assertIsInstance(res.dest[0], IPv4Address)
        self.assertEqual('1.2.3.4', str(res.source[0]))
        self.assertEqual(10, res.source[1])
        self.assertEqual('5.6.7.8', str(res.dest[0]))
        self.assertEqual(20, res.dest[1])

    def test_parse_line_tcp4_bad(self) -> None:
        pp = ProxyProtocolV1()
        with self.assertRaises(ProxyProtocolError):
            pp.parse_line(b'PROXY TCP4 abcd efgh 10 20\r\n')
        with self.assertRaises(ProxyProtocolError):
            pp.parse_line(b'PROXY TCP4 1.2.3.4 5.6.7.8 ab cd\r\n')
        with self.assertRaises(ProxyProtocolError):
            pp.parse_line(b'PROXY TCP4 1.2.3.4 5.6.7.8 -1 -1\r\n')

    def test_parse_line_tcp6(self) -> None:
        pp = ProxyProtocolV1()
        res = pp.parse_line(b'PROXY TCP6 ::1 ::2 10 20\r\n')
        if not isinstance(res, ProxyProtocolResult6):
            self.fail('expected ProxyProtocolResult6 instance')
        self.assertIsInstance(res.source[0], IPv6Address)
        self.assertIsInstance(res.dest[0], IPv6Address)
        self.assertEqual('::1', str(res.source[0]))
        self.assertEqual(10, res.source[1])
        self.assertEqual('::2', str(res.dest[0]))
        self.assertEqual(20, res.dest[1])

    def test_parse_line_tcp6_bad(self) -> None:
        pp = ProxyProtocolV1()
        with self.assertRaises(ProxyProtocolError):
            pp.parse_line(b'PROXY TCP6 abcd efgh 10 20\r\n')
        with self.assertRaises(ProxyProtocolError):
            pp.parse_line(b'PROXY TCP6 ::1 ::2 ab cd\r\n')
        with self.assertRaises(ProxyProtocolError):
            pp.parse_line(b'PROXY TCP6 ::1 ::2 -1 -1\r\n')
