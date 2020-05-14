
import socket
import unittest
from ipaddress import IPv4Address, IPv6Address

from proxyprotocol.base import ProxyProtocolError
from proxyprotocol.result import ProxyProtocolResultLocal, \
    ProxyProtocolResultUnknown, ProxyProtocolResult4, ProxyProtocolResult6, \
    ProxyProtocolResultUnix
from proxyprotocol.v2 import ProxyProtocolV2Header, ProxyProtocolV2


class TestProxyProtocolV2(unittest.TestCase):

    def test_parse_header(self) -> None:
        pp = ProxyProtocolV2()
        header = pp.parse_header(b'\r\n\r\n\x00\r\nQUIT\n\x21\x21\xf0\xf0')
        self.assertIsInstance(header, ProxyProtocolV2Header)
        self.assertEqual('proxy', header.command)
        self.assertEqual(socket.AF_INET6, header.family)
        self.assertEqual(socket.SOCK_STREAM, header.protocol)
        self.assertEqual(61680, header.addr_len)

    def test_parse_header_bad(self) -> None:
        pp = ProxyProtocolV2()
        with self.assertRaises(AssertionError):
            pp.parse_header(b'bad')
        with self.assertRaises(ProxyProtocolError):
            pp.parse_header(b'\r\n\r\n\x00\r\nQUIT\n\x31\x21\xf0\xf0')

    def test_parse_addresses_local(self) -> None:
        pp = ProxyProtocolV2()
        header = ProxyProtocolV2Header(command='local', family=None,
                                       protocol=None, addr_len=0)
        res = pp.parse_addresses(b'', header)
        if not isinstance(res, ProxyProtocolResultLocal):
            self.fail('expected ProxyProtocolResultLocal instance')
        self.assertEqual(socket.AF_UNSPEC, res.family)
        self.assertIsNone(res.protocol)
        self.assertTrue(res.is_local)
        self.assertFalse(res.is_unknown)

    def test_parse_addresses_bad(self) -> None:
        pp = ProxyProtocolV2()
        header = ProxyProtocolV2Header(command='bad', family=None,
                                       protocol=None, addr_len=0)
        with self.assertRaises(ProxyProtocolError):
            pp.parse_addresses(b'', header)

    def test_parse_addresses_unknown(self) -> None:
        pp = ProxyProtocolV2()
        header = ProxyProtocolV2Header(command='proxy', family=None,
                                       protocol=None, addr_len=0)
        res = pp.parse_addresses(b'', header)
        if not isinstance(res, ProxyProtocolResultUnknown):
            self.fail('expected ProxyProtocolResultUnknown instance')
        self.assertEqual(socket.AF_UNSPEC, res.family)
        self.assertIsNone(res.protocol)
        self.assertFalse(res.is_local)
        self.assertTrue(res.is_unknown)

    def test_parse_addresses_inet(self) -> None:
        pp = ProxyProtocolV2()
        header = ProxyProtocolV2Header(command='proxy', family=socket.AF_INET,
                                       protocol=socket.SOCK_STREAM, addr_len=0)
        res = pp.parse_addresses(
            b'\x00\x00\x00\x00\x7f\x00\x00\x01\x00\x00\x00\x19', header)
        if not isinstance(res, ProxyProtocolResult4):
            self.fail('expected ProxyProtocolResult4 instance')
        self.assertEqual(socket.AF_INET, res.family)
        self.assertEqual(socket.SOCK_STREAM, res.protocol)
        self.assertFalse(res.is_local)
        self.assertFalse(res.is_unknown)
        self.assertIsInstance(res.source[0], IPv4Address)
        self.assertIsInstance(res.dest[0], IPv4Address)
        self.assertEqual('0.0.0.0', str(res.source[0]))
        self.assertEqual(0, res.source[1])
        self.assertEqual('127.0.0.1', str(res.dest[0]))
        self.assertEqual(25, res.dest[1])

    def test_parse_addresses_inet6(self) -> None:
        pp = ProxyProtocolV2()
        header = ProxyProtocolV2Header(command='proxy', family=socket.AF_INET6,
                                       protocol=socket.SOCK_STREAM, addr_len=0)
        res = pp.parse_addresses(
            (b'\x00'*15 + b'\x01') * 2 + b'\x00\x00\x00\x19', header)
        if not isinstance(res, ProxyProtocolResult6):
            self.fail('expected ProxyProtocolResult6 instance')
        self.assertEqual(socket.AF_INET6, res.family)
        self.assertEqual(socket.SOCK_STREAM, res.protocol)
        self.assertFalse(res.is_local)
        self.assertFalse(res.is_unknown)
        self.assertIsInstance(res.source[0], IPv6Address)
        self.assertIsInstance(res.dest[0], IPv6Address)
        self.assertEqual('::1', str(res.source[0]))
        self.assertEqual(0, res.source[1])
        self.assertEqual('::1', str(res.dest[0]))
        self.assertEqual(25, res.dest[1])

    def test_parse_addresses_unix(self) -> None:
        pp = ProxyProtocolV2()
        header = ProxyProtocolV2Header(command='proxy', family=socket.AF_UNIX,
                                       protocol=socket.SOCK_STREAM, addr_len=0)
        res = pp.parse_addresses(
            b'abc' + b'\x00'*105 + b'defghi' + b'\x00'*102, header)
        if not isinstance(res, ProxyProtocolResultUnix):
            self.fail('expected ProxyProtocolResultUnix instance')
        self.assertEqual(socket.AF_UNIX, res.family)
        self.assertEqual(socket.SOCK_STREAM, res.protocol)
        self.assertFalse(res.is_local)
        self.assertFalse(res.is_unknown)
        self.assertEqual('abc', res.source)
        self.assertEqual('defghi', res.dest)
