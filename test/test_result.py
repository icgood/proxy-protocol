
import socket
import unittest
from ipaddress import IPv4Address, IPv6Address

from proxyprotocol.result import is_local, is_unknown, \
    is_ipv4, is_ipv6, is_unix, ProxyResultLocal, ProxyResultUnknown, \
    ProxyResultIPv4, ProxyResultIPv6, ProxyResultUnix


class TestProxyResult(unittest.TestCase):

    def test_result_local(self) -> None:
        res = ProxyResultLocal()
        self.assertTrue(is_local(res))
        self.assertIsNone(res.source)
        self.assertIsNone(res.dest)
        self.assertEqual(socket.AF_UNSPEC, res.family)
        self.assertIsNone(res.protocol)
        self.assertFalse(res.proxied)
        self.assertIsNone(res.peername)
        self.assertIsNone(res.sockname)
        self.assertEqual('ProxyResultLocal()', repr(res))
        self.assertEqual(0, len(res.tlv))

    def test_result_unknown(self) -> None:
        exc = RuntimeError('test')
        res = ProxyResultUnknown(exc)
        self.assertTrue(is_unknown(res))
        self.assertEqual(exc, res.exception)
        self.assertIsNone(res.source)
        self.assertIsNone(res.dest)
        self.assertEqual(socket.AF_UNSPEC, res.family)
        self.assertIsNone(res.protocol)
        self.assertTrue(res.proxied)
        self.assertIsNone(res.peername)
        self.assertIsNone(res.sockname)
        self.assertEqual("ProxyResultUnknown(RuntimeError('test'))",
                         repr(res))
        self.assertEqual(0, len(res.tlv))

    def test_result_ipv4(self) -> None:
        res = ProxyResultIPv4((IPv4Address('1.2.3.4'), 10),
                              (IPv4Address('5.6.7.8'), 20))
        self.assertTrue(is_ipv4(res))
        self.assertEqual((IPv4Address('1.2.3.4'), 10), res.source)
        self.assertEqual((IPv4Address('5.6.7.8'), 20), res.dest)
        self.assertEqual(socket.AF_INET, res.family)
        self.assertIsNone(res.protocol)
        self.assertTrue(res.proxied)
        self.assertEqual(('1.2.3.4', 10), res.peername)
        self.assertEqual(('5.6.7.8', 20), res.sockname)
        self.assertEqual(
            "ProxyResultIPv4((IPv4Address('1.2.3.4'), 10), "
            "(IPv4Address('5.6.7.8'), 20))", repr(res))
        self.assertEqual(0, len(res.tlv))

    def test_result_ipv4_protocol(self) -> None:
        res = ProxyResultIPv4((IPv4Address('1.2.3.4'), 10),
                              (IPv4Address('5.6.7.8'), 20),
                              protocol=socket.SOCK_STREAM)
        self.assertEqual(socket.SOCK_STREAM, res.protocol)
        self.assertEqual(
            "ProxyResultIPv4((IPv4Address('1.2.3.4'), 10), "
            "(IPv4Address('5.6.7.8'), 20), protocol=socket.SOCK_STREAM)",
            repr(res))

    def test_result_ipv6(self) -> None:
        res = ProxyResultIPv6((IPv6Address('::1'), 10),
                              (IPv6Address('::2'), 20))
        self.assertTrue(is_ipv6(res))
        self.assertEqual((IPv6Address('::1'), 10), res.source)
        self.assertEqual((IPv6Address('::2'), 20), res.dest)
        self.assertEqual(socket.AF_INET6, res.family)
        self.assertIsNone(res.protocol)
        self.assertTrue(res.proxied)
        self.assertEqual(('::1', 10, 0, 0), res.peername)
        self.assertEqual(('::2', 20, 0, 0), res.sockname)
        self.assertEqual(
            "ProxyResultIPv6((IPv6Address('::1'), 10), "
            "(IPv6Address('::2'), 20))", repr(res))
        self.assertEqual(0, len(res.tlv))

    def test_result_ipv6_protocol(self) -> None:
        res = ProxyResultIPv6((IPv6Address('::1'), 10),
                              (IPv6Address('::2'), 20),
                              protocol=socket.SOCK_STREAM)
        self.assertEqual(socket.SOCK_STREAM, res.protocol)
        self.assertEqual(
            "ProxyResultIPv6((IPv6Address('::1'), 10), "
            "(IPv6Address('::2'), 20), protocol=socket.SOCK_STREAM)",
            repr(res))

    def test_result_unix(self) -> None:
        res = ProxyResultUnix('/source.sock', '/dest.sock')
        self.assertTrue(is_unix(res))
        self.assertEqual('/source.sock', res.source)
        self.assertEqual('/dest.sock', res.dest)
        self.assertEqual(socket.AF_UNIX, res.family)
        self.assertIsNone(res.protocol)
        self.assertTrue(res.proxied)
        self.assertEqual('/source.sock', res.peername)
        self.assertEqual('/dest.sock', res.sockname)
        self.assertEqual("ProxyResultUnix('/source.sock', '/dest.sock')",
                         repr(res))
        self.assertEqual(0, len(res.tlv))

    def test_result_unix_protocol(self) -> None:
        res = ProxyResultUnix('/source.sock', '/dest.sock',
                              protocol=socket.SOCK_STREAM)
        self.assertEqual(socket.SOCK_STREAM, res.protocol)
        self.assertEqual(
            "ProxyResultUnix('/source.sock', "
            "'/dest.sock', protocol=socket.SOCK_STREAM)",
            repr(res))
