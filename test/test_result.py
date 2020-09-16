
import socket
import unittest
from ipaddress import IPv4Address, IPv6Address

from proxyprotocol.result import ProxyProtocolResultLocal, \
    ProxyProtocolResultUnknown, ProxyProtocolResultIPv4, \
    ProxyProtocolResultIPv6, ProxyProtocolResultUnix


class TestProxyProtocolResult(unittest.TestCase):

    def test_result_local(self) -> None:
        res = ProxyProtocolResultLocal()
        self.assertIsNone(res.source)
        self.assertIsNone(res.dest)
        self.assertEqual(socket.AF_UNSPEC, res.family)
        self.assertIsNone(res.protocol)
        self.assertFalse(res.proxied)
        self.assertIsNone(res._sockname)
        self.assertIsNone(res._peername)
        self.assertEqual('ProxyProtocolResultLocal()', str(res))
        self.assertEqual(0, len(res.tlv))

    def test_result_unknown(self) -> None:
        exc = RuntimeError('test')
        res = ProxyProtocolResultUnknown(exc)
        self.assertEqual(exc, res.exception)
        self.assertIsNone(res.source)
        self.assertIsNone(res.dest)
        self.assertEqual(socket.AF_UNSPEC, res.family)
        self.assertIsNone(res.protocol)
        self.assertTrue(res.proxied)
        self.assertIsNone(res._sockname)
        self.assertIsNone(res._peername)
        self.assertEqual('ProxyProtocolResultUnknown()', str(res))
        self.assertEqual(0, len(res.tlv))

    def test_result_ipv4(self) -> None:
        res = ProxyProtocolResultIPv4((IPv4Address('1.2.3.4'), 10),
                                      (IPv4Address('5.6.7.8'), 20))
        self.assertEqual((IPv4Address('1.2.3.4'), 10), res.source)
        self.assertEqual((IPv4Address('5.6.7.8'), 20), res.dest)
        self.assertEqual(socket.AF_INET, res.family)
        self.assertIsNone(res.protocol)
        self.assertTrue(res.proxied)
        self.assertEqual(('1.2.3.4', 10), res._peername)
        self.assertEqual(('5.6.7.8', 20), res._sockname)
        self.assertEqual(
            "ProxyProtocolResultIPv4((IPv4Address('1.2.3.4'), 10), "
            "(IPv4Address('5.6.7.8'), 20))", str(res))
        self.assertEqual(0, len(res.tlv))

    def test_result_ipv4_protocol(self) -> None:
        res = ProxyProtocolResultIPv4((IPv4Address('1.2.3.4'), 10),
                                      (IPv4Address('5.6.7.8'), 20),
                                      protocol=socket.SOCK_STREAM)
        self.assertEqual(socket.SOCK_STREAM, res.protocol)
        self.assertEqual(
            "ProxyProtocolResultIPv4((IPv4Address('1.2.3.4'), 10), "
            "(IPv4Address('5.6.7.8'), 20), protocol=socket.SOCK_STREAM)",
            str(res))

    def test_result_ipv6(self) -> None:
        res = ProxyProtocolResultIPv6((IPv6Address('::1'), 10),
                                      (IPv6Address('::2'), 20))
        self.assertEqual((IPv6Address('::1'), 10), res.source)
        self.assertEqual((IPv6Address('::2'), 20), res.dest)
        self.assertEqual(socket.AF_INET6, res.family)
        self.assertIsNone(res.protocol)
        self.assertTrue(res.proxied)
        self.assertEqual(('::1', 10, 0, 0), res._peername)
        self.assertEqual(('::2', 20, 0, 0), res._sockname)
        self.assertEqual(
            "ProxyProtocolResultIPv6((IPv6Address('::1'), 10), "
            "(IPv6Address('::2'), 20))", str(res))
        self.assertEqual(0, len(res.tlv))

    def test_result_ipv6_protocol(self) -> None:
        res = ProxyProtocolResultIPv6((IPv6Address('::1'), 10),
                                      (IPv6Address('::2'), 20),
                                      protocol=socket.SOCK_STREAM)
        self.assertEqual(socket.SOCK_STREAM, res.protocol)
        self.assertEqual(
            "ProxyProtocolResultIPv6((IPv6Address('::1'), 10), "
            "(IPv6Address('::2'), 20), protocol=socket.SOCK_STREAM)",
            str(res))

    def test_result_unix(self) -> None:
        res = ProxyProtocolResultUnix('/source.sock', '/dest.sock')
        self.assertEqual('/source.sock', res.source)
        self.assertEqual('/dest.sock', res.dest)
        self.assertEqual(socket.AF_UNIX, res.family)
        self.assertIsNone(res.protocol)
        self.assertTrue(res.proxied)
        self.assertEqual('/source.sock', res._peername)
        self.assertEqual('/dest.sock', res._sockname)
        self.assertEqual(
            "ProxyProtocolResultUnix('/source.sock', "
            "'/dest.sock')", str(res))
        self.assertEqual(0, len(res.tlv))

    def test_result_unix_protocol(self) -> None:
        res = ProxyProtocolResultUnix('/source.sock', '/dest.sock',
                                      protocol=socket.SOCK_STREAM)
        self.assertEqual(socket.SOCK_STREAM, res.protocol)
        self.assertEqual(
            "ProxyProtocolResultUnix('/source.sock', "
            "'/dest.sock', protocol=socket.SOCK_STREAM)",
            str(res))
