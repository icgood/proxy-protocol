
import socket
import unittest
from asyncio import BaseTransport
from ipaddress import IPv4Address, IPv6Address
from ssl import SSLContext
from typing import Any, Dict
from unittest.mock import MagicMock

from proxyprotocol.result import ProxyProtocolResultLocal, \
    ProxyProtocolResultUnknown, ProxyProtocolResultIPv6
from proxyprotocol.sock import SocketInfo


class TestSocketInfo(unittest.TestCase):

    def setUp(self) -> None:
        self.extra: Dict[str, Any] = {}
        self.transport = MagicMock(BaseTransport)

        def get_extra_info(name: str, default: Any = None) -> Any:
            return self.extra.get(name, default)
        self.transport.get_extra_info.side_effect = get_extra_info

    def test_socket(self) -> None:
        info = SocketInfo(self.transport)
        self.extra['socket'] = sock = MagicMock(socket.socket)
        self.assertEqual(sock, info.socket)

    def test_sockname_socket(self) -> None:
        result = ProxyProtocolResultLocal()
        info = SocketInfo(self.transport, result)
        self.extra['sockname'] = ('::1', 10, 0, 0)
        self.assertEqual(('::1', 10, 0, 0), info.sockname)

    def test_sockname_override(self) -> None:
        result = ProxyProtocolResultIPv6((IPv6Address('::1'), 10),
                                         (IPv6Address('::FFFF:1.2.3.4'), 20))
        info = SocketInfo(self.transport, result)
        self.assertEqual(('::1', 10, 0, 0), info.sockname)

    def test_sockname_unknown(self) -> None:
        result = ProxyProtocolResultUnknown()
        info = SocketInfo(self.transport, result)
        self.assertIsNone(info.sockname)

    def test_sockname_ip(self) -> None:
        info = SocketInfo(self.transport)
        self.extra['socket'] = sock = MagicMock(socket.socket)
        sock.family = socket.AF_UNSPEC
        self.assertIsNone(info.sockname_ip)

    def test_sockname_port(self) -> None:
        info = SocketInfo(self.transport)
        self.extra['socket'] = sock = MagicMock(socket.socket)
        sock.family = socket.AF_UNSPEC
        self.assertIsNone(info.sockname_port)

    def test_peername_socket(self) -> None:
        result = ProxyProtocolResultLocal()
        info = SocketInfo(self.transport, result)
        self.extra['peername'] = ('::FFFF:1.2.3.4', 20, 0, 0)
        self.assertEqual(('::FFFF:1.2.3.4', 20, 0, 0), info.peername)

    def test_peername_override(self) -> None:
        result = ProxyProtocolResultIPv6((IPv6Address('::1'), 10),
                                         (IPv6Address('::FFFF:1.2.3.4'), 20))
        info = SocketInfo(self.transport, result)
        self.assertEqual(('::ffff:102:304', 20, 0, 0), info.peername)

    def test_peername_unknown(self) -> None:
        result = ProxyProtocolResultUnknown()
        info = SocketInfo(self.transport, result)
        self.assertIsNone(info.peername)

    def test_peername_ip(self) -> None:
        result = ProxyProtocolResultIPv6((IPv6Address('::1'), 10),
                                         (IPv6Address('::FFFF:1.2.3.4'), 20))
        info = SocketInfo(self.transport, result)
        self.assertEqual(IPv4Address('1.2.3.4'), info.peername_ip)

    def test_peername_port(self) -> None:
        result = ProxyProtocolResultIPv6((IPv6Address('::1'), 10),
                                         (IPv6Address('::FFFF:1.2.3.4'), 20))
        info = SocketInfo(self.transport, result)
        self.assertEqual(20, info.peername_port)

    def test_family_socket(self) -> None:
        result = ProxyProtocolResultLocal()
        info = SocketInfo(self.transport, result)
        self.extra['socket'] = sock = MagicMock(socket.socket)
        sock.family = socket.AF_INET6
        self.assertEqual(socket.AF_INET6, info.family)

    def test_family_override(self) -> None:
        result = ProxyProtocolResultIPv6((IPv6Address('::1'), 10),
                                         (IPv6Address('::FFFF:1.2.3.4'), 20))
        info = SocketInfo(self.transport, result)
        self.assertEqual(socket.AF_INET6, info.family)

    def test_protocol_socket(self) -> None:
        result = ProxyProtocolResultLocal()
        info = SocketInfo(self.transport, result)
        self.extra['socket'] = sock = MagicMock(socket.socket)
        sock.proto = socket.SOCK_STREAM
        self.assertEqual(socket.SOCK_STREAM, info.protocol)

    def test_protocol_override(self) -> None:
        result = ProxyProtocolResultIPv6((IPv6Address('::1'), 10),
                                         (IPv6Address('::FFFF:1.2.3.4'), 20),
                                         protocol=socket.SOCK_STREAM)
        info = SocketInfo(self.transport, result)
        self.assertEqual(socket.SOCK_STREAM, info.protocol)

    def test_peercert(self) -> None:
        info = SocketInfo(self.transport)
        self.extra['peercert'] = peercert = {'issuer': 'test'}
        self.assertEqual(peercert, info.peercert)

    def test_ssl_context(self) -> None:
        info = SocketInfo(self.transport)
        self.extra['sslcontext'] = sslctx = SSLContext()
        self.assertEqual(sslctx, info.ssl_context)

    def test_from_localhost_unix(self) -> None:
        result = ProxyProtocolResultLocal()
        info = SocketInfo(self.transport, result)
        self.extra['socket'] = sock = MagicMock(socket.socket)
        sock.family = socket.AF_UNIX
        self.assertTrue(info.from_localhost)

    def test_from_localhost_unknown(self) -> None:
        result = ProxyProtocolResultUnknown()
        info = SocketInfo(self.transport, result)
        self.assertFalse(info.from_localhost)

    def test_from_localhost_false(self) -> None:
        result = ProxyProtocolResultIPv6((IPv6Address('::1'), 10),
                                         (IPv6Address('::FFFF:1.2.3.4'), 20))
        info = SocketInfo(self.transport, result)
        self.assertFalse(info.from_localhost)

    def test_from_localhost_true(self) -> None:
        result = ProxyProtocolResultIPv6((IPv6Address('::FFFF:1.2.3.4'), 10),
                                         (IPv6Address('::1'), 20))
        info = SocketInfo(self.transport, result)
        self.assertTrue(info.from_localhost)

    def test_getattr(self) -> None:
        info = SocketInfo(self.transport)
        self.extra['foo'] = foo = ('foo', 'bar')
        self.assertEqual(foo, info.foo)

    def test_getattr_invalid(self) -> None:
        info = SocketInfo(self.transport)
        with self.assertRaises(AttributeError):
            info.foo

    def test_str(self) -> None:
        info = SocketInfo(self.transport)
        self.extra['sockname'] = 'source'
        self.extra['peername'] = 'dest'
        self.assertEqual("<SocketInfo peername='dest' sockname='source' "
                         "peercert=None>", str(info))
