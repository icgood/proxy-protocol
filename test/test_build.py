
import socket
import unittest
from asyncio import BaseTransport
from ipaddress import IPv4Address, IPv6Address
from ssl import SSLSocket
from typing import Any, Dict
from unittest.mock import MagicMock

from proxyprotocol.build import build_socket_result, build_transport_result


class TestBuild(unittest.TestCase):

    def setUp(self) -> None:
        self.extra: Dict[str, Any] = {}
        self.transport = MagicMock(BaseTransport)

        def get_extra_info(name: str, default: Any = None) -> Any:
            return self.extra.get(name, default)
        self.transport.get_extra_info.side_effect = get_extra_info

    def test_ipv4_socket(self) -> None:
        sock = MagicMock(socket.socket)
        sock.family = socket.AF_INET
        sock.type = socket.SOCK_STREAM
        sock.getpeername.return_value = ('127.0.0.1', 10)
        sock.getsockname.return_value = ('1.2.3.4', 20)
        res = build_socket_result(sock, unique_id=b'uid', dnsbl='host')
        self.assertEqual((IPv4Address('127.0.0.1'), 10), res.source)
        self.assertEqual((IPv4Address('1.2.3.4'), 20), res.dest)
        self.assertEqual(socket.AF_INET, res.family)
        self.assertEqual(socket.SOCK_STREAM, res.protocol)
        self.assertEqual(b'uid', res.tlv.unique_id)
        self.assertEqual('host', res.tlv.ext.dnsbl)

    def test_ipv6_socket(self) -> None:
        sock = MagicMock(socket.socket)
        sock.family = socket.AF_INET6
        sock.type = socket.SOCK_STREAM
        sock.getpeername.return_value = ('::1', 10)
        sock.getsockname.return_value = ('::FFFF:1.2.3.4', 20)
        res = build_socket_result(sock, unique_id=b'uid', dnsbl='host')
        self.assertEqual((IPv6Address('::1'), 10), res.source)
        self.assertEqual((IPv6Address('::FFFF:1.2.3.4'), 20), res.dest)
        self.assertEqual(socket.AF_INET6, res.family)
        self.assertEqual(b'uid', res.tlv.unique_id)
        self.assertEqual('host', res.tlv.ext.dnsbl)

    def test_unix_socket(self) -> None:
        sock = MagicMock(socket.socket)
        sock.family = socket.AF_UNIX
        sock.type = socket.SOCK_STREAM
        sock.getpeername.return_value = '/source.sock'
        sock.getsockname.return_value = '/dest.sock'
        res = build_socket_result(sock, unique_id=b'uid')
        self.assertEqual('/source.sock', res.source)
        self.assertEqual('/dest.sock', res.dest)
        self.assertEqual(socket.AF_UNIX, res.family)
        self.assertEqual(b'uid', res.tlv.unique_id)

    def test_unknown(self) -> None:
        sock = MagicMock(socket.socket)
        sock.family = socket.AF_UNSPEC
        sock.type = socket.SOCK_STREAM
        sock.getpeername.return_value = None
        sock.getsockname.return_value = None
        res = build_socket_result(sock)
        self.assertIsNone(res.source)
        self.assertIsNone(res.dest)
        self.assertEqual(socket.AF_UNSPEC, res.family)

    def test_ssl_socket(self) -> None:
        sock = MagicMock(SSLSocket)
        sock.family = socket.AF_INET6
        sock.type = socket.SOCK_STREAM
        sock.getpeername.return_value = ('::1', 10)
        sock.getsockname.return_value = ('::FFFF:1.2.3.4', 20)
        sock.cipher.return_value = None
        sock.compression.return_value = None
        sock.getpeercert.return_value = None
        res = build_socket_result(sock)
        self.assertEqual((IPv6Address('::1'), 10), res.source)
        self.assertEqual((IPv6Address('::FFFF:1.2.3.4'), 20), res.dest)
        self.assertEqual(socket.AF_INET6, res.family)
        self.assertTrue(res.tlv.ssl.has_ssl)

    def test_transport(self) -> None:
        self.extra['socket'] = sock = MagicMock(socket.socket)
        sock.family = socket.AF_INET
        sock.type = socket.SOCK_STREAM
        self.extra['peername'] = ('127.0.0.1', 10)
        self.extra['sockname'] = ('1.2.3.4', 20)
        self.extra['ssl_object'] = None
        res = build_transport_result(self.transport)
        self.assertEqual((IPv4Address('127.0.0.1'), 10), res.source)
        self.assertEqual((IPv4Address('1.2.3.4'), 20), res.dest)
