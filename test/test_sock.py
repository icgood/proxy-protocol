
import socket
import unittest
from asyncio import BaseTransport
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Dict
from unittest.mock import MagicMock

from proxyprotocol.result import ProxyProtocolResultLocal, \
    ProxyProtocolResultUnknown, ProxyProtocolResultIPv6
from proxyprotocol.sock import SocketInfo
from proxyprotocol.tlv import ProxyProtocolTLV, ProxyProtocolSSLTLV, \
    ProxyProtocolExtTLV


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

    def test_peername_socket(self) -> None:
        result = ProxyProtocolResultLocal()
        info = SocketInfo(self.transport, result)
        self.extra['peername'] = ('::1', 10, 0, 0)
        self.assertEqual(('::1', 10, 0, 0), info.peername)

    def test_peername_override(self) -> None:
        result = ProxyProtocolResultIPv6((IPv6Address('::1'), 10),
                                         (IPv6Address('::FFFF:1.2.3.4'), 20))
        info = SocketInfo(self.transport, result)
        self.assertEqual(('::1', 10, 0, 0), info.peername)

    def test_peername_unknown(self) -> None:
        result = ProxyProtocolResultUnknown()
        info = SocketInfo(self.transport, result)
        self.assertIsNone(info.peername)

    def test_peername_ip(self) -> None:
        info = SocketInfo(self.transport)
        self.extra['socket'] = sock = MagicMock(socket.socket)
        sock.family = socket.AF_UNSPEC
        self.assertIsNone(info.peername_ip)

    def test_peername_port(self) -> None:
        info = SocketInfo(self.transport)
        self.extra['socket'] = sock = MagicMock(socket.socket)
        sock.family = socket.AF_UNSPEC
        self.assertIsNone(info.peername_port)

    def test_sockname_socket(self) -> None:
        result = ProxyProtocolResultLocal()
        info = SocketInfo(self.transport, result)
        self.extra['sockname'] = ('::FFFF:1.2.3.4', 20, 0, 0)
        self.assertEqual(('::FFFF:1.2.3.4', 20, 0, 0), info.sockname)

    def test_sockname_override(self) -> None:
        result = ProxyProtocolResultIPv6((IPv6Address('::1'), 10),
                                         (IPv6Address('::FFFF:1.2.3.4'), 20))
        info = SocketInfo(self.transport, result)
        self.assertEqual(('::ffff:102:304', 20, 0, 0), info.sockname)

    def test_sockname_unknown(self) -> None:
        result = ProxyProtocolResultUnknown()
        info = SocketInfo(self.transport, result)
        self.assertIsNone(info.sockname)

    def test_sockname_ip(self) -> None:
        result = ProxyProtocolResultIPv6((IPv6Address('::1'), 10),
                                         (IPv6Address('::FFFF:1.2.3.4'), 20))
        info = SocketInfo(self.transport, result)
        self.assertEqual(IPv4Address('1.2.3.4'), info.sockname_ip)

    def test_sockname_port(self) -> None:
        result = ProxyProtocolResultIPv6((IPv6Address('::1'), 10),
                                         (IPv6Address('::FFFF:1.2.3.4'), 20))
        info = SocketInfo(self.transport, result)
        self.assertEqual(20, info.sockname_port)

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
        sock.type = socket.SOCK_STREAM
        self.assertEqual(socket.SOCK_STREAM, info.protocol)

    def test_protocol_override(self) -> None:
        result = ProxyProtocolResultIPv6((IPv6Address('::1'), 10),
                                         (IPv6Address('::FFFF:1.2.3.4'), 20),
                                         protocol=socket.SOCK_STREAM)
        info = SocketInfo(self.transport, result)
        self.assertEqual(socket.SOCK_STREAM, info.protocol)

    def test_compression_socket(self) -> None:
        result = ProxyProtocolResultLocal()
        info = SocketInfo(self.transport, result)
        self.extra['compression'] = 'alg_name'
        self.assertEqual('alg_name', info.compression)

    def test_compression_override(self) -> None:
        tlv = ProxyProtocolTLV(ext=ProxyProtocolExtTLV(compression='alg_name'))
        result = ProxyProtocolResultIPv6((IPv6Address('::1'), 10),
                                         (IPv6Address('::FFFF:1.2.3.4'), 20),
                                         tlv=tlv)
        info = SocketInfo(self.transport, result)
        self.assertEqual('alg_name', info.compression)

    def test_cipher_socket(self) -> None:
        result = ProxyProtocolResultLocal()
        info = SocketInfo(self.transport, result)
        self.extra['cipher'] = ('cipher_name', 'ssl_version', 123)
        self.assertEqual(('cipher_name', 'ssl_version', 123), info.cipher)

    def test_cipher_override(self) -> None:
        tlv = ProxyProtocolTLV(ssl=ProxyProtocolSSLTLV(has_ssl=True,
                                                       cipher='cipher_name',
                                                       version='ssl_version'),
                               ext=ProxyProtocolExtTLV(secret_bits=123))
        result = ProxyProtocolResultIPv6((IPv6Address('::1'), 10),
                                         (IPv6Address('::FFFF:1.2.3.4'), 20),
                                         tlv=tlv)
        info = SocketInfo(self.transport, result)
        self.assertEqual(('cipher_name', 'ssl_version', 123), info.cipher)

    def test_cipher_override_none(self) -> None:
        tlv = ProxyProtocolTLV(ssl=ProxyProtocolSSLTLV(has_ssl=False))
        result = ProxyProtocolResultIPv6((IPv6Address('::1'), 10),
                                         (IPv6Address('::FFFF:1.2.3.4'), 20),
                                         tlv=tlv)
        info = SocketInfo(self.transport, result)
        self.assertIsNone(info.cipher)

    def test_peercert_socket(self) -> None:
        result = ProxyProtocolResultLocal()
        info = SocketInfo(self.transport, result)
        self.extra['peercert'] = {'subject': 'test'}
        self.assertEqual({'subject': 'test'}, info.peercert)

    def test_peercert_override(self) -> None:
        tlv = ProxyProtocolTLV(ext=ProxyProtocolExtTLV(
            peercert={'subject': 'test'}))
        result = ProxyProtocolResultIPv6((IPv6Address('::1'), 10),
                                         (IPv6Address('::FFFF:1.2.3.4'), 20),
                                         tlv=tlv)
        info = SocketInfo(self.transport, result)
        self.assertEqual({'subject': 'test'}, info.peercert)

    def test_dnsbl_socket(self) -> None:
        result = ProxyProtocolResultLocal()
        info = SocketInfo(self.transport, result, dnsbl='abc')
        self.assertEqual('abc', info.dnsbl)

    def test_dnsbl_override(self) -> None:
        tlv = ProxyProtocolTLV(ext=ProxyProtocolExtTLV(dnsbl='test_dnsbl'))
        result = ProxyProtocolResultIPv6((IPv6Address('::1'), 10),
                                         (IPv6Address('::FFFF:1.2.3.4'), 20),
                                         tlv=tlv)
        info = SocketInfo(self.transport, result, dnsbl='abc')
        self.assertEqual('test_dnsbl', info.dnsbl)

    def test_unique_id_socket(self) -> None:
        result = ProxyProtocolResultLocal()
        info = SocketInfo(self.transport, result, unique_id=b'abc')
        self.assertEqual(b'abc', info.unique_id)

    def test_unique_id_override(self) -> None:
        tlv = ProxyProtocolTLV(unique_id=b'1234567890')
        result = ProxyProtocolResultIPv6((IPv6Address('::1'), 10),
                                         (IPv6Address('::FFFF:1.2.3.4'), 20),
                                         tlv=tlv)
        info = SocketInfo(self.transport, result, unique_id=b'abc')
        self.assertEqual(b'1234567890', info.unique_id)

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

    def test_from_localhost_true(self) -> None:
        result = ProxyProtocolResultIPv6((IPv6Address('::1'), 10),
                                         (IPv6Address('::FFFF:1.2.3.4'), 20))
        info = SocketInfo(self.transport, result)
        self.assertTrue(info.from_localhost)

    def test_from_localhost_false(self) -> None:
        result = ProxyProtocolResultIPv6((IPv6Address('::FFFF:1.2.3.4'), 10),
                                         (IPv6Address('::1'), 20))
        info = SocketInfo(self.transport, result)
        self.assertFalse(info.from_localhost)

    def test_str_unix(self) -> None:
        info = SocketInfo(self.transport)
        self.extra['sockname'] = 'source'
        self.extra['peername'] = 'dest'
        self.extra['socket'] = sock = MagicMock(socket.socket)
        sock.family = socket.AF_UNIX
        self.assertEqual("<SocketInfo peername='dest' sockname='source'>",
                         str(info))

    def test_str_ipv6(self) -> None:
        info = SocketInfo(self.transport)
        self.extra['sockname'] = ('::1', 10)
        self.extra['peername'] = ('::2', 20)
        self.extra['socket'] = sock = MagicMock(socket.socket)
        sock.family = socket.AF_INET6
        self.assertEqual("<SocketInfo peername='[::2]:20' "
                         "sockname='[::1]:10'>", str(info))

    def test_str_unknown(self) -> None:
        result = ProxyProtocolResultUnknown()
        info = SocketInfo(self.transport, result)
        self.assertEqual("<SocketInfo peername=None sockname=None "
                         "proxied=True>", str(info))
