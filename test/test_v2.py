
import socket
import unittest
from ipaddress import IPv4Address, IPv6Address

from proxyprotocol import ProxyProtocolSyntaxError, \
    ProxyProtocolChecksumError, ProxyProtocolIncompleteError
from proxyprotocol.version import ProxyProtocolVersion
from proxyprotocol.result import ProxyResultLocal, ProxyResultUnknown, \
    ProxyResultIPv4, ProxyResultIPv6, ProxyResultUnix
from proxyprotocol.tlv import ProxyProtocolTLV, \
    ProxyProtocolSSLTLV, ProxyProtocolExtTLV
from proxyprotocol.v2 import ProxyProtocolV2Header, ProxyProtocolV2


class TestProxyProtocolV2(unittest.TestCase):

    def test_version(self) -> None:
        pp = ProxyProtocolVersion.get('V2')
        self.assertIsInstance(pp, ProxyProtocolV2)

    def test_unpack_incomplete(self) -> None:
        pp = ProxyProtocolV2()
        with self.assertRaises(ProxyProtocolIncompleteError) as raised:
            pp.unpack(b'')
        self.assertEqual(16, raised.exception.want_read.want_bytes)
        self.assertFalse(raised.exception.want_read.want_line)
        with self.assertRaises(ProxyProtocolIncompleteError) as raised:
            pp.unpack(b'\r\n\r\n\x00\r\nQUIT\n\x21\x21\xf0\xf0')
        self.assertEqual(61680, raised.exception.want_read.want_bytes)
        self.assertFalse(raised.exception.want_read.want_line)

    def test_unpack(self) -> None:
        pp = ProxyProtocolV2()
        res = pp.unpack(b'\r\n\r\n\x00\r\nQUIT\n\x21\x00\x00\x00')
        self.assertIsInstance(res, ProxyResultUnknown)

    def test_unpack_local(self) -> None:
        pp = ProxyProtocolV2()
        res = pp.unpack(b'\r\n\r\n\x00\r\nQUIT\n\x20\x00\x00\x07' +
                        b'\x03\x00\x04\xa9\xb8~\x8f')
        self.assertIsInstance(res, ProxyResultLocal)
        self.assertEqual(2847440527, res.tlv.crc32c)

    def test_unpack_checksum_error(self) -> None:
        pp = ProxyProtocolV2()
        with self.assertRaises(ProxyProtocolChecksumError) as raised:
            pp.unpack(b'\r\n\r\n\x00\r\nQUIT\n\x20\x00\x00\x07' +
                      b'\x03\x00\x04\xa9\xb8!\x8f')
        res = raised.exception.result
        self.assertIsInstance(res, ProxyResultLocal)
        self.assertEqual(2847416719, res.tlv.crc32c)

    def test_unpack_header(self) -> None:
        pp = ProxyProtocolV2()
        header = pp.unpack_header(b'\r\n\r\n\x00\r\nQUIT\n\x21\x21\xf0\xf0')
        self.assertIsInstance(header, ProxyProtocolV2Header)
        self.assertEqual('proxy', header.command)
        self.assertEqual(socket.AF_INET6, header.family)
        self.assertEqual(socket.SOCK_STREAM, header.protocol)
        self.assertEqual(61680, header.data_len)

    def test_unpack_header_bad(self) -> None:
        pp = ProxyProtocolV2()
        with self.assertRaises(ProxyProtocolSyntaxError):
            pp.unpack_header(b'bad')
        with self.assertRaises(ProxyProtocolSyntaxError):
            pp.unpack_header(b'\r\n\r\n\x00\r\nQUIT\n\x31\x21\xf0\xf0')

    def test_unpack_data_local(self) -> None:
        pp = ProxyProtocolV2()
        header = ProxyProtocolV2Header(command='local', family=None,
                                       protocol=None, data_len=0)
        res = pp.unpack_data(header, b'', b'')
        if not isinstance(res, ProxyResultLocal):
            self.fail('expected ProxyResultLocal instance')
        self.assertIsNone(res.source)
        self.assertIsNone(res.dest)
        self.assertEqual(socket.AF_UNSPEC, res.family)
        self.assertIsNone(res.protocol)

    def test_unpack_data_bad(self) -> None:
        pp = ProxyProtocolV2()
        header = ProxyProtocolV2Header(command='bad', family=None,
                                       protocol=None, data_len=0)
        with self.assertRaises(ProxyProtocolSyntaxError):
            pp.unpack_data(header, b'', b'')

    def test_unpack_data_unknown(self) -> None:
        pp = ProxyProtocolV2()
        header = ProxyProtocolV2Header(command='proxy', family=None,
                                       protocol=None, data_len=0)
        res = pp.unpack_data(header, b'', b'')
        if not isinstance(res, ProxyResultUnknown):
            self.fail('expected ProxyResultUnknown instance')
        self.assertIsNone(res.source)
        self.assertIsNone(res.dest)
        self.assertEqual(socket.AF_UNSPEC, res.family)
        self.assertIsNone(res.protocol)

    def test_unpack_data_inet(self) -> None:
        pp = ProxyProtocolV2()
        header = ProxyProtocolV2Header(command='proxy', family=socket.AF_INET,
                                       protocol=socket.SOCK_STREAM, data_len=0)
        res = pp.unpack_data(
            header, b'', b'\x00\x00\x00\x00\x7f\x00\x00\x01\x00\x00\x00\x19')
        if not isinstance(res, ProxyResultIPv4):
            self.fail('expected ProxyResult4 instance')
        self.assertEqual(socket.AF_INET, res.family)
        self.assertEqual(socket.SOCK_STREAM, res.protocol)
        self.assertIsInstance(res.source[0], IPv4Address)
        self.assertIsInstance(res.dest[0], IPv4Address)
        self.assertEqual('0.0.0.0', str(res.source[0]))
        self.assertEqual(0, res.source[1])
        self.assertEqual('127.0.0.1', str(res.dest[0]))
        self.assertEqual(25, res.dest[1])

    def test_unpack_data_inet6(self) -> None:
        pp = ProxyProtocolV2()
        header = ProxyProtocolV2Header(command='proxy', family=socket.AF_INET6,
                                       protocol=socket.SOCK_STREAM, data_len=0)
        res = pp.unpack_data(
            header, b'', (b'\x00'*15 + b'\x01') * 2 + b'\x00\x00\x00\x19')
        if not isinstance(res, ProxyResultIPv6):
            self.fail('expected ProxyResult6 instance')
        self.assertEqual(socket.AF_INET6, res.family)
        self.assertEqual(socket.SOCK_STREAM, res.protocol)
        self.assertIsInstance(res.source[0], IPv6Address)
        self.assertIsInstance(res.dest[0], IPv6Address)
        self.assertEqual('::1', str(res.source[0]))
        self.assertEqual(0, res.source[1])
        self.assertEqual('::1', str(res.dest[0]))
        self.assertEqual(25, res.dest[1])

    def test_unpack_data_unix(self) -> None:
        pp = ProxyProtocolV2()
        header = ProxyProtocolV2Header(command='proxy', family=socket.AF_UNIX,
                                       protocol=socket.SOCK_STREAM, data_len=0)
        res = pp.unpack_data(
            header, b'', b'abc' + b'\x00'*105 + b'defghi' + b'\x00'*102)
        if not isinstance(res, ProxyResultUnix):
            self.fail('expected ProxyResultUnix instance')
        self.assertEqual('abc', res.source)
        self.assertEqual('defghi', res.dest)
        self.assertEqual(socket.AF_UNIX, res.family)
        self.assertEqual(socket.SOCK_STREAM, res.protocol)

    def test_unpack_data_tlv(self) -> None:
        pp = ProxyProtocolV2()
        header = ProxyProtocolV2Header(command='proxy', family=socket.AF_INET,
                                       protocol=socket.SOCK_STREAM, data_len=0)
        res = pp.unpack_data(
            header, b'', b'\x00' * 12 + b'\x02\x00\x04test')
        if not isinstance(res, ProxyResultIPv4):
            self.fail('expected ProxyResult4 instance')
        self.assertIsNotNone(res.tlv)
        self.assertEqual('test', res.tlv.authority)

    def test_pack_tcp4(self) -> None:
        pp = ProxyProtocolV2()
        result = ProxyResultIPv4(
            (IPv4Address('0.0.0.0'), 0),
            (IPv4Address('127.0.0.1'), 25),
            protocol=socket.SOCK_STREAM)
        header = pp.pack(result)
        self.assertEqual(b'\r\n\r\n\x00\r\nQUIT\n\x21\x11\x00\x13' +
                         b'\x00\x00\x00\x00\x7f\x00\x00\x01\x00\x00\x00\x19' +
                         b'\x03\x00\x04%\xc9\x11r', header)

    def test_pack_tcp6(self) -> None:
        pp = ProxyProtocolV2()
        result = ProxyResultIPv6(
            (IPv6Address('::1'), 0),
            (IPv6Address('::1'), 25),
            protocol=socket.SOCK_STREAM)
        header = pp.pack(result)
        self.assertEqual(b'\r\n\r\n\x00\r\nQUIT\n!!\x00+' +
                         (b'\x00'*15 + b'\x01') * 2 + b'\x00\x00\x00\x19' +
                         b'\x03\x00\x04p\x86\x92\xe9', header)

    def test_pack_unix(self) -> None:
        pp = ProxyProtocolV2()
        result = ProxyResultUnix('abc', 'defghi',
                                 protocol=socket.SOCK_STREAM)
        header = pp.pack(result)
        self.assertEqual(b'\r\n\r\n\x00\r\nQUIT\n\x21\x31\x00\xdf' +
                         b'abc' + b'\x00'*105 + b'defghi' + b'\x00'*102 +
                         b'\x03\x00\x04W\x8a\x8e\xb4', header)

    def test_pack_unknown(self) -> None:
        pp = ProxyProtocolV2()
        result = ProxyResultUnknown()
        header = pp.pack(result)
        self.assertEqual(b'\r\n\r\n\x00\r\nQUIT\n!\x00\x00\x07'
                         b'\x03\x00\x04>\xc9\x89N', header)

    def test_pack_not_proxied(self) -> None:
        pp = ProxyProtocolV2()
        result = ProxyResultLocal()
        header = pp.pack(result)
        self.assertEqual(b'\r\n\r\n\x00\r\nQUIT\n\x20\x00\x00\x07' +
                         b'\x03\x00\x04\xa9\xb8~\x8f', header)

    def test_pack_tlv(self) -> None:
        pp = ProxyProtocolV2()
        tlv = ProxyProtocolTLV(
            auto_crc32c=True,
            unique_id=b'connection_id',
            ssl=ProxyProtocolSSLTLV(has_ssl=True,
                                    cipher='cipher_name',
                                    version='ssl_version'),
            ext=ProxyProtocolExtTLV(compression='compression_name',
                                    secret_bits=123,
                                    dnsbl='dnsbl_result'))
        result = ProxyResultUnknown(tlv=tlv)
        header = pp.pack(result)
        self.assertEqual(b'\r\n\r\n\x00\r\nQUIT\n!\x00\x00m' +
                         b'\x03\x00\x04\x16\xb5"\x85\x04\x00/\x88\x1by' +
                         b'\xc1\xce\x96\x85\xb0\x01\x00\x10compression_name' +
                         b'\x02\x00\x02\x00{\x04\x00\x0cdnsbl_result\x05\x00' +
                         b'\rconnection_id \x00!\x01\x00\x00\x00\x01!\x00' +
                         b'\x0bssl_version#\x00\x0bcipher_name',
                         header)
