
import json
import unittest
import zlib
from struct import pack

from proxyprotocol.tlv import Type, ExtType, TLV, ProxyProtocolTLV, \
    ProxyProtocolSSLTLV, ProxyProtocolExtTLV

peercert = zlib.compress(json.dumps({'test': 'peercert'}).encode('ascii'))
ssl_data = \
    pack('!BL', 0x05, 0) + \
    pack('!BH', Type.PP2_SUBTYPE_SSL_VERSION, 3) + b'1.0' + \
    pack('!BH', Type.PP2_SUBTYPE_SSL_CN, 11) + \
    b'test_\xe2\x93\x92\xe2\x93\x9d' + \
    pack('!BH', Type.PP2_SUBTYPE_SSL_CIPHER, 11) + b'test_cipher' + \
    pack('!BH', Type.PP2_SUBTYPE_SSL_SIG_ALG, 12) + b'test_sig_alg' + \
    pack('!BH', Type.PP2_SUBTYPE_SSL_KEY_ALG, 12) + b'test_key_alg'
ext_data = ProxyProtocolExtTLV.MAGIC_PREFIX + \
    pack('!BH', ExtType.PP2_TYPE_EXT_COMPRESSION, 16) + b'test_compression' + \
    pack('!BHH', ExtType.PP2_TYPE_EXT_SECRET_BITS, 2, 2048) + \
    pack('!BH', ExtType.PP2_TYPE_EXT_PEERCERT, len(peercert)) + peercert + \
    pack('!BH', ExtType.PP2_TYPE_EXT_DNSBL, 10) + b'test_dnsbl'
tlv_data = \
    pack('!BH', Type.PP2_TYPE_ALPN, 5) + b'test1' + \
    pack('!BH', Type.PP2_TYPE_AUTHORITY, 7) + b'test\xe2\x91\xa1' + \
    pack('!BHL', Type.PP2_TYPE_CRC32C, 4, 389237127) + \
    pack('!BHQQ', Type.PP2_TYPE_UNIQUE_ID, 16, 78781291827, 971627382) + \
    pack('!BH', Type.PP2_TYPE_NETNS, 5) + b'test3' + \
    pack('!BH', Type.PP2_TYPE_SSL, len(ssl_data)) + ssl_data + \
    pack('!BH', Type.PP2_TYPE_NOOP, len(ext_data)) + ext_data + \
    pack('!BH', Type.PP2_TYPE_MIN_CUSTOM + 2, 5) + b'test4'


class TestProxyProtocolTLV(unittest.TestCase):

    def setUp(self) -> None:
        self.tlv = ProxyProtocolTLV(tlv_data)
        self.empty = ProxyProtocolTLV()
        self.auto = ProxyProtocolTLV(unique_id=b'test', auto_crc32c=True)

    def test_alpn(self) -> None:
        self.assertIsNone(self.empty.alpn)
        self.assertEqual(b'test1', self.tlv.alpn)

    def test_authority(self) -> None:
        self.assertIsNone(self.empty.authority)
        self.assertEqual('test②', self.tlv.authority)

    def test_crc32c(self) -> None:
        self.assertIsNone(self.empty.crc32c)
        self.assertEqual(389237127, self.tlv.crc32c)

    def test_checksum(self) -> None:
        self.assertTrue(self.empty.verify_checksum(b'invalid'))
        self.assertEqual(self.empty, self.empty.with_checksum(b'test'))
        tlv = self.auto.with_checksum(b'one', b'two', b'three')
        self.assertEqual(1851355838, tlv.crc32c)
        self.assertTrue(tlv.verify_checksum(b'one', b'two', b'three'))
        self.assertFalse(tlv.verify_checksum(b'one', b'two'))
        self.assertFalse(tlv.verify_checksum(b'four', b'five'))
        tlv = self.auto.with_checksum(b'four', b'five')
        self.assertEqual(3148507994, tlv.crc32c)
        self.assertTrue(tlv.verify_checksum(b'four', b'five'))
        self.assertFalse(tlv.verify_checksum(b'one', b'two', b'three'))

    def test_noop(self) -> None:
        self.assertIsNone(self.empty.get(Type.PP2_TYPE_NOOP))
        self.assertIsNotNone(self.tlv.get(Type.PP2_TYPE_NOOP))

    def test_unique_id(self) -> None:
        self.assertEqual(b'', self.empty.unique_id)
        self.assertEqual(
            b'\x00\x00\x00\x12W\xbb\x1d3\x00\x00\x00\x009\xe9\xdbv',
            self.tlv.unique_id)

    def test_ssl(self) -> None:
        empty_ssl = self.empty.ssl
        self.assertEqual(0, empty_ssl.client)
        self.assertFalse(empty_ssl.has_ssl)
        self.assertFalse(empty_ssl.has_cert_conn)
        self.assertFalse(empty_ssl.has_cert_sess)
        self.assertNotEqual(0, empty_ssl.verify)
        self.assertFalse(empty_ssl.verified)
        ssl = self.tlv.ssl
        self.assertEqual(5, ssl.client)
        self.assertTrue(ssl.has_ssl)
        self.assertFalse(ssl.has_cert_conn)
        self.assertTrue(ssl.has_cert_sess)
        self.assertEqual(0, ssl.verify)
        self.assertTrue(ssl.verified)

    def test_netns(self) -> None:
        self.assertIsNone(self.empty.netns)
        self.assertEqual('test3', self.tlv.netns)

    def test_custom(self) -> None:
        self.assertIsNone(self.empty.get(Type.PP2_TYPE_MIN_CUSTOM + 2))
        self.assertIsNone(self.tlv.get(Type.PP2_TYPE_MIN_CUSTOM + 1))
        self.assertEqual(b'test4', self.tlv.get(Type.PP2_TYPE_MIN_CUSTOM + 2))

    def test_ssl_version(self) -> None:
        self.assertIsNone(self.empty.ssl.version)
        self.assertEqual('1.0', self.tlv.ssl.version)

    def test_ssl_cn(self) -> None:
        self.assertIsNone(self.empty.ssl.cn)
        self.assertEqual('test_ⓒⓝ', self.tlv.ssl.cn)

    def test_ssl_cipher(self) -> None:
        self.assertIsNone(self.empty.ssl.cipher)
        self.assertEqual('test_cipher', self.tlv.ssl.cipher)

    def test_ssl_sig_alg(self) -> None:
        self.assertIsNone(self.empty.ssl.sig_alg)
        self.assertEqual('test_sig_alg', self.tlv.ssl.sig_alg)

    def test_ssl_key_alg(self) -> None:
        self.assertIsNone(self.empty.ssl.key_alg)
        self.assertEqual('test_key_alg', self.tlv.ssl.key_alg)

    def test_ext_compression(self) -> None:
        self.assertIsNone(self.empty.ext.compression)
        self.assertEqual('test_compression', self.tlv.ext.compression)

    def test_ext_secret_bits(self) -> None:
        self.assertIsNone(self.empty.ext.secret_bits)
        self.assertEqual(2048, self.tlv.ext.secret_bits)

    def test_ext_peercert(self) -> None:
        self.assertIsNone(self.empty.ext.peercert)
        self.assertEqual({'test': 'peercert'}, self.tlv.ext.peercert)

    def test_ext_dnsbl(self) -> None:
        self.assertIsNone(self.empty.ext.dnsbl)
        self.assertEqual('test_dnsbl', self.tlv.ext.dnsbl)

    def test_iter(self) -> None:
        self.assertEqual({Type.PP2_TYPE_ALPN, Type.PP2_TYPE_AUTHORITY,
                          Type.PP2_TYPE_CRC32C, Type.PP2_TYPE_NOOP,
                          Type.PP2_TYPE_UNIQUE_ID, Type.PP2_TYPE_SSL,
                          Type.PP2_TYPE_NETNS, Type.PP2_TYPE_MIN_CUSTOM + 2},
                         set(self.tlv))

    def test_bytes_auto(self) -> None:
        with self.assertRaises(ValueError):
            bytes(self.auto)

    def test_size(self) -> None:
        self.assertEqual(len(bytes(self.empty)), self.empty.size)
        self.assertEqual(len(bytes(self.tlv)), self.tlv.size)
        without_auto = ProxyProtocolTLV(init=self.auto)
        self.assertEqual(len(bytes(without_auto)) + 7, self.auto.size)

    def test_len(self) -> None:
        self.assertEqual(0, len(self.empty))
        self.assertEqual(8, len(self.tlv))

    def test_hash(self) -> None:
        self.assertIsInstance(hash(self.empty), int)
        self.assertIsInstance(hash(self.tlv), int)
        self.assertIsInstance(hash(self.tlv.ssl), int)
        self.assertEqual(hash(self.empty), hash(self.empty))
        self.assertEqual(hash(self.tlv), hash(self.tlv))
        self.assertEqual(hash(self.tlv.ssl), hash(self.tlv.ssl))

    def test_eq(self) -> None:
        self.assertEqual(self.empty, ProxyProtocolTLV(bytes(self.empty)))
        self.assertEqual(self.tlv, ProxyProtocolTLV(bytes(self.tlv)))
        self.assertNotEqual(self.tlv, self.empty)
        self.assertNotEqual(self.tlv, self.tlv.ssl)
        self.assertNotEqual(self.tlv.ssl, self.tlv)
        self.assertEqual(self.tlv.ssl, self.tlv.ssl)

    def test_repr(self) -> None:
        self.assertEqual("ProxyProtocolTLV(b'')", repr(self.empty))
        self.assertEqual(f'ProxyProtocolTLV({bytes(self.tlv)!r})',
                         repr(self.tlv))

    def test_kwargs(self) -> None:
        ssl_tlv = ProxyProtocolSSLTLV(has_ssl=True, has_cert_conn=False,
                                      has_cert_sess=True, verify=0,
                                      version='1.0', cn='test_ⓒⓝ',
                                      cipher='test_cipher',
                                      sig_alg='test_sig_alg',
                                      key_alg='test_key_alg')
        ext_tlv = ProxyProtocolExtTLV(compression='test_compression',
                                      secret_bits=2048,
                                      peercert={'test': 'peercert'},
                                      dnsbl='test_dnsbl')
        custom_type = Type.PP2_TYPE_MIN_CUSTOM + 2
        unique_id = b'\x00\x00\x00\x12W\xbb\x1d3\x00\x00\x00\x009\xe9\xdbv'
        init_tlv = TLV(init={custom_type: b'test4'})
        tlv = ProxyProtocolTLV(init=init_tlv,
                               alpn=b'test1', authority='test②',
                               crc32c=389237127, ext=ext_tlv,
                               unique_id=unique_id, ssl=ssl_tlv,
                               netns='test3')
        self.assertEqual(self.tlv, tlv)

    def test_update(self) -> None:
        data = pack('!BL', 0x05, 37)
        ssl_tlv = ProxyProtocolSSLTLV(data, has_ssl=False)
        self.assertEqual(0x04, ssl_tlv.client)
        self.assertEqual(37, ssl_tlv.verify)
        ssl_tlv = ProxyProtocolSSLTLV(data, has_cert_conn=True)
        self.assertEqual(0x07, ssl_tlv.client)
        self.assertEqual(37, ssl_tlv.verify)
        ssl_tlv = ProxyProtocolSSLTLV(data, has_cert_sess=False)
        self.assertEqual(0x01, ssl_tlv.client)
        self.assertEqual(37, ssl_tlv.verify)
        ssl_tlv = ProxyProtocolSSLTLV(data, verify=0)
        self.assertEqual(0x05, ssl_tlv.client)
        self.assertEqual(0, ssl_tlv.verify)
