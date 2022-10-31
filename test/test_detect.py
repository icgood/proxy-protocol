
import unittest
from unittest.mock import MagicMock

from proxyprotocol import ProxyProtocolSyntaxError, \
    ProxyProtocolIncompleteError
from proxyprotocol.version import ProxyProtocolVersion
from proxyprotocol.result import ProxyResultUnknown
from proxyprotocol.detect import ProxyProtocolDetect
from proxyprotocol.v1 import ProxyProtocolV1
from proxyprotocol.v2 import ProxyProtocolV2


class TestProxyProtocolDetect(unittest.TestCase):

    def test_version(self) -> None:
        pp = ProxyProtocolVersion.get('DETECT')
        self.assertIsInstance(pp, ProxyProtocolDetect)

    def test_is_valid(self) -> None:
        pp = ProxyProtocolDetect()
        self.assertTrue(pp.is_valid(b'PROXY ...'))
        self.assertTrue(pp.is_valid(b'\r\n\r\n\x00\r\nQ'))
        self.assertFalse(pp.is_valid(b'bad'))

    def test_unpack_incomplete(self) -> None:
        pp = ProxyProtocolDetect()
        with self.assertRaises(ProxyProtocolIncompleteError) as raised:
            pp.unpack(b'')
        self.assertEqual(8, raised.exception.want_read.want_bytes)
        self.assertFalse(raised.exception.want_read.want_line)

    def test_unpack(self) -> None:
        mock_one = MagicMock(ProxyProtocolV1)
        mock_two = MagicMock(ProxyProtocolV1)
        pp = ProxyProtocolDetect(mock_one, mock_two)
        mock_one.is_valid.return_value = False
        mock_one.unpack.side_effect = ValueError
        mock_two.is_valid.return_value = True
        mock_two.unpack.return_value = ProxyResultUnknown()
        res = pp.unpack(b'12345678')
        self.assertIsInstance(res, ProxyResultUnknown)

    def test_choose_version_v1(self) -> None:
        pp = ProxyProtocolDetect()
        pp_choice = pp.choose_version(b'PROXY ...')
        self.assertIsInstance(pp_choice, ProxyProtocolV1)

    def test_choose_version_v2(self) -> None:
        pp = ProxyProtocolDetect()
        pp_choice = pp.choose_version(b'\r\n\r\n\x00\r\nQUIT')
        self.assertIsInstance(pp_choice, ProxyProtocolV2)

    def test_choose_version_bad(self) -> None:
        pp = ProxyProtocolDetect()
        with self.assertRaises(ProxyProtocolSyntaxError):
            pp.choose_version(b'PROXY')
        with self.assertRaises(ProxyProtocolSyntaxError):
            pp.choose_version(b'\r\n\r\n\x00\r\n')
        with self.assertRaises(ProxyProtocolSyntaxError):
            pp.choose_version(b'badPROXY ...')
        with self.assertRaises(ProxyProtocolSyntaxError):
            pp.choose_version(b'bad\r\n\r\n\x00\r\nQUIT')

    def test_pack(self) -> None:
        mock_one = MagicMock(ProxyProtocolV1)
        mock_two = MagicMock(ProxyProtocolV1)
        mock_three = MagicMock(ProxyProtocolV1)
        pp = ProxyProtocolDetect(mock_one, mock_two, mock_three)
        mock_one.pack.side_effect = ValueError
        mock_two.pack.return_value = b'data'
        mock_three.pack.side_effect = AssertionError
        self.assertEqual(
            b'data', pp.pack(ProxyResultUnknown()))

    def test_pack_error(self) -> None:
        mock_one = MagicMock(ProxyProtocolV1)
        pp = ProxyProtocolDetect(mock_one)
        mock_one.pack.side_effect = ValueError
        with self.assertRaises(ValueError):
            pp.pack(ProxyResultUnknown())
