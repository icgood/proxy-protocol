
import unittest

from proxyprotocol import ProxyProtocolError
from proxyprotocol.version import ProxyProtocolVersion
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
        with self.assertRaises(ProxyProtocolError):
            pp.choose_version(b'PROXY')
        with self.assertRaises(ProxyProtocolError):
            pp.choose_version(b'\r\n\r\n\x00\r\n')
        with self.assertRaises(ProxyProtocolError):
            pp.choose_version(b'badPROXY ...')
        with self.assertRaises(ProxyProtocolError):
            pp.choose_version(b'bad\r\n\r\n\x00\r\nQUIT')
