
import unittest

from proxyprotocol.base import ProxyProtocolError
from proxyprotocol.any import ProxyProtocolAny
from proxyprotocol.v1 import ProxyProtocolV1
from proxyprotocol.v2 import ProxyProtocolV2


class TestProxyProtocolAny(unittest.TestCase):

    def test_choose_version_v1(self) -> None:
        pp = ProxyProtocolAny()
        pp_choice = pp.choose_version(b'PROXY ...')
        self.assertIsInstance(pp_choice, ProxyProtocolV1)

    def test_choose_version_v2(self) -> None:
        pp = ProxyProtocolAny()
        pp_choice = pp.choose_version(b'\r\n\r\n\x00\r\nQUIT')
        self.assertIsInstance(pp_choice, ProxyProtocolV2)

    def test_choose_version_bad(self) -> None:
        pp = ProxyProtocolAny()
        with self.assertRaises(ProxyProtocolError):
            pp.choose_version(b'PROXY')
        with self.assertRaises(ProxyProtocolError):
            pp.choose_version(b'\r\n\r\n\x00\r\n')
        with self.assertRaises(ProxyProtocolError):
            pp.choose_version(b'badPROXY ...')
        with self.assertRaises(ProxyProtocolError):
            pp.choose_version(b'bad\r\n\r\n\x00\r\nQUIT')
