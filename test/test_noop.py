
import unittest

from proxyprotocol.version import ProxyProtocolVersion
from proxyprotocol.noop import ProxyProtocolNoop
from proxyprotocol.result import ProxyResultLocal


class TestProxyProtocolNoop(unittest.TestCase):

    def test_version(self) -> None:
        pp = ProxyProtocolVersion.get()
        self.assertIsInstance(pp, ProxyProtocolNoop)
        pp = ProxyProtocolVersion.get('')
        self.assertIsInstance(pp, ProxyProtocolNoop)
        pp = ProxyProtocolVersion.get('NOOP')
        self.assertIsInstance(pp, ProxyProtocolNoop)

    def test_unpack(self) -> None:
        pp = ProxyProtocolNoop()
        pp_result = pp.unpack(b'')
        self.assertIsInstance(pp_result, ProxyResultLocal)

    def test_pack(self) -> None:
        pp = ProxyProtocolNoop()
        self.assertEqual(b'', pp.pack(ProxyResultLocal()))
