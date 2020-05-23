
import socket
import unittest

from proxyprotocol.version import ProxyProtocolVersion
from proxyprotocol.noop import ProxyProtocolNoop


class TestProxyProtocolNoop(unittest.TestCase):

    def test_version(self) -> None:
        pp = ProxyProtocolVersion.get()
        self.assertIsInstance(pp, ProxyProtocolNoop)
        pp = ProxyProtocolVersion.get('')
        self.assertIsInstance(pp, ProxyProtocolNoop)
        pp = ProxyProtocolVersion.get('NOOP')
        self.assertIsInstance(pp, ProxyProtocolNoop)

    def test_build(self) -> None:
        pp = ProxyProtocolNoop()
        self.assertEqual(b'', pp.build(None, None, family=socket.AF_UNSPEC))
