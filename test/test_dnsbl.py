
from asyncio import AbstractEventLoop
from ipaddress import IPv4Address, IPv6Address
from unittest.mock import MagicMock

try:
    from unittest import IsolatedAsyncioTestCase
    from unittest.mock import AsyncMock
except ImportError as exc:  # Python < 3.8
    from unittest import SkipTest
    raise SkipTest('Missing unittest asyncio imports') from exc

from proxyprotocol.dnsbl import Dnsbl, NoopDnsbl, BasicDnsbl, SpamhausDnsbl
from proxyprotocol.sock import SocketInfo


class TestDnsbl(IsolatedAsyncioTestCase):

    def test_load(self) -> None:
        dnsbl = Dnsbl.load('test.spamhaus.org', timeout=1.3)
        self.assertIsInstance(dnsbl, SpamhausDnsbl)
        dnsbl = Dnsbl.load('test.example.com', timeout=1.3)
        self.assertIsInstance(dnsbl, BasicDnsbl)
        dnsbl = Dnsbl.load(None, timeout=1.3)
        self.assertIsInstance(dnsbl, NoopDnsbl)

    async def test_noop_lookup(self) -> None:
        dnsbl = NoopDnsbl()
        sock_info = MagicMock(SocketInfo)
        result = await dnsbl.lookup(sock_info)
        self.assertIsNone(result)

    async def test_basic_lookup_ipv6(self) -> None:
        dnsbl = BasicDnsbl('test.example.com', None)
        sock_info = MagicMock(SocketInfo)
        sock_info.peername_ip = IPv6Address('::1')
        result = await dnsbl.lookup(sock_info)
        self.assertIsNone(result)

    async def test_basic_lookup_oserror(self) -> None:
        dnsbl = BasicDnsbl('test.example.com', None)
        sock_info = MagicMock(SocketInfo)
        sock_info.peername_ip = IPv4Address('1.2.3.4')
        loop = MagicMock(AbstractEventLoop)
        loop.getaddrinfo = AsyncMock(side_effect=OSError)
        result = await dnsbl.lookup(sock_info, loop=loop)
        self.assertIsNone(result)

    async def test_basic_lookup_empty(self) -> None:
        dnsbl = BasicDnsbl('test.example.com', None)
        sock_info = MagicMock(SocketInfo)
        sock_info.peername_ip = IPv4Address('1.2.3.4')
        loop = MagicMock(AbstractEventLoop)
        loop.getaddrinfo = AsyncMock(return_value=[])
        result = await dnsbl.lookup(sock_info, loop=loop)
        self.assertIsNone(result)

    async def test_basic_lookup(self) -> None:
        dnsbl = BasicDnsbl('test.example.com', None)
        sock_info = MagicMock(SocketInfo)
        sock_info.peername_ip = IPv4Address('1.2.3.4')
        loop = MagicMock(AbstractEventLoop)
        loop.getaddrinfo = AsyncMock(return_value=[
            (None, None, None, None, ('0.0.0.0', 0))])
        result = await dnsbl.lookup(sock_info, loop=loop)
        self.assertEqual('test.example.com', result)

    async def test_spamhaus_lookup_empty(self) -> None:
        dnsbl = SpamhausDnsbl('test.spamhaus.org', None)
        sock_info = MagicMock(SocketInfo)
        sock_info.peername_ip = IPv4Address('1.2.3.4')
        loop = MagicMock(AbstractEventLoop)
        loop.getaddrinfo = AsyncMock(return_value=[])
        result = await dnsbl.lookup(sock_info, loop=loop)
        self.assertIsNone(result)

    async def test_spamhaus_lookup(self) -> None:
        dnsbl = SpamhausDnsbl('test.spamhaus.org', None)
        sock_info = MagicMock(SocketInfo)
        sock_info.peername_ip = IPv4Address('1.2.3.4')
        loop = MagicMock(AbstractEventLoop)
        loop.getaddrinfo = AsyncMock(return_value=[
            (None, None, None, None, ('127.0.0.4', 0))])
        result = await dnsbl.lookup(sock_info, loop=loop)
        self.assertEqual('https://www.spamhaus.org/xbl/', result)

    async def test_spamhaus_lookup_unmapped(self) -> None:
        dnsbl = SpamhausDnsbl('test.spamhaus.org', None)
        sock_info = MagicMock(SocketInfo)
        sock_info.peername_ip = IPv4Address('1.2.3.4')
        loop = MagicMock(AbstractEventLoop)
        loop.getaddrinfo = AsyncMock(return_value=[
            (None, None, None, None, ('127.0.0.100', 0))])
        result = await dnsbl.lookup(sock_info, loop=loop)
        self.assertEqual('test.spamhaus.org', result)
