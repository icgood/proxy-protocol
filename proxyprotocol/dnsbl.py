
from __future__ import annotations

import asyncio
from abc import abstractmethod, ABCMeta
from asyncio import AbstractEventLoop, TimeoutError
from ipaddress import IPv4Address, IPv4Network
from socket import AF_INET, SOCK_STREAM
from typing import Optional, Sequence
from typing_extensions import Final

from .sock import SocketInfo

__all__ = ['Dnsbl', 'NoopDnsbl', 'BasicDnsbl', 'SpamhausDnsbl']


class Dnsbl(metaclass=ABCMeta):
    """Manages the optional lookup of the connecting IP address against a
    trusted `DNSBL
    <https://en.wikipedia.org/wiki/Domain_Name_System-based_blackhole_list>`_.

    """

    __slots__: Sequence[str] = []

    @abstractmethod
    async def lookup(self, sock_info: SocketInfo, *,
                     loop: Optional[AbstractEventLoop] = None) \
            -> Optional[str]:
        """Looks up the connecting IP address and returns the DNSBL hostname
        and the lookup result. Any timeout or misconfiguration is treated as an
        empty result.

        Args:
            sock_info: The connection socket info.

        """
        ...

    @classmethod
    def load(cls, host: Optional[str], *,
             timeout: Optional[float] = None) -> Dnsbl:
        """Given a DNSBL hostname, returns a :class:`Dnsbl` implementation that
        best suits the given *host*.

        Args:
            host: The DNSBL hostname, if any.
            timeout: The time to wait for a response, in seconds, or None for
                indefinite.

        Raises:
            ValueError: The *host* is invalid for this :class:`Dnsbl`.

        """
        if host is None:
            return NoopDnsbl()
        elif host.endswith('.spamhaus.org'):
            return SpamhausDnsbl(host, timeout=timeout)
        else:
            return BasicDnsbl(host, timeout=timeout)


class NoopDnsbl(Dnsbl):
    """Disables DNSBL lookup altogether, :meth:`.lookup` always returns
    ``None``.

    """

    __slots__: Sequence[str] = []

    async def lookup(self, sock_info: SocketInfo, *,
                     loop: Optional[AbstractEventLoop] = None) -> None:
        return None


class BasicDnsbl(Dnsbl):
    """A basic :class:`Dnsbl` implementation that simply returns the DNSBL
    hostname if the DNS lookup returns any IP addresses.

    """

    __slots__ = ['host', 'timeout']

    def __init__(self, host: str, timeout: Optional[float]) -> None:
        super().__init__()
        self.host: Final = host
        self.timeout: Final = timeout

    def map_results(self, addresses: Sequence[IPv4Address]) -> Optional[str]:
        """Given a list of IP address results from a DNSBL lookup, return a
        single string categorizing the results or ``None`` to discard them.

        Args:
            addresses: The list of IP address results.

        """
        if addresses:
            result = self.host
            assert result is not None
            return result
        else:
            return None

    async def lookup(self, sock_info: SocketInfo, *,
                     loop: Optional[AbstractEventLoop] = None) \
            -> Optional[str]:
        host = self.host
        peername_ip = sock_info.peername_ip
        if not isinstance(peername_ip, IPv4Address):
            return self.map_results([])
        loop = loop or asyncio.get_running_loop()
        lookup = '.'.join(peername_ip.reverse_pointer.split('.')[0:4] + [host])
        try:
            addrinfo = await asyncio.wait_for(
                loop.getaddrinfo(lookup, 0, family=AF_INET, type=SOCK_STREAM),
                self.timeout)
        except (OSError, TimeoutError):
            pass
        else:
            if addrinfo:
                addresses = [IPv4Address(res[4][0]) for res in addrinfo]
                return self.map_results(addresses)
        return self.map_results([])


class SpamhausDnsbl(BasicDnsbl):
    """A :class:`Dnsbl` designed for querying `Spamhaus
    <https://www.spamhaus.org/>`_ DNSBLs.

    """

    __slots__: Sequence[str] = []

    _mapping = [(IPv4Network('127.0.0.2/32'), 'https://www.spamhaus.org/sbl/'),
                (IPv4Network('127.0.0.3/32'), 'https://www.spamhaus.org/css/'),
                (IPv4Network('127.0.0.4/30'), 'https://www.spamhaus.org/xbl/'),
                (IPv4Network('127.0.0.10/31'),
                 'https://www.spamhaus.org/pbl/')]

    def map_results(self, addresses: Sequence[IPv4Address]) -> Optional[str]:
        if not addresses:
            return None
        result = addresses[0]
        for network, host in self._mapping:
            if result in network:
                return host
        return self.host
