
from __future__ import annotations

from socket import AddressFamily, SocketKind
from ssl import SSLSocket, SSLObject
from typing import Union, Optional, Sequence, NoReturn

from . import ProxyProtocol
from .result import ProxyProtocolResultLocal
from .typing import Address

__all__ = ['ProxyProtocolNoop']


class ProxyProtocolNoop(ProxyProtocol):
    """Implements :class:`~proxyprotocol.base.ProxyProtocol` but does not read
    anything from the stream. A
    :class:`~proxyprotocol.result.ProxyProtocolResultLocal` result is always
    returned.

    """

    __slots__: Sequence[str] = []

    def is_valid(self, signature: bytes) -> NoReturn:
        # This implementation may not be detected
        raise NotImplementedError()

    def parse(self, data: bytes) -> ProxyProtocolResultLocal:
        return ProxyProtocolResultLocal()

    def build(self, source: Address, dest: Address, *, family: AddressFamily,
              protocol: Optional[SocketKind] = None,
              ssl: Union[None, SSLSocket, SSLObject] = None,
              unique_id: Optional[bytes] = None,
              proxied: bool = True,
              dnsbl: Optional[str] = None) -> bytes:
        return b''
