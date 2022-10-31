
from __future__ import annotations

from typing import Sequence, NoReturn

from . import ProxyProtocol
from .result import ProxyResult, ProxyResultLocal

__all__ = ['ProxyProtocolNoop']


class ProxyProtocolNoop(ProxyProtocol):
    """Implements :class:`~proxyprotocol.base.ProxyProtocol` but does not read
    anything from the stream. A
    :class:`~proxyprotocol.result.ProxyResultLocal` result is always
    returned.

    """

    __slots__: Sequence[str] = []

    def is_valid(self, signature: bytes) -> NoReturn:
        # This implementation may not be detected
        raise NotImplementedError()

    def unpack(self, data: bytes) -> ProxyResultLocal:
        return ProxyResultLocal()

    def pack(self, result: ProxyResult) -> bytes:
        return b''
