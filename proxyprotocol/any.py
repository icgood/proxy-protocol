
from __future__ import annotations

from typing import Optional

from .base import ProxyProtocolError, DataReader, ProxyProtocol
from .result import ProxyProtocolResult
from .v1 import ProxyProtocolV1
from .v2 import ProxyProtocolV2

__all__ = ['ProxyProtocolAny']


class ProxyProtocolAny(ProxyProtocol):
    """A PROXY protocol implementation that detects the version based on the
    first 8 bytes from the stream and passes it on to the version parser. This
    adds minimal overhead and *should* be used instead of a specific version.

    Args:
        v1: The PROXY protocol v1 implementation.
        v2: The PROXY protocol v2 implementation.

    """

    def __init__(self, *, v1: Optional[ProxyProtocolV1] = None,
                 v2: Optional[ProxyProtocolV2] = None) -> None:
        super().__init__()
        self.v1 = v1 or ProxyProtocolV1()
        self.v2 = v2 or ProxyProtocolV2()

    async def read(self, reader: DataReader, *,
                   signature: bytes = b'') \
            -> ProxyProtocolResult:  # pragma: no cover
        signature += await reader.readexactly(8 - len(signature))
        pp = self.choose_version(signature)
        return await pp.read(reader, signature=signature)

    def choose_version(self, signature: bytes) -> ProxyProtocol:
        """Choose the PROXY protocol version based on the 8-byte signature.

        Args:
            signature: The signature bytestring.

        """
        if signature.startswith(b'PROXY '):
            return self.v1
        elif signature.startswith(b'\r\n\r\n\x00\r\nQ'):
            return self.v2
        else:
            raise ProxyProtocolError(
                'Unrecognized proxy protocol version signature')
