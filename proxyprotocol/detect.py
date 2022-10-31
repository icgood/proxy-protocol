
from __future__ import annotations

from . import ProxyProtocolWantRead, ProxyProtocol, \
    ProxyProtocolSyntaxError, ProxyProtocolIncompleteError
from .result import ProxyResult
from .v1 import ProxyProtocolV1
from .v2 import ProxyProtocolV2

__all__ = ['ProxyProtocolDetect']


class ProxyProtocolDetect(ProxyProtocol):
    """A PROXY protocol implementation that detects the version based on the
    first 8 bytes from the stream and passes it on to the version parser. This
    adds minimal overhead and *should* be used instead of a specific version.

    Args:
        versions: Override the default set of PROXY protocol implementations.

    """

    __slots__ = ['versions']

    def __init__(self, *versions: ProxyProtocol) -> None:
        super().__init__()
        self.versions = versions or [ProxyProtocolV2(), ProxyProtocolV1()]

    def is_valid(self, signature: bytes) -> bool:
        return any(v.is_valid(signature) for v in self.versions)

    def choose_version(self, signature: bytes) -> ProxyProtocol:
        """Choose the PROXY protocol version based on the 8-byte signature.

        Args:
            signature: The signature bytestring.

        """
        for version in self.versions:
            if version.is_valid(signature):
                return version
        raise ProxyProtocolSyntaxError(
            'Unrecognized proxy protocol version signature')

    def unpack(self, data: bytes) -> ProxyResult:
        if len(data) < 8:
            want_read = ProxyProtocolWantRead(8 - len(data))
            raise ProxyProtocolIncompleteError(want_read)
        pp = self.choose_version(data[0:8])
        return pp.unpack(data)

    def pack(self, result: ProxyResult) -> bytes:
        for version in self.versions:
            try:
                return version.pack(result)
            except (KeyError, ValueError):
                pass
        else:
            raise ValueError('Could not build PROXY protocol header')
