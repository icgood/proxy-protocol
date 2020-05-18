
from . import ProxyProtocolError, ProxyProtocolResult, ProxyProtocol
from .result import ProxyProtocolResultUnknown
from .typing import StreamReaderProtocol
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
        self.versions = versions or [ProxyProtocolV1(), ProxyProtocolV2()]

    def is_valid(self, signature: bytes) -> bool:
        return any(v.is_valid(signature) for v in self.versions)

    async def read(self, reader: StreamReaderProtocol, *,
                   signature: bytes = b'') \
            -> ProxyProtocolResult:  # pragma: no cover
        try:
            signature += await reader.readexactly(8 - len(signature))
        except (EOFError, ConnectionResetError) as exc:
            return ProxyProtocolResultUnknown(exc)
        pp = self.choose_version(signature)
        return await pp.read(reader, signature=signature)

    def choose_version(self, signature: bytes) -> ProxyProtocol:
        """Choose the PROXY protocol version based on the 8-byte signature.

        Args:
            signature: The signature bytestring.

        """
        for version in self.versions:
            if version.is_valid(signature):
                return version
        raise ProxyProtocolError(
            'Unrecognized proxy protocol version signature')
