
from typing_extensions import Final

from . import ProxyProtocolWantRead, ProxyProtocol, ProxyProtocolResult
from .result import ProxyProtocolResultUnknown
from .typing import StreamReaderProtocol

__all__ = ['ProxyProtocolReader']


class ProxyProtocolReader:
    """Read a PROXY protocol header from a stream.

    Args:
        pp: The PROXY protocol implementation.

    """

    def __init__(self, pp: ProxyProtocol) -> None:
        super().__init__()
        self.pp: Final = pp

    def _parse(self, data: bytearray) -> ProxyProtocolResult:
        view = memoryview(data)
        try:
            return self.pp.parse(view)
        finally:
            view.release()

    async def _handle_want(self, reader: StreamReaderProtocol,
                           want_read: ProxyProtocolWantRead) -> bytes:
        if want_read.want_bytes is not None:
            return await reader.readexactly(want_read.want_bytes)
        elif want_read.want_line:
            return await reader.readline()
        raise ValueError() from want_read

    async def read(self, reader: StreamReaderProtocol) -> ProxyProtocolResult:
        """Read a complete PROXY protocol header from the input stream and
        return the result.

        Args:
            reader: The input stream.

        """
        data = bytearray()
        while True:
            try:
                return self._parse(data)
            except ProxyProtocolWantRead as want_read:
                try:
                    data += await self._handle_want(reader, want_read)
                except (EOFError, ConnectionResetError) as exc:
                    return ProxyProtocolResultUnknown(exc)
