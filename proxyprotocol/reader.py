
from __future__ import annotations

import asyncio
from asyncio import StreamReader, StreamWriter
from functools import partial
from typing import Any, Awaitable, Callable, Coroutine, Union
from typing_extensions import Final, TypeAlias
from uuid import uuid4

from . import ProxyProtocol, ProxyProtocolIncompleteError, \
    ProxyProtocolWantRead
from .result import ProxyResult, ProxyResultUnknown
from .sock import SocketInfo
from .typing import StreamReaderProtocol

__all__ = ['ProxyProtocolReader']

_Callback: TypeAlias = Callable[
    [StreamReader, StreamWriter], Awaitable[None]]
_WrappedCallback: TypeAlias = Callable[
    [StreamReader, StreamWriter, SocketInfo], Coroutine[Any, Any, None]]


class ProxyProtocolReader:
    """Read a PROXY protocol header from a stream.

    Args:
        pp: The PROXY protocol implementation.

    """

    def __init__(self, pp: ProxyProtocol) -> None:
        super().__init__()
        self.pp: Final = pp

    async def _handle_want(self, reader: StreamReaderProtocol,
                           want_read: ProxyProtocolWantRead) -> bytes:
        if want_read.want_bytes is not None:
            return await reader.readexactly(want_read.want_bytes)
        elif want_read.want_line:
            return await reader.readline()
        raise ValueError('No conditions given to complete parsing')

    async def read(self, reader: StreamReaderProtocol) -> ProxyResult:
        """Read a complete PROXY protocol header from the input stream and
        return the result.

        Args:
            reader: The input stream.

        """
        data = bytearray()
        want_read: ProxyProtocolWantRead
        while True:
            try:
                with memoryview(data) as view:
                    return self.pp.unpack(view)
            except ProxyProtocolIncompleteError as exc:
                want_read = exc.want_read
            data += await self._handle_want(reader, want_read)

    def get_callback(self, callback: _WrappedCallback,
                     timeout: Union[None, int, float] = 3) -> _Callback:
        """Get a callback object for use as the *client_connected_cb* argument
        to :func:`asyncio.start_server`.

        The returned callback will first read the PROXY protocol header before
        starting the provided *callback* as a :class:`~asyncio.Task`. The
        *callback* argument is similar to *client_connected_cb* but with an
        additional positional argument -- the
        :class:`~proxyprotocol.sock.SocketInfo` read from the header.

        Args:
            callback: Async function with arguments ``(reader, writer,
                sock_info)`` called after successfully reading the header.
            timeout: A timeout in seconds to allow for reading the header.

        """
        return partial(self._read_then_call, callback, timeout)

    async def _read_then_call(self, callback: _WrappedCallback,
                              timeout: Union[None, int, float],
                              reader: StreamReader, writer: StreamWriter) \
            -> None:
        try:
            result = await asyncio.wait_for(self.read(reader), timeout)
        except Exception as exc:
            writer.close()
            result = ProxyResultUnknown(exc)
        sock_info = SocketInfo.get(writer, result, unique_id=uuid4().bytes)
        asyncio.create_task(callback(reader, writer, sock_info))
