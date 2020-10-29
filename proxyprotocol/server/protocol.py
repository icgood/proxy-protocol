
from __future__ import annotations

import logging
from abc import abstractmethod, ABCMeta
from asyncio import Task, AbstractEventLoop, CancelledError
from asyncio.protocols import BufferedProtocol, BaseProtocol
from asyncio.transports import Transport, BaseTransport
from collections import deque
from functools import partial
from socket import AddressFamily, SocketKind
from typing import Any, Type, Optional, Tuple, Deque
from typing_extensions import Final
from uuid import uuid4

from .. import ProxyProtocol
from ..sock import SocketInfo
from . import Address

__all__ = ['DownstreamProtocol', 'UpstreamProtocol']

_log = logging.getLogger(__name__)

_Connect = Tuple[BaseTransport, BaseProtocol]


class _Base(BufferedProtocol, metaclass=ABCMeta):

    def __init__(self, buf_len: int) -> None:
        super().__init__()
        self._paused = False
        self._buf: bytearray = bytearray(buf_len)
        self._queue: Deque[bytes] = deque()
        self._transport: Optional[Transport] = None
        self._sock_info: Optional[SocketInfo] = None

    @property
    def sock_info(self) -> SocketInfo:
        sock_info = self._sock_info
        assert sock_info is not None
        return sock_info

    def close(self) -> None:
        if self._transport is not None:
            self._transport.close()
            self._transport = None
            self._sock_info = None

    def write(self, data: memoryview) -> None:
        transport = self._transport
        queue = self._queue
        if self._paused or transport is None:
            queue.append(data.tobytes())
        else:
            if queue:
                self._drain(queue)
            transport.write(data)

    def _drain(self, queue: Deque[bytes]) -> None:
        transport = self._transport
        if transport is not None:
            while queue and not self._paused:
                data = queue.popleft()
                transport.write(data)

    def connection_made(self, transport: BaseTransport) -> None:
        assert isinstance(transport, Transport)
        self._transport = transport
        self._sock_info = SocketInfo(transport, unique_id=uuid4().bytes)

    def connection_lost(self, exc: Optional[Exception]) -> None:
        self.close()

    def pause_writing(self) -> None:
        self._paused = True

    def resume_writing(self) -> None:
        self._paused = False
        self._drain(self._queue)

    def get_buffer(self, sizehint: int) -> bytearray:
        return self._buf

    def buffer_updated(self, nbytes: int) -> None:
        data = memoryview(self._buf)[0:nbytes]
        self.proxy_data(data)

    @abstractmethod
    def proxy_data(self, data: memoryview) -> None:
        ...


class DownstreamProtocol(_Base):

    def __init__(self, upstream_protocol: Type[UpstreamProtocol],
                 loop: AbstractEventLoop, buf_len: int,
                 upstream: Address) -> None:
        super().__init__(buf_len)
        self.loop: Final = loop
        self.upstream: Final = upstream
        self.id: Final = uuid4().bytes
        self._waiting: Deque[memoryview] = deque()
        self._connect: Optional[Task[Any]] = None
        self._upstream: Optional[UpstreamProtocol] = None
        self._upstream_factory = partial(upstream_protocol, self, buf_len,
                                         upstream.pp)

    def close(self) -> None:
        super().close()
        if self._connect is not None:
            self._connect.cancel()
            self._connect = None
        if self._upstream is not None:
            upstream = self._upstream
            self._upstream = None
            upstream.close()

    def _set_client(self, connect: Task[_Connect]) -> None:
        self._connect = None
        try:
            _, upstream = connect.result()
        except CancelledError:
            pass  # Connection was never established
        except OSError:
            self.close()
            _log.exception('[%s] Connection failed: %s',
                           self.id.hex(), self.upstream)
        else:
            assert isinstance(upstream, UpstreamProtocol)
            self._upstream = upstream
            waiting = self._waiting
            while waiting:
                data = waiting.popleft()
                upstream.write(data)

    def connection_made(self, transport: BaseTransport) -> None:
        super().connection_made(transport)
        _log.info('[%s] Downstream connection received: %s',
                  self.id.hex(), self.sock_info)
        loop = self.loop
        self._connect = connect = loop.create_task(
            loop.create_connection(self._upstream_factory,
                                   self.upstream.host, self.upstream.port or 0,
                                   ssl=self.upstream.ssl))
        connect.add_done_callback(self._set_client)

    def connection_lost(self, exc: Optional[Exception]) -> None:
        super().connection_lost(exc)
        _log.info('[%s] Downstream connection closed', self.id.hex())

    def proxy_data(self, data: memoryview) -> None:
        upstream = self._upstream
        if upstream is None:
            self._waiting.append(memoryview(data.tobytes()))
        else:
            upstream.write(data)


class UpstreamProtocol(_Base):

    def __init__(self, downstream: DownstreamProtocol, buf_len: int,
                 pp: ProxyProtocol) -> None:
        super().__init__(buf_len)
        self.pp: Final = pp
        self.downstream: Final = downstream

    def close(self) -> None:
        super().close()
        self.downstream.close()

    def build_pp_header(self) -> bytes:
        sock_info = self.downstream.sock_info
        sock = sock_info.socket
        ssl_object = sock_info.transport.get_extra_info('ssl_object')
        try:
            protocol: Optional[SocketKind] = SocketKind(sock.proto)
        except ValueError:
            protocol = None
        return self.pp.build(sock.getpeername(), sock.getsockname(),
                             family=AddressFamily(sock.family),
                             protocol=protocol, unique_id=self.downstream.id,
                             ssl=ssl_object)

    def connection_made(self, transport: BaseTransport) -> None:
        super().connection_made(transport)
        header = self.build_pp_header()
        self.write(memoryview(header))

    def proxy_data(self, data: memoryview) -> None:
        self.downstream.write(data)
