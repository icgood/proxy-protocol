
from __future__ import annotations

import logging
from abc import abstractmethod, ABCMeta
from asyncio import Task, AbstractEventLoop, CancelledError
from asyncio.protocols import BufferedProtocol, BaseProtocol
from asyncio.transports import Transport, BaseTransport
from collections import deque
from functools import partial
from socket import AddressFamily, SocketKind
from typing import Any, Type, Optional, Tuple, Deque, Set
from typing_extensions import Final
from uuid import uuid4

from . import Address
from .. import ProxyProtocol
from ..dnsbl import Dnsbl
from ..sock import SocketInfo

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

    @property
    def is_open(self) -> bool:
        return self._sock_info is not None

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
                 loop: AbstractEventLoop, buf_len: int, dnsbl: Dnsbl,
                 upstream: Address) -> None:
        super().__init__(buf_len)
        self.loop: Final = loop
        self.dnsbl: Final = dnsbl
        self.upstream: Final = upstream
        self.id: Final = uuid4().bytes
        self._waiting: Deque[memoryview] = deque()
        self._tasks: Set[Task[Any]] = set()
        self._upstream: Optional[UpstreamProtocol] = None
        self._upstream_factory = partial(upstream_protocol, self, buf_len,
                                         upstream.pp)

    def close(self) -> None:
        super().close()
        for task in self._tasks:
            task.cancel()
        if self._upstream is not None:
            upstream = self._upstream
            self._upstream = None
            upstream.close()

    def _set_client(self, connect_task: Task[_Connect]) -> None:
        try:
            _, upstream = connect_task.result()
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
        dnsbl_task = loop.create_task(self.dnsbl.lookup(self.sock_info))
        self._tasks.add(dnsbl_task)
        dnsbl_task.add_done_callback(self._tasks.discard)
        connect_task = loop.create_task(
            loop.create_connection(partial(self._upstream_factory, dnsbl_task),
                                   self.upstream.host, self.upstream.port or 0,
                                   ssl=self.upstream.ssl))
        self._tasks.add(connect_task)
        connect_task.add_done_callback(self._tasks.discard)
        connect_task.add_done_callback(self._set_client)

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
                 pp: ProxyProtocol, dnsbl_task: Task[Optional[str]]) -> None:
        super().__init__(buf_len)
        self.pp: Final = pp
        self.downstream: Final = downstream
        self.dnsbl_task: Final = dnsbl_task

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
        dnsbl = self.dnsbl_task.result()
        return self.pp.build(sock.getpeername(), sock.getsockname(),
                             family=AddressFamily(sock.family),
                             protocol=protocol, unique_id=self.downstream.id,
                             ssl=ssl_object, dnsbl=dnsbl)

    def connection_made(self, transport: BaseTransport) -> None:
        super().connection_made(transport)
        self.dnsbl_task.add_done_callback(self._write_header)

    def _write_header(self, task: Task[Any]) -> None:
        if self.downstream.is_open:
            header = self.build_pp_header()
            self.write(memoryview(header))

    def proxy_data(self, data: memoryview) -> None:
        self.downstream.write(data)
