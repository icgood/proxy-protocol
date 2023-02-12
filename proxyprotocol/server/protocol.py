
from __future__ import annotations

import logging
from abc import abstractmethod, ABCMeta
from asyncio import Task, AbstractEventLoop
from asyncio.protocols import BufferedProtocol
from asyncio.transports import Transport, BaseTransport
from collections import deque
from functools import partial
from typing import Type, Optional, Tuple, Deque
from typing_extensions import Final
from uuid import uuid4

from . import Address
from .. import ProxyProtocol
from ..dnsbl import Dnsbl
from ..build import build_transport_result
from ..result import ProxyResult
from ..sock import SocketInfo, SocketInfoLocal

__all__ = ['DownstreamProtocol', 'UpstreamProtocol']

_log = logging.getLogger(__name__)

_Connect = Tuple[BaseTransport, 'UpstreamProtocol']


class _Base(BufferedProtocol, metaclass=ABCMeta):

    __slots__ = ['_paused', '_buf', '_view', '_queue',
                 '_transport', '_sock_info']

    def __init__(self, buf_len: int) -> None:
        super().__init__()
        self._paused = False
        self._buf = buf = bytearray(buf_len)
        self._view = memoryview(buf).toreadonly()
        self._queue: Deque[bytes] = deque()
        self._transport: Optional[Transport] = None
        self._sock_info: Optional[SocketInfo] = None

    @property
    def sock_info(self) -> SocketInfo:
        sock_info = self._sock_info
        assert sock_info is not None
        return sock_info

    @property
    def transport(self) -> Transport:
        transport = self._transport
        assert transport is not None
        return transport

    @property
    def connected(self) -> bool:
        return self._transport is not None

    def close(self) -> None:
        if self._transport is not None:
            self._transport.close()
            self._transport = None

    def write(self, data: bytes) -> None:
        transport = self._transport
        queue = self._queue
        if self._paused or transport is None:
            queue.append(bytes(data))
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
        self._sock_info = SocketInfoLocal(transport, unique_id=uuid4().bytes)

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
        with self._view[0:nbytes] as updated:
            self.proxy_data(updated)

    @abstractmethod
    def proxy_data(self, data: bytes) -> None:
        ...


class DownstreamProtocol(_Base):

    __slots__ = ['loop', 'dnsbl', 'upstream', 'id', '_waiting',
                 '_waiting_closed', '_upstream', '_upstream_factory',
                 '_dnsbl_task', '_connect_task']

    def __init__(self, upstream_protocol: Type[UpstreamProtocol],
                 loop: AbstractEventLoop, buf_len: int, dnsbl: Dnsbl,
                 upstream: Address) -> None:
        super().__init__(buf_len)
        self.loop: Final = loop
        self.dnsbl: Final = dnsbl
        self.upstream: Final = upstream
        self.id: Final = uuid4().bytes
        self._dnsbl_task: Optional[Task[Optional[str]]] = None
        self._connect_task: Optional[Task[_Connect]] = None
        self._waiting: Deque[bytes] = deque()
        self._waiting_closed = False
        self._upstream: Optional[UpstreamProtocol] = None
        self._upstream_factory = partial(upstream_protocol, self, buf_len,
                                         upstream.pp)

    def _set_client(self, result: ProxyResult,
                    connect_task: Task[_Connect]) -> None:
        dnsbl_task = self._dnsbl_task
        self._dnsbl_task = None
        self._connect_task = None
        assert dnsbl_task is not None
        try:
            _, upstream = connect_task.result()
        except OSError:
            self.close()
            dnsbl_task.cancel()
            _log.exception('[%s] Connection failed: %s',
                           self.id.hex(), self.upstream)
        else:
            callback = partial(self._send_initial, upstream, result)
            dnsbl_task.add_done_callback(callback)

    def _send_initial(self, upstream: UpstreamProtocol, result: ProxyResult,
                      dnsbl_task: Task[Optional[str]]) -> None:
        self._upstream = upstream
        upstream.write_header(dnsbl_task.result(), result)
        waiting = self._waiting
        while waiting:
            data = waiting.popleft()
            upstream.write(data)
        if self._waiting_closed:
            upstream.close()

    def connection_made(self, transport: BaseTransport) -> None:
        super().connection_made(transport)
        _log.info('[%s] Downstream connection received: %s',
                  self.id.hex(), self.sock_info)
        loop = self.loop
        self._dnsbl_task = loop.create_task(self.dnsbl.lookup(self.sock_info))
        self._connect_task = connect_task = loop.create_task(
            loop.create_connection(self._upstream_factory,
                                   self.upstream.host, self.upstream.port or 0,
                                   ssl=self.upstream.ssl))
        result = build_transport_result(transport, unique_id=self.id)
        connect_task.add_done_callback(partial(self._set_client, result))

    def connection_lost(self, exc: Optional[Exception]) -> None:
        super().connection_lost(exc)
        if self._upstream is None:
            self._waiting_closed = True
        else:
            self._upstream.close()
        _log.info('[%s] Downstream connection closed', self.id.hex())

    def proxy_data(self, data: bytes) -> None:
        upstream = self._upstream
        if upstream is None:
            self._waiting.append(bytes(data))
        else:
            upstream.write(data)


class UpstreamProtocol(_Base):

    __slots__ = ['pp', 'downstream']

    def __init__(self, downstream: DownstreamProtocol, buf_len: int,
                 pp: ProxyProtocol) -> None:
        super().__init__(buf_len)
        self.pp: Final = pp
        self.downstream: Final = downstream

    def close(self) -> None:
        super().close()
        self.downstream.close()

    def build_pp_header(self, dnsbl: Optional[str],
                        result: ProxyResult) -> bytes:
        if self.downstream.connected:
            result = build_transport_result(self.downstream.transport,
                                            unique_id=self.downstream.id,
                                            dnsbl=dnsbl)
        return self.pp.pack(result)

    def write_header(self, dnsbl: Optional[str], result: ProxyResult) -> None:
        header = self.build_pp_header(dnsbl, result)
        self.write(header)

    def proxy_data(self, data: bytes) -> None:
        self.downstream.write(data)
