
import logging
import socket
from abc import abstractmethod, ABCMeta
from asyncio import Task, AbstractEventLoop
from asyncio.protocols import BufferedProtocol
from asyncio.transports import Transport, BaseTransport
from collections import deque
from socket import AddressFamily, SocketKind
from typing import Any, Optional, Deque
from typing_extensions import Final

from .. import ProxyProtocol
from ..sock import SocketInfo

__all__ = ['Server', 'Client']

_log = logging.getLogger(__name__)


class _Base(BufferedProtocol, metaclass=ABCMeta):

    def __init__(self, pp: ProxyProtocol, buf_len: int) -> None:
        super().__init__()
        self.pp: Final = pp
        self._paused = False
        self._buf: bytearray = bytearray(buf_len)
        self._queue: Deque[bytes] = deque()
        self._transport: Optional[Transport] = None

    @property
    def sock(self) -> socket.socket:
        transport = self._transport
        assert transport is not None
        return transport.get_extra_info('socket')  # type: ignore

    def close(self) -> None:
        if self._transport is not None:
            self._transport.close()
            self._transport = None

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


class Server(_Base):

    def __init__(self, pp: ProxyProtocol, loop: AbstractEventLoop,
                 buf_len: int, host: str, port: int) -> None:
        super().__init__(pp, buf_len)
        self.loop: Final = loop
        self.host: Final = host
        self.port: Final = port
        self._waiting: Deque[memoryview] = deque()
        self._connect: Optional[Task[Any]] = None
        self._client: Optional[Client] = None

    def close(self) -> None:
        super().close()
        if self._connect is not None:
            self._connect.cancel()
            self._connect = None
        if self._client is not None:
            client = self._client
            self._client = None
            client.close()

    def _set_client(self, connect: Any) -> None:
        self._connect = None
        try:
            _, client = connect.result()
        except OSError:
            self.close()
            _log.exception('Downstream connection failed: %s:%s',
                           self.host, self.port)
        else:
            assert isinstance(client, Client)
            self._client = client
            waiting = self._waiting
            while waiting:
                data = waiting.popleft()
                client.write(data)

    def connection_made(self, transport: BaseTransport) -> None:
        super().connection_made(transport)
        _log.info('Upstream connection received: %s', SocketInfo(transport))
        loop = self.loop
        self._connect = loop.create_task(loop.create_connection(
            lambda: Client(self), self.host, self.port))
        self._connect.add_done_callback(self._set_client)

    def proxy_data(self, data: memoryview) -> None:
        client = self._client
        if client is None:
            self._waiting.append(memoryview(data.tobytes()))
        else:
            client.write(data)


class Client(_Base):

    def __init__(self, server: Server) -> None:
        super().__init__(server.pp, len(server._buf))
        self.server: Final = server

    def close(self) -> None:
        super().close()
        self.server.close()

    def build_pp_header(self) -> bytes:
        sock = self.server.sock
        try:
            protocol: Optional[SocketKind] = SocketKind(sock.proto)
        except ValueError:
            protocol = None
        return self.pp.build(sock.getpeername(), sock.getsockname(),
                             family=AddressFamily(sock.family),
                             protocol=protocol)

    def connection_made(self, transport: BaseTransport) -> None:
        super().connection_made(transport)
        header = self.build_pp_header()
        self.write(memoryview(header))

    def proxy_data(self, data: memoryview) -> None:
        self.server.write(data)
