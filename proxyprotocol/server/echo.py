"""Simple PROXY protocol echo server."""

from __future__ import annotations

import asyncio
import logging
import signal
import sys
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from asyncio import CancelledError, StreamReader, StreamWriter
from functools import partial

from .. import ProxyProtocol
from ..sock import SocketInfo
from ..version import ProxyProtocolVersion

__all__ = ['main']

_log = logging.getLogger(__name__)


def main() -> int:
    parser = ArgumentParser(description=__doc__,
                            formatter_class=ArgumentDefaultsHelpFormatter)
    parser.add_argument('--host', default='localhost',
                        help='the listener host')
    parser.add_argument('--port', default=10007, type=int,
                        help='the listener port')
    parser.add_argument('type', default='detect', nargs='?',
                        choices=[v.name.lower() for v in ProxyProtocolVersion],
                        help='the PROXY protocol version')
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)-15s %(name)s %(message)s')

    pp = ProxyProtocolVersion.get(args.type)
    return asyncio.run(run(pp, args.host, args.port))


async def run(pp: ProxyProtocol, host: str, port: int) -> int:
    loop = asyncio.get_event_loop()
    callback = partial(run_conn, pp)
    server = await asyncio.start_server(callback, host, port)
    async with server:
        forever = asyncio.create_task(server.serve_forever())
        loop.add_signal_handler(signal.SIGINT, forever.cancel)
        loop.add_signal_handler(signal.SIGTERM, forever.cancel)
        try:
            await forever
        except CancelledError:
            pass
    return 0


async def run_conn(pp: ProxyProtocol, reader: StreamReader,
                   writer: StreamWriter) -> None:
    result = await pp.read(reader)
    info = SocketInfo(writer, result)
    _log.info('Upstream connection received: %s', info)
    try:
        while True:
            line = await reader.readline()
            if not line:
                break
            writer.write(line)
    except IOError:
        pass
    finally:
        _log.info('Upstream connection lost: %s', info)


if __name__ == '__main__':
    sys.exit(main())
