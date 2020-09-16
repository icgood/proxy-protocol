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
from . import Address

__all__ = ['main']

_log = logging.getLogger(__name__)


def main() -> int:
    parser = ArgumentParser(description=__doc__,
                            formatter_class=ArgumentDefaultsHelpFormatter)
    parser.add_argument('type', default='detect', nargs='?',
                        choices=[v.name.lower() for v in ProxyProtocolVersion],
                        help='the PROXY protocol version')
    parser.add_argument('address', metavar='HOST:PORT',
                        type=partial(Address, server=True),
                        nargs='?', default='localhost:10007',
                        help='the listener address')
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)-15s %(name)s %(message)s')

    pp = ProxyProtocolVersion.get(args.type)
    return asyncio.run(run(pp, args.address))


async def run(pp: ProxyProtocol, address: Address) -> int:
    loop = asyncio.get_event_loop()
    callback = partial(run_conn, pp)
    server = await asyncio.start_server(
        callback, address.host, address.port or 10007, ssl=address.ssl)
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
    sock_info = SocketInfo(writer, result)
    _log.info('[%s] Connection received: %s',
              sock_info.unique_id.hex(), sock_info)
    try:
        while True:
            line = await reader.readline()
            if not line:
                break
            writer.write(line)
    except IOError:
        pass
    finally:
        _log.info('[%s] Connection lost', sock_info.unique_id.hex())


if __name__ == '__main__':
    sys.exit(main())
