"""Simple PROXY protocol echo server."""

from __future__ import annotations

import asyncio
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from asyncio import StreamReader, StreamWriter
from functools import partial

from . import ProxyProtocol
from .sock import SocketInfo
from .version import ProxyProtocolVersion

__all__ = ['main']


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

    pp = ProxyProtocolVersion.get(args.type)
    return asyncio.run(run(args.host, args.port, pp))


async def run(host: str, port: int, pp: ProxyProtocol) -> int:
    callback = partial(run_conn, pp)
    server = await asyncio.start_server(callback, host, port)

    async with server:
        await server.serve_forever()
    return 0


async def run_conn(pp: ProxyProtocol, reader: StreamReader,
                   writer: StreamWriter) -> None:
    result = await pp.read(reader)
    info = SocketInfo(writer, result)
    print(info)
    while True:
        line = await reader.readline()
        if not line:
            break
        writer.write(line)
