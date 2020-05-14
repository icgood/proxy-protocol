"""Simple PROXY protocol echo server."""

from __future__ import annotations

import asyncio
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from asyncio import StreamReader, StreamWriter
from functools import partial

from .any import ProxyProtocolAny
from .base import ProxyProtocol
from .v1 import ProxyProtocolV1
from .v2 import ProxyProtocolV2

__all__ = ['main']


def main() -> int:
    parser = ArgumentParser(description=__doc__,
                            formatter_class=ArgumentDefaultsHelpFormatter)
    parser.add_argument('--host', default='localhost',
                        help='the listener host')
    parser.add_argument('--port', default=10007, type=int,
                        help='the listener port')
    parser.add_argument('type', choices=['any', 'v1', 'v2'], default='any',
                        nargs='?', help='the PROXY protocol version')
    args = parser.parse_args()

    pp: ProxyProtocol
    if args.type == 'any':
        pp = ProxyProtocolAny()
    elif args.type == 'v1':
        pp = ProxyProtocolV1()
    elif args.type == 'v2':
        pp = ProxyProtocolV2()
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
    print(result)
    while True:
        line = await reader.readline()
        if not line:
            break
        writer.write(line)
