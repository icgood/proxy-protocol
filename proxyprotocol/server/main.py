"""A server which proxies connections to a destination, prefixing a PROXY
protocol header to the outbound connection.

"""

from __future__ import annotations

import asyncio
import logging
import signal
import sys
from argparse import Namespace, ArgumentParser, \
    ArgumentDefaultsHelpFormatter, SUPPRESS
from asyncio import CancelledError
from contextlib import AsyncExitStack
from functools import partial

from . import Address
from .protocol import DownstreamProtocol, UpstreamProtocol
from ..dnsbl import Dnsbl

__all__ = ['main']


def main() -> int:
    parser = ArgumentParser(description=__doc__,
                            formatter_class=ArgumentDefaultsHelpFormatter)
    parser.add_argument('--service', nargs=2, default=[],
                        metavar=('SOURCE:PORT', 'DEST:PORT'),
                        action='append', dest='services',
                        help='source and destination of a service')
    parser.add_argument('--buf-len', metavar='BYTES', default=262144, type=int,
                        help='size of the read buffer')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='show only upstream connection errors')
    parser.add_argument('--dnsbl', metavar='HOST', default=None,
                        help='the DNSBL lookup hostname')
    parser.add_argument('--dnsbl-timeout', type=float, help=SUPPRESS)
    args = parser.parse_args()

    if not args.services:
        parser.error('At least one --service is required.')

    logging.basicConfig(
        level=logging.ERROR if args.quiet else logging.INFO,
        format='%(asctime)-15s %(name)s %(message)s')

    return asyncio.run(run(args))


async def run(args: Namespace) -> int:
    loop = asyncio.get_running_loop()
    services = [(Address(source, server=True), Address(dest))
                for (source, dest) in args.services]
    buf_len: int = args.buf_len
    dnsbl = Dnsbl.load(args.dnsbl, timeout=args.dnsbl_timeout)
    new_server = partial(DownstreamProtocol, UpstreamProtocol,
                         loop, buf_len, dnsbl)
    servers = [
        await loop.create_server(partial(new_server, dest),
                                 source.host, source.port or 0,
                                 ssl=source.ssl)
        for source, dest in services]
    async with AsyncExitStack() as stack:
        for server in servers:
            await stack.enter_async_context(server)
        forever = asyncio.gather(*[server.serve_forever()
                                   for server in servers])
        loop.add_signal_handler(signal.SIGINT, forever.cancel)
        loop.add_signal_handler(signal.SIGTERM, forever.cancel)
        try:
            await forever
        except CancelledError:
            pass
    return 0


if __name__ == '__main__':
    sys.exit(main())
