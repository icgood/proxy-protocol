proxy-protocol
==============

PROXY protocol library with [asyncio][2] server implementation.

[![build](https://github.com/icgood/proxy-protocol/actions/workflows/python-check.yml/badge.svg)](https://github.com/icgood/proxy-protocol/actions/workflows/python-check.yml)
[![PyPI](https://img.shields.io/pypi/v/proxy-protocol.svg)](https://pypi.python.org/pypi/proxy-protocol)
[![PyPI](https://img.shields.io/pypi/pyversions/proxy-protocol.svg)](https://pypi.python.org/pypi/proxy-protocol)
![platforms](https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-blueviolet)
[![PyPI](https://img.shields.io/pypi/l/proxy-protocol.svg)](https://pypi.python.org/pypi/proxy-protocol)

#### [Specification](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt)
#### [API Reference](http://icgood.github.io/proxy-protocol/)
#### [Docker Image](https://github.com/icgood/proxy-protocol/pkgs/container/proxy-protocol)

### Table of Contents

* [Install and Usage](#install-and-usage)
* [Server Usage](#server-usage)
  * [Echo Server](#echo-server)
  * [Proxy Server](#proxy-server)
* [Development and Testing](#development-and-testing)
  * [Type Hinting](#type-hinting)

## Install and Usage

```bash
$ pip install proxy-protocol
```

Integration with an [`asyncio.start_server`][3] based server is intended to be
extremely simple. Here is an example, which will detect PROXY protocol v1 or
v2.

```python
from proxyprotocol import ProxyProtocol
from proxyprotocol.detect import ProxyProtocolDetect
from proxyprotocol.reader import ProxyProtocolReader
from proxyprotocol.sock import SocketInfo

async def run(host: str, port: int) -> None:
    pp_detect = ProxyProtocolDetect()
    callback = ProxyProtocolReader(pp_detect).get_callback(on_connection)
    server = await asyncio.start_server(callback, host, port)
    async with server:
        await server.serve_forever()

async def on_connection(reader: StreamReader, writer: StreamWriter,
                        info: SocketInfo) -> None:
    print(info.family, info.peername)
    # ... continue using connection
```

To simplify PROXY protocol use based on configuration, the version can also be
read from a string.

```python
from proxyprotocol.version import ProxyProtocolVersion

pp_noop = ProxyProtocolVersion.get(None)
pp_detect = ProxyProtocolVersion.get('detect')
pp_v1 = ProxyProtocolVersion.get('v1')
pp_v2 = ProxyProtocolVersion.get('v2')
```

The `pp_noop` object in this example is a special case implementation that does
not read a PROXY protocol header from the stream at all. It may be used to
disable PROXY protocol use without complicating your server code.

You can also check out the [`proxyprotocol-echo`][4] reference implementation.
If you configure your proxy to send PROXY protocol to `localhost:10007`, you
can see it in action:

```bash
$ proxyprotocol-echo --help
$ proxyprotocol-echo detect
$ proxyprotocol-echo noop
```

## Server Usage

Two basic server implementations are included for reference. Using the two
together can demonstrate the process end-to-end: use `proxyprotocol-server`
to proxy connections with a PROXY protocol header to `proxyprotocol-echo`,
which then displays the original connection information.

The `hostname:port` arguments used by both types of servers are parsed by the
[`Address`][8] class, which allows for customization of SSL/TLS and PROXY
protocol versions.

### Echo Server

The `proxyprotocol-echo` server expects inbound connections to provide a PROXY
protocol header indicating the original source of the connection. After the
header, all received data will be echoed back to the client.

```bash
proxyprotocol-echo --help
proxyprotocol-echo  # run the server
```

### Proxy Server

The `proxyprotocol-server` server proxies inbound connections to another
host/port endoint, prefixing the outbound connection with a PROXY protocol
header to indicate the original connection information.

```bash
proxyprotocol-server --help
proxyprotocol-server --service localhost:10000 localhost:10007
```

## Development and Testing

You will need to do some additional setup to develop and test plugins. Install
[Hatch][1] to use the CLI examples below.

Run all tests and linters:

```console
$ hatch run check
```

Because this project supports several versions of Python, you can use the
following to run the checks on all versions:

```console
$ hatch run all:check
```

### Type Hinting

This project makes heavy use of Python's [type hinting][6] system, with the
intention of a clean run of [mypy][7] in strict mode:

```console
mypy proxyprotocol test
```

No code contribution will be accepted unless it makes every effort to use type
hinting to the extent possible and common in the rest of the codebase.

[1]: https://hatch.pypa.io/latest/install/
[2]: https://docs.python.org/3/library/asyncio.html
[3]: https://docs.python.org/3/library/asyncio-stream.html#asyncio.start_server
[4]: https://github.com/icgood/proxy-protocol/blob/main/proxyprotocol/server/echo.py
[6]: https://www.python.org/dev/peps/pep-0484/
[7]: http://mypy-lang.org/
[8]: https://icgood.github.io/proxy-protocol/proxyprotocol.server.html#proxyprotocol.server.Address
