proxy-protocol
==============

PROXY protocol library with [asyncio][2] server implementation.

[![Build Status](https://travis-ci.com/icgood/proxy-protocol.svg?branch=master)](https://travis-ci.com/icgood/proxy-protocol)
[![Coverage Status](https://coveralls.io/repos/icgood/proxy-protocol/badge.svg)](https://coveralls.io/r/icgood/proxy-protocol)
[![PyPI](https://img.shields.io/pypi/v/proxy-protocol.svg)](https://pypi.python.org/pypi/proxy-protocol)
[![PyPI](https://img.shields.io/pypi/pyversions/proxy-protocol.svg)](https://pypi.python.org/pypi/proxy-protocol)
[![PyPI](https://img.shields.io/pypi/l/proxy-protocol.svg)](https://pypi.python.org/pypi/proxy-protocol)

#### [Specification](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt)
#### [API Documentation](http://icgood.github.io/proxy-protocol/)

### Table of Contents

* [Install and Usage](#install-and-usage)
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
from functools import partial

from proxyprotocol.base import ProxyProtocol
from proxyprotocol.detect import ProxyProtocolDetect
from proxyprotocol.socket import SocketInfo

async def run(host: str, port: int) -> None:
    pp = ProxyProtocolDetect()
    callback = partial(on_connection, pp)
    server = await asyncio.start_server(callback, host, port)
    async with server:
        await server.serve_forever()

async def on_connection(pp: ProxyProtocolDetect,
                        reader: StreamReader, writer: StreamWriter) -> None:
    result = await pp.read(reader)
    info = SocketInfo(writer, result)
    print(info.family, info.peername)
    # ... continue using connection
```

To simplify PROXY protocol use based on configuration, the version can also be
read from a string.

```python
from proxyprotocol.version import ProxyProtocolVersion

pp_noop = ProxyProtocolVersion.get()
pp_detect = ProxyProtocolVersion.get('detect')
pp_v1 = ProxyProtocolVersion.get('v1')
pp_v2 = ProxyProtocolVersion.get('v2')
```

The `pp_noop` object in this example is a special case implementation that does
not read a PROXY protocol header from the stream at all. It may be used to
disable PROXY protocol use without complicating your server code.

You can also check out the [`proxyprotocol/echo.py`][4] reference
implementation. If you configure your proxy to send PROXY protocol to
`localhost:10007`, you can see it in action:

```bash
$ proxyprotocol-echo --help
$ proxyprotocol-echo detect
$ proxyprotocol-echo noop
```

## Development and Testing

You will need to do some additional setup to develop and test plugins. First
off, I suggest activating a [venv][5]. Then, install the test requirements and
a local link to the proxy-protocol package:

```
$ pip install -r test/requirements.txt
$ pip install -e .
```

Run the tests with py.test:

```
$ py.test
```

If you intend to create a pull request, you should make sure the full suite of
tests run by CI/CD is passing:

```
$ py.test
$ mypy --strict proxyprotocol test
$ flake8 proxyprotocol test
```

A py.test run executes both unit and integration tests. The integration tests
use mocked sockets to simulate the sending and receiving of commands and
responses, and are kept in the `test/server/` subdirectory.

### Type Hinting

This project makes heavy use of Python's [type hinting][6] system, with the
intention of a clean run of [mypy][7]:

```
mypy --strict proxyprotocol test
```

No code contribution will be accepted unless it makes every effort to use type
hinting to the extent possible and common in the rest of the codebase.

[2]: https://docs.python.org/3/library/asyncio.html
[3]: https://docs.python.org/3/library/asyncio-stream.html#asyncio.start_server
[4]: https://github.com/icgood/proxy-protocol/blob/master/proxyprotocol/echo.py
[5]: https://docs.python.org/3/library/venv.html
[6]: https://www.python.org/dev/peps/pep-0484/
[7]: http://mypy-lang.org/
