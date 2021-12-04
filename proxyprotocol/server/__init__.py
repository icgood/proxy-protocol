
from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit, parse_qs
from ssl import SSLContext, Purpose, VerifyMode, create_default_context
from typing import Optional
from typing_extensions import Final

from .. import ProxyProtocol
from ..version import ProxyProtocolVersion

__all__ = ['Address']


class Address:
    """Parses an address on the command-line. Valid examples include:

    * ``HOST``
    * ``HOST:PORT``
    * ``HOST:PORT?pp=v1``
    * ``ssl://HOST:PORT`` (outbound addresses only)
    * ``ssl://HOST:PORT?cert=/path/to/cert.pem``
    * ``ssl://HOST:PORT?cert=cert.pem&key=privkey.pem&verify=CERT_REQUIRED``

    Args:
        addr: The address string to parse.
        server: True for server-side (listen) addresses.

    """

    __slots__ = ['url', 'query', 'server', '_ssl']

    def __init__(self, addr: str, *, server: bool = False) -> None:
        super().__init__()
        url = urlsplit(addr)
        if not url.scheme or not url.netloc:
            url = urlsplit('//' + addr)
        if url.query:
            query = parse_qs(url.query)
        else:
            query = {}
        self.url: Final = url
        self.query: Final = query
        self.server: Final = server
        self._ssl: Optional[SSLContext] = None

    @property
    def host(self) -> str:
        """The hostname parsed from the address."""
        return self.url.hostname or ''

    @property
    def port(self) -> Optional[int]:
        """The port parsed from the address."""
        return self.url.port or None

    @property
    def pp(self) -> ProxyProtocol:
        """The PROXY protocol implementation."""
        pp_version = self.query.get('pp', [''])[-1] or 'detect'
        return ProxyProtocolVersion.get(pp_version)

    @property
    def ssl(self) -> Optional[SSLContext]:
        """The: class:`~ssl.SSLContext` to use on the address."""
        if self.url.scheme == 'ssl':
            if self._ssl is None:
                if self.server:
                    ssl = create_default_context(Purpose.CLIENT_AUTH)
                else:
                    ssl = create_default_context(Purpose.SERVER_AUTH)
                if self.server or 'cert' in self.query:
                    cert = self.query['cert'][-1]
                    key = self.query.get('key', [''])[-1] or None
                    ssl.load_cert_chain(cert, key)
                if 'verify' in self.query:
                    ssl.verify_mode = VerifyMode[self.query['verify'][-1]]
                if 'cafile' in self.query or 'capath' in self.query:
                    cafile = self.query.get('cafile', [''])[-1] or None
                    capath = self.query.get('capath', [''])[-1] or None
                    cadata = self.query.get('cadata', [''])[-1] or None
                    ssl.load_verify_locations(cafile, capath, cadata)
                self._ssl = ssl
            return self._ssl
        else:
            return None

    def __str__(self) -> str:
        return urlunsplit(self.url)
