
from __future__ import annotations

import json
import zlib
from enum import IntEnum, IntFlag
from struct import Struct, error as struct_error
from typing import ClassVar, Any, Hashable, Optional, Union, Iterator, \
    Mapping, Dict, List

from .typing import PeerCert

__all__ = ['Type', 'SSLClient', 'TLV', 'ProxyProtocolTLV',
           'ProxyProtocolSSLTLV', 'ProxyProtocolExtTLV']


class Type(IntEnum):
    """The PROXY protocol TLV type values."""

    PP2_TYPE_ALPN = 0x01
    PP2_TYPE_AUTHORITY = 0x02
    PP2_TYPE_CRC32C = 0x03
    PP2_TYPE_NOOP = 0x04
    PP2_TYPE_UNIQUE_ID = 0x05
    PP2_TYPE_SSL = 0x20
    PP2_TYPE_NETNS = 0x30
    PP2_SUBTYPE_SSL_VERSION = 0x21
    PP2_SUBTYPE_SSL_CN = 0x22
    PP2_SUBTYPE_SSL_CIPHER = 0x23
    PP2_SUBTYPE_SSL_SIG_ALG = 0x24
    PP2_SUBTYPE_SSL_KEY_ALG = 0x25
    PP2_TYPE_MIN_CUSTOM = 0xE0
    PP2_TYPE_MAX_CUSTOM = 0xEF
    PP2_TYPE_MIN_EXPERIMENT = 0xF0
    PP2_TYPE_MAX_EXPERIMENT = 0xF7
    PP2_TYPE_MIN_FUTURE = 0xF8
    PP2_TYPE_MAX_FUTURE = 0xFF

    # Extension TLV sub-types
    PP2_SUBTYPE_EXT_COMPRESSION = 0x01
    PP2_SUBTYPE_EXT_SECRET_BITS = 0x02
    PP2_SUBTYPE_EXT_PEERCERT = 0x03


class SSLClient(IntFlag):
    """The PROXY protocol ``PP2_TYPE_SSL`` client flags."""

    PP2_CLIENT_SSL = 0x01
    PP2_CLIENT_CERT_CONN = 0x02
    PP2_CLIENT_CERT_SESS = 0x04


class TLV(Mapping[int, bytes], Hashable):
    """Defines the basic parsing and structure of a PROXY protocol TLV vector.
    The unpacked TLV values are available as dict-style keys of this object,
    e.g. ``tlv[0xE2]``. To serialize back to a bytestring, use ``bytes(tlv)``.

    Args:
        data: TLV data to parse.
        init: A mapping of types to values to initialize the TLV, such as
            another :class:`TLV`.

    """

    _fmt = Struct('!BH')

    def __init__(self, data: bytes = b'',
                 init: Mapping[int, bytes] = {}) -> None:
        super().__init__()
        self._tlv = self._unpack(data)
        self._tlv.update(init)
        self._frozen = self._freeze()

    def _freeze(self) -> Hashable:
        return frozenset((key, zlib.adler32(val))
                         for key, val in self._tlv.items())

    def _unpack(self, data: bytes) -> Dict[int, bytes]:
        view = memoryview(data)
        index = 0
        fmt = self._fmt
        results: Dict[int, bytes] = {}
        while len(data) >= index + fmt.size:
            type_num, size = fmt.unpack_from(view, index)
            index += fmt.size
            results[type_num] = view[index:index + size]
            index += size
        return results

    def _pack(self) -> bytes:
        parts: List[bytes] = []
        fmt = self._fmt
        for type_num in range(0x00, 0x100):
            val = self.get(type_num)
            if val is not None:
                parts.append(fmt.pack(type_num, len(val)))
                parts.append(val)
        return b''.join(parts)

    def __bytes__(self) -> bytes:
        return self._pack()

    def __getitem__(self, type_num: int) -> bytes:
        return self._tlv[type_num]

    def __iter__(self) -> Iterator[int]:
        return iter(self._tlv)

    def __len__(self) -> int:
        return len(self._tlv)

    def __hash__(self) -> int:
        return hash(self._frozen)

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, type(self)):
            return self._frozen == other._frozen
        return super().__eq__(other)

    def __repr__(self) -> str:
        return f'{type(self).__name__}({bytes(self)!r})'


class ProxyProtocolTLV(TLV):
    """Defines the TLV values that may be appended to a PROXY protocol header.
    These values can provide additional information not stored in the address
    data. Refer to the PROXY protocol spec for more information about each TLV.

    Args:
        data: TLV data to parse.
        init: A mapping of types to values to initialize the TLV, such as
            another :class:`TLV`.

    """

    __slots__ = ['_ssl']

    _crc32c_fmt = Struct('!L')

    def __init__(self, data: bytes = b'', init: Mapping[int, bytes] = {}, *,
                 alpn: Optional[bytes] = None,
                 authority: Optional[str] = None,
                 crc32c: Optional[int] = None,
                 unique_id: Optional[bytes] = None,
                 ssl: Optional[ProxyProtocolSSLTLV] = None,
                 netns: Optional[str] = None,
                 ext: Optional[ProxyProtocolExtTLV] = None) -> None:
        results = dict(init)
        if alpn is not None:
            results[Type.PP2_TYPE_ALPN] = alpn
        if authority is not None:
            results[Type.PP2_TYPE_AUTHORITY] = authority.encode('utf-8')
        if crc32c is not None:
            results[Type.PP2_TYPE_CRC32C] = self._crc32c_fmt.pack(crc32c)
        if unique_id is not None:
            results[Type.PP2_TYPE_UNIQUE_ID] = unique_id
        if ssl is not None:
            results[Type.PP2_TYPE_SSL] = bytes(ssl)
        if netns is not None:
            results[Type.PP2_TYPE_NETNS] = netns.encode('ascii')
        if ext is not None:
            results[Type.PP2_TYPE_NOOP] = bytes(ext)
        super().__init__(data, results)

    @property
    def alpn(self) -> Optional[bytes]:
        """The ``PP2_TYPE_ALPN`` value."""
        val = self.get(Type.PP2_TYPE_ALPN)
        if val is not None:
            return bytes(val)
        return None

    @property
    def authority(self) -> Optional[str]:
        """The ``PP2_TYPE_AUTHORITY`` value."""
        val = self.get(Type.PP2_TYPE_AUTHORITY)
        if val is not None:
            return str(val, 'utf-8')
        return None

    @property
    def crc32c(self) -> Optional[int]:
        """The ``PP2_TYPE_CRC32C`` value."""
        val = self.get(Type.PP2_TYPE_CRC32C)
        if val is not None:
            crc32c, = self._crc32c_fmt.unpack(val)
            return int(crc32c)
        return None

    @property
    def unique_id(self) -> bytes:
        """The ``PP2_TYPE_UNIQUE_ID`` value."""
        val = self.get(Type.PP2_TYPE_UNIQUE_ID)
        if val is not None:
            return bytes(val)
        return b''

    @property
    def ssl(self) -> ProxyProtocolSSLTLV:
        """The ``PP2_TYPE_SSL`` value."""
        val = self.get(Type.PP2_TYPE_SSL)
        if val is not None:
            return ProxyProtocolSSLTLV(val)
        return ProxyProtocolSSLTLV()

    @property
    def netns(self) -> Optional[str]:
        """The ``PP2_TYPE_NETNS`` value."""
        val = self.get(Type.PP2_TYPE_NETNS)
        if val is not None:
            return str(val, 'ascii')
        return None

    @property
    def ext(self) -> ProxyProtocolExtTLV:
        """The ``PP2_TYPE_NOOP`` value, possibly parsed as an extension TLV."""
        val = self.get(Type.PP2_TYPE_NOOP)
        if val is not None:
            return ProxyProtocolExtTLV(val)
        return ProxyProtocolExtTLV()


class ProxyProtocolSSLTLV(TLV):
    """The ``PP2_TYPE_SSL`` TLV, which is prefixed with a struct containing
    *client* and *verify* values, then follows with ``PP2_SUBTYPE_SSL_*`` TLVs.

    Args:
        data: TLV data to parse.
        init: A mapping of types to values to initialize the TLV, such as
            another :class:`TLV`.

    """

    _prefix_fmt = Struct('!BL')

    def __init__(self, data: bytes = b'', init: Mapping[int, bytes] = {}, *,
                 has_ssl: Optional[bool] = None,
                 has_cert_conn: Optional[bool] = None,
                 has_cert_sess: Optional[bool] = None,
                 verify: Union[None, int, bool] = None,
                 version: Optional[str] = None,
                 cn: Optional[str] = None,
                 cipher: Optional[str] = None,
                 sig_alg: Optional[str] = None,
                 key_alg: Optional[str] = None) -> None:
        self._client = 0
        self._verify = 1
        results = dict(init)
        if version is not None:
            results[Type.PP2_SUBTYPE_SSL_VERSION] = version.encode('ascii')
        if cn is not None:
            results[Type.PP2_SUBTYPE_SSL_CN] = cn.encode('utf-8')
        if cipher is not None:
            results[Type.PP2_SUBTYPE_SSL_CIPHER] = cipher.encode('ascii')
        if sig_alg is not None:
            results[Type.PP2_SUBTYPE_SSL_SIG_ALG] = sig_alg.encode('ascii')
        if key_alg is not None:
            results[Type.PP2_SUBTYPE_SSL_KEY_ALG] = key_alg.encode('ascii')
        super().__init__(data, results)
        if has_ssl is True:
            self._client |= SSLClient.PP2_CLIENT_SSL
        elif has_ssl is False:
            self._client &= ~SSLClient.PP2_CLIENT_SSL
        if has_cert_conn is True:
            self._client |= SSLClient.PP2_CLIENT_CERT_CONN
        elif has_cert_conn is False:
            self._client &= ~SSLClient.PP2_CLIENT_CERT_CONN
        if has_cert_sess is True:
            self._client |= SSLClient.PP2_CLIENT_CERT_SESS
        elif has_cert_sess is False:
            self._client &= ~SSLClient.PP2_CLIENT_CERT_SESS
        if verify is not None:
            self._verify = int(verify)

    def _unpack(self, data: bytes) -> Dict[int, bytes]:
        view = memoryview(data)
        try:
            self._client, self._verify = self._prefix_fmt.unpack_from(data, 0)
        except struct_error:
            pass
        view = view[self._prefix_fmt.size:]
        return super()._unpack(view)

    def _pack(self) -> bytes:
        prefix = self._prefix_fmt.pack(self.client, self.verify)
        return prefix + super()._pack()

    def __hash__(self) -> int:
        return hash((self._frozen, self._client, self._verify))

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, type(self)):
            self_cmp = (self._frozen, self._client, self._verify)
            other_cmp = (self._frozen, self._client, self._verify)
            return self_cmp == other_cmp
        return super().__eq__(other)

    @property
    def client(self) -> int:
        """The client field in the ``PP2_TYPE_SSL`` value."""
        return self._client

    @property
    def verify(self) -> int:
        """The verify field in the ``PP2_TYPE_SSL`` value."""
        return self._verify

    @property
    def has_ssl(self) -> bool:
        """True if the ``PP2_CLIENT_SSL`` flag was set."""
        return self.client & SSLClient.PP2_CLIENT_SSL != 0

    @property
    def has_cert_conn(self) -> bool:
        """True if the ``PP2_CLIENT_CERT_CONN`` flag was set."""
        return self.client & SSLClient.PP2_CLIENT_CERT_CONN != 0

    @property
    def has_cert_sess(self) -> bool:
        """True if the ``PP2_CLIENT_CERT_SESS`` flag was set."""
        return self.client & SSLClient.PP2_CLIENT_CERT_SESS != 0

    @property
    def verified(self) -> bool:
        """True if the client provided a certificate that was successfully
        verified.

        """
        return self.verify == 0

    @property
    def version(self) -> Optional[str]:
        """The ``PP2_SUBTYPE_SSL_VERSION`` value."""
        val = self.get(Type.PP2_SUBTYPE_SSL_VERSION)
        if val is not None:
            return str(val, 'ascii')
        return None

    @property
    def cn(self) -> Optional[str]:
        """The ``PP2_SUBTYPE_SSL_CN`` value."""
        val = self.get(Type.PP2_SUBTYPE_SSL_CN)
        if val is not None:
            return str(val, 'utf-8')
        return None

    @property
    def cipher(self) -> Optional[str]:
        """The ``PP2_SUBTYPE_SSL_CIPHER`` value."""
        val = self.get(Type.PP2_SUBTYPE_SSL_CIPHER)
        if val is not None:
            return str(val, 'ascii')
        return None

    @property
    def sig_alg(self) -> Optional[str]:
        """The ``PP2_SUBTYPE_SSL_SIG_ALG`` value."""
        val = self.get(Type.PP2_SUBTYPE_SSL_SIG_ALG)
        if val is not None:
            return str(val, 'ascii')
        return None

    @property
    def key_alg(self) -> Optional[str]:
        """The ``PP2_SUBTYPE_SSL_KEY_ALG`` value."""
        val = self.get(Type.PP2_SUBTYPE_SSL_KEY_ALG)
        if val is not None:
            return str(val, 'ascii')
        return None


class ProxyProtocolExtTLV(TLV):
    """Non-standard extension TLV, which is hidden inside a ``PP2_TYPE_NOOP``
    and must start with :attr:`.MAGIC_PREFIX`.

    Args:
        data: TLV data to parse.
        init: A mapping of types to values to initialize the TLV, such as
            another :class:`TLV`.

    """

    #: The ``PP2_TYPE_NOOP`` value must begin with this byte sequence to be
    #: parsed as a :class:`ProxyProtocolExtTLV`.
    MAGIC_PREFIX: ClassVar[bytes] = b'\x88\x1b\x79\xc1\xce\x96\x85\xb0'

    _secret_bits_fmt = Struct('!H')

    def __init__(self, data: bytes = b'', init: Mapping[int, bytes] = {}, *,
                 compression: Optional[str] = None,
                 secret_bits: Optional[int] = None,
                 peercert: Optional[PeerCert] = None) -> None:
        results = dict(init)
        if compression is not None:
            val = compression.encode('ascii')
            results[Type.PP2_SUBTYPE_EXT_COMPRESSION] = val
        if secret_bits is not None:
            val = self._secret_bits_fmt.pack(secret_bits)
            results[Type.PP2_SUBTYPE_EXT_SECRET_BITS] = val
        if peercert is not None:
            val = zlib.compress(json.dumps(peercert).encode('ascii'))
            results[Type.PP2_SUBTYPE_EXT_PEERCERT] = val
        super().__init__(data, results)

    def _unpack(self, data: bytes) -> Dict[int, bytes]:
        view = memoryview(data)
        magic_prefix = self.MAGIC_PREFIX
        if view[0:len(magic_prefix)] != magic_prefix:
            return {}
        view = view[len(magic_prefix):]
        return super()._unpack(view)

    def _pack(self) -> bytes:
        return self.MAGIC_PREFIX + super()._pack()

    @property
    def compression(self) -> Optional[str]:
        """The ``PP2_SUBTYPE_EXT_COMPRESSION`` value. This is used by the
        :attr:`~proxyprotocol.sock.SocketInfo.compression` value.

        """
        val = self.get(Type.PP2_SUBTYPE_EXT_COMPRESSION)
        if val is not None:
            return str(val, 'ascii')
        return None

    @property
    def secret_bits(self) -> Optional[int]:
        """The ``PP2_SUBTYPE_EXT_SECRET_BITS`` value. This is used to populate
        the third member of the: attr:`~proxyprotocol.sock.SocketInfo.cipher`
        tuple.

        """
        val = self.get(Type.PP2_SUBTYPE_EXT_SECRET_BITS)
        if val is not None:
            secret_bits, = self._secret_bits_fmt.unpack(val)
            return int(secret_bits)
        return None

    @property
    def peercert(self) -> Optional[PeerCert]:
        """The ``PP2_SUBTYPE_EXT_PEERCERT`` value. This is used by the
        :attr:`~proxyprotocol.sock.SocketInfo.peercert` value.

        """
        val = self.get(Type.PP2_SUBTYPE_EXT_PEERCERT)
        if val is not None:
            decompressed = zlib.decompress(val)
            ret: PeerCert = json.loads(decompressed)
            return ret
        return None
