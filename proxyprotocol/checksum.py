
from __future__ import annotations

from abc import abstractmethod
from typing import Optional, Sequence
from typing_extensions import Protocol

try:
    from crc32c import crc32c as _crc32c
except ImportError:  # pragma: no cover
    _crc32c = None

__all__ = ['crc32c', 'Checksum']


#: The CRC32C checksum function, if the ``crc32c`` library is installed.
crc32c: Optional[Checksum] = _crc32c


class Checksum(Protocol):
    """Provides typing compatible with the `crc32c.crc32c
    <https://github.com/ICRAR/crc32c#usage>`_ function, if it is installed.

    Args:
        val: The bytestring to checksum.
        crc: The checksum of previous portions of data.

    """

    __slots__: Sequence[str] = []

    @abstractmethod
    def __call__(self, val: bytes, crc: int = ...) -> int:
        ...
