
from __future__ import annotations

from enum import Enum
from typing import cast, Optional

from . import ProxyProtocol
from .detect import ProxyProtocolDetect
from .noop import ProxyProtocolNoop
from .v1 import ProxyProtocolV1
from .v2 import ProxyProtocolV2

__all__ = ['ProxyProtocolVersion']


class ProxyProtocolVersion(Enum):
    """Enumerates the supported PROXY protocol versions."""

    #: Do not read a PROXY protocol header from the input stream.
    NOOP = ProxyProtocolNoop()

    #: The version should be detected from the signature. This is the
    #: recommended choice.
    DETECT = ProxyProtocolDetect()

    #: Use PROXY protocol version 1.
    V1 = ProxyProtocolV1()

    #: Use PROXY protocol version 2.
    V2 = ProxyProtocolV2()

    @classmethod
    def get(cls, name: Optional[str] = None) -> ProxyProtocol:
        """From *name*, return a PROXY protocol implementation class. If *name*
        is empty or ``None``, :class:`~proxyprotocol.noop.ProxyProtocolNoop` is
        returned.

        Args:
            name: The name of the implementation.

        Raises:
            :exc:`KeyError`

        """
        if not name:
            return cls.NOOP.value
        return cast(ProxyProtocol, cls[name.upper()].value)
