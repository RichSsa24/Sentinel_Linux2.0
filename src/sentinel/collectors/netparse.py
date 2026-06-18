"""Pure parser for ``/proc/net/tcp`` rows — no I/O, no event construction.

This module is the address/state decoding layer for the network collector. It
is deliberately dependency-light (only :mod:`ipaddress` from the stdlib) and
side-effect free: it turns one raw ``/proc/net/tcp`` or ``/proc/net/tcp6`` line
into a :class:`_Socket` value object, or ``None`` when the line is the header or
is malformed. Keeping it separate from :mod:`sentinel.collectors.network` makes
the parsing exhaustively unit-testable without touching the async pipeline, and
keeps the collector module within the project's file-size budget.

The kernel encodes addresses in an awkward layout that this module untangles:

- **IPv4** is 8 hex chars holding the 32-bit address in host (little-endian)
  byte order, so ``0100007F`` is ``127.0.0.1``.
- **IPv6** is 32 hex chars holding four little-endian 32-bit words, so each
  4-byte group is byte-reversed before assembly.
- **Ports** are big-endian hex, so ``0035`` is port 53.

Every field is treated as hostile (§3.3 — reject, don't coerce): lengths are
checked before :func:`bytes.fromhex`, ports are range-bounded, and any decode
failure yields ``None`` rather than a partially-populated record.
"""

from __future__ import annotations

import ipaddress
from typing import Final, NamedTuple

# Whitespace-split column indices of a /proc/net/tcp data row.
_MIN_FIELDS: Final[int] = 10
_LOCAL_IDX: Final[int] = 1
_REMOTE_IDX: Final[int] = 2
_STATE_IDX: Final[int] = 3
_UID_IDX: Final[int] = 7
_INODE_IDX: Final[int] = 9

# An "ADDR:PORT" endpoint splits into exactly two hex fields.
_ENDPOINT_PARTS: Final[int] = 2
_IPV4_HEX_LEN: Final[int] = 8
_IPV6_HEX_LEN: Final[int] = 32
_IPV6_BYTES: Final[int] = 16
_WORD_BYTES: Final[int] = 4  # /proc stores IPv6 as 4 little-endian 32-bit words.
_MIN_PORT: Final[int] = 0
_MAX_PORT: Final[int] = 65535

# Hex TCP states from the kernel (see include/net/tcp_states.h).
STATE_LISTEN: Final[str] = "LISTEN"
STATE_ESTABLISHED: Final[str] = "ESTABLISHED"
_TCP_STATES: Final[dict[str, str]] = {
    "01": STATE_ESTABLISHED, "02": "SYN_SENT", "03": "SYN_RECV",
    "04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
    "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
    "0A": STATE_LISTEN, "0B": "CLOSING",
}  # fmt: skip

SocketKey = tuple[str, str, int, str, int, int]


class Socket(NamedTuple):
    """A parsed, security-relevant socket row from /proc/net/tcp."""

    proto: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str
    uid: int
    inode: int

    @property
    def key(self) -> SocketKey:
        """Stable identity of this socket instance (inode disambiguates reuse)."""
        return (
            self.proto, self.local_ip, self.local_port,
            self.remote_ip, self.remote_port, self.inode,
        )  # fmt: skip


def _parse_ipv4_hex(value: str) -> str | None:
    """Decode an 8-char little-endian hex IPv4 address (e.g. '0100007F')."""
    if len(value) != _IPV4_HEX_LEN:
        return None
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        return None
    return str(ipaddress.IPv4Address(raw[::-1]))


def _parse_ipv6_hex(value: str) -> str | None:
    """Decode a 32-char hex IPv6 address stored as 4 little-endian 32-bit words."""
    if len(value) != _IPV6_HEX_LEN:
        return None
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        return None
    packed = b"".join(raw[i : i + _WORD_BYTES][::-1] for i in range(0, _IPV6_BYTES, _WORD_BYTES))
    return str(ipaddress.IPv6Address(packed))


def _parse_endpoint(field: str, *, ipv6: bool) -> tuple[str, int] | None:
    """Decode an 'ADDR:PORT' hex endpoint into ``(ip, port)`` or ``None``."""
    parts = field.split(":")
    if len(parts) != _ENDPOINT_PARTS:
        return None
    addr_hex, port_hex = parts
    ip = _parse_ipv6_hex(addr_hex) if ipv6 else _parse_ipv4_hex(addr_hex)
    if ip is None:
        return None
    try:
        port = int(port_hex, 16)
    except ValueError:
        return None
    if not _MIN_PORT <= port <= _MAX_PORT:
        return None
    return ip, port


def parse_net_line(line: str, *, proto: str) -> Socket | None:
    """Parse one ``/proc/net/tcp[6]`` row into a :class:`Socket`, or ``None``.

    Returns ``None`` for the header row and any malformed line (too few columns,
    undecodable address, unknown state, non-integer uid/inode). The caller
    decides which states to act on; every recognised state is returned here so
    the parser stays a pure, fully-testable function.
    """
    fields = line.split()
    if len(fields) < _MIN_FIELDS:
        return None
    ipv6 = proto.endswith("6")
    local = _parse_endpoint(fields[_LOCAL_IDX], ipv6=ipv6)
    remote = _parse_endpoint(fields[_REMOTE_IDX], ipv6=ipv6)
    state = _TCP_STATES.get(fields[_STATE_IDX].upper())
    if local is None or remote is None or state is None:
        return None
    try:
        uid = int(fields[_UID_IDX])
        inode = int(fields[_INODE_IDX])
    except ValueError:
        return None
    return Socket(
        proto=proto,
        local_ip=local[0],
        local_port=local[1],
        remote_ip=remote[0],
        remote_port=remote[1],
        state=state,
        uid=uid,
        inode=inode,
    )
