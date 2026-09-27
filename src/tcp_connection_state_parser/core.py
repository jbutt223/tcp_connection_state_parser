"""Parser for /proc/net/tcp and /proc/net/tcp6.

The kernel writes these files in a whitespace-aligned, fixed-column-ish layout.
We treat them as whitespace-split fields rather than byte offsets: the layout
has been stable across kernels for many years, and splitting is robust to the
slight column drift that happens when queue depths grow. The risk is a future
kernel adding a column; we guard against that by validating the header row.
"""

from __future__ import annotations

import enum
import os
from dataclasses import dataclass
from typing import Iterable, List, Optional


class TcpState(enum.IntEnum):
    """Decoded TCP states from /proc/net/tcp.

    The numeric values are the kernel's internal ``TCP_*`` enum values from
    ``include/net/tcp_states.h``. We keep them as the underlying ints so that
    callers can compare against raw values if they ever need to.
    """

    ESTABLISHED = 1
    SYN_SENT = 2
    SYN_RECV = 3
    FIN_WAIT1 = 4
    FIN_WAIT2 = 5
    TIME_WAIT = 6
    CLOSE = 7
    CLOSE_WAIT = 8
    LAST_ACK = 9
    LISTEN = 10
    CLOSING = 11
    NEW_SYN_RECV = 12

    @classmethod
    def from_raw(cls, raw: int) -> "TcpState":
        try:
            return cls(raw)
        except ValueError:
            # Unknown states have shipped before (e.g. when the kernel added
            # NEW_SYN_RECV). We don't want to crash a monitoring agent on a
            # newer kernel, so we fall back to CLOSE (7), which is the
            # "no state" sentinel the kernel itself uses in some paths.
            return cls.CLOSE


# Timer type names as they appear in the kernel's tcp_timer output. The
# /proc/net/tcp ``Tr`` field is the timer type; ``Tm`` is the remaining
# jiffies. We decode the type to a human string because the raw integer is
# meaningless without the header file.
_TIMER_TYPES = {
    0: "none",
    1: "retransmit",
    2: "keep_alive",
    3: "time_wait",
    4: "probe",
}


@dataclass(frozen=True)
class ConnectionRecord:
    """A single decoded TCP connection row.

    Addresses are kept in their colon-separated hex form exactly as the kernel
    writes them. Converting to dotted-quad or colon-notation IPv6 would require
    endian handling that differs between IPv4 and IPv6, and most consumers
    (ss, netstat, monitoring agents) do that display step themselves. We
    expose the raw value and the port separately so callers don't have to
    re-split.
    """

    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    state: TcpState
    tx_queue: int
    rx_queue: int
    uid: int
    inode: int
    timer_type: str
    timer_expires_jiffies: int
    raw_state: int


def _parse_address_port(field: str) -> tuple[str, int]:
    """Split an ``ADDRESS:PORT`` hex field into (address, port).

    The address may itself contain colons (IPv6), so we split on the last
    colon only. Ports are always four hex digits.
    """
    idx = field.rfind(":")
    if idx == -1:
        raise ValueError(f"malformed address:port field: {field!r}")
    addr = field[:idx]
    port = int(field[idx + 1:], 16)
    return addr, port


def _parse_queue(field: str) -> tuple[int, int]:
    """Parse the ``TX:RX`` queue field into (tx, rx) as ints."""
    tx_str, _, rx_str = field.partition(":")
    if not rx_str:
        raise ValueError(f"malformed queue field: {field!r}")
    return int(tx_str, 16), int(rx_str, 16)


def _parse_timer(field: str) -> tuple[int, int]:
    """Parse the ``Tr:Tm`` timer field into (timer_type, expires_jiffies).

    ``Tr`` is a single hex digit timer type; ``Tm`` is hex jiffies remaining.
    """
    tr_str, _, tm_str = field.partition(":")
    if not tm_str:
        raise ValueError(f"malformed timer field: {field!r}")
    return int(tr_str, 16), int(tm_str, 16)


def parse_tcp(lines: Iterable[str]) -> List[ConnectionRecord]:
    """Parse the text contents of /proc/net/tcp or /proc/net/tcp6.

    Accepts any iterable of lines (e.g. an open file handle or a list). The
    first line is the header and is validated to contain the expected column
    names; if it does not, ``ValueError`` is raised rather than silently
    producing garbage records.

    Blank lines are skipped, which makes this safe to feed a file object that
    ends in a trailing newline.
    """
    records: List[ConnectionRecord] = []
    header_seen = False

    for lineno, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line:
            continue

        if not header_seen:
            # We check for the two columns that have never changed name across
            # kernels: ``st`` (state) and ``inode``. Checking the whole header
            # verbatim would break on cosmetic column reordering.
            lowered = line.lower()
            if "st" not in lowered.split() or "inode" not in lowered.split():
                raise ValueError(
                    f"expected /proc/net/tcp header on line 1, got: {line!r}"
                )
            header_seen = True
            continue

        parts = line.split()
        if len(parts) < 10:
            # A real /proc/net/tcp row has 17 fields, but we only need the
            # first 10 for our record. Anything under 10 is a corrupt line.
            raise ValueError(
                f"line {lineno}: expected at least 10 fields, got {len(parts)}: {line!r}"
            )

        # Field layout (1-indexed in comments, 0-indexed in code):
        #  0: sl (entry number)
        #  1: local_address:port
        #  2: remote_address:port
        #  3: st (state, hex)
        #  4: tx_queue:rx_queue
        #  5: tr:tm->timer (we split on the first colon)
        #  6: retrnsmt
        #  7: uid
        #  8: timeout
        #  9: inode
        local_addr, local_port = _parse_address_port(parts[1])
        remote_addr, remote_port = _parse_address_port(parts[2])
        raw_state = int(parts[3], 16)
        tx_queue, rx_queue = _parse_queue(parts[4])
        timer_type_raw, timer_expires = _parse_timer(parts[5])
        uid = int(parts[7], 16)
        inode = int(parts[9])

        records.append(
            ConnectionRecord(
                local_address=local_addr,
                local_port=local_port,
                remote_address=remote_addr,
                remote_port=remote_port,
                state=TcpState.from_raw(raw_state),
                tx_queue=tx_queue,
                rx_queue=rx_queue,
                uid=uid,
                inode=inode,
                timer_type=_TIMER_TYPES.get(timer_type_raw, f"unknown({timer_type_raw})"),
                timer_expires_jiffies=timer_expires,
                raw_state=raw_state,
            )
        )

    if not header_seen:
        raise ValueError("input was empty or contained no header line")

    return records


def parse_tcp_file(path: str) -> List[ConnectionRecord]:
    """Read and parse a /proc/net/tcp[6] file from disk.

    This is a thin convenience wrapper around :func:`parse_tcp`. It opens the
    file in text mode with the default encoding, which is correct for procfs
    on Linux (the kernel writes ASCII).
    """
    with open(path, "r", encoding="ascii") as f:
        return parse_tcp(f)
