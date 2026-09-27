# TCP Connection State Parser

Parses `/proc/net/tcp` and `/proc/net/tcp6` into structured `ConnectionRecord` objects with decoded state names and timer types.

```python
from tcp_connection_state_parser import parse_tcp, parse_tcp_file, TcpState

# From an already-open file handle or list of lines:
with open("/proc/net/tcp") as f:
    records = parse_tcp(f)

for r in records:
    print(r.local_address, r.local_port, r.state.name, r.timer_type)

# Or straight from a path:
records = parse_tcp_file("/proc/net/tcp")
```

## Why this exists

Reading `/proc/net/tcp` directly means splitting whitespace-aligned columns and decoding hex state codes against `include/net/tcp_states.h`. Doing that inline in a monitoring agent is noisy and error-prone. This library does exactly that one job and returns dataclasses.

The trade-off: addresses are returned in their raw hex form (`0100007F`), not converted to dotted-quad or colon IPv6 notation. Endian handling differs between IPv4 and IPv6, and most downstream tools already have that conversion. Keeping the raw form avoids doing it wrong here.

## Edge cases

- **Unknown state codes** (a future kernel adding a state) fall back to `TcpState.CLOSE` rather than raising. The raw integer is preserved in `raw_state`.
- **Unknown timer types** are returned as `"unknown(N)"` instead of crashing.
- **IPv6 addresses** contain colons, so the address/port split is on the last colon, not the first.
- The header row is validated for the `st` and `inode` column names. If the kernel layout changes incompatibly, you get a `ValueError` rather than silently wrong data.

## Exports

- `parse_tcp(lines)` — takes an iterable of strings (e.g. an open file), returns `list[ConnectionRecord]`.
- `parse_tcp_file(path)` — convenience wrapper that opens the file for you.
- `ConnectionRecord` — frozen dataclass with: `local_address`, `local_port`, `remote_address`, `remote_port`, `state`, `tx_queue`, `rx_queue`, `uid`, `inode`, `timer_type`, `timer_expires_jiffies`, `raw_state`.
- `TcpState` — `IntEnum` with members `ESTABLISHED`, `SYN_SENT`, `SYN_RECV`, `FIN_WAIT1`, `FIN_WAIT2`, `TIME_WAIT`, `CLOSE`, `CLOSE_WAIT`, `LAST_ACK`, `LISTEN`, `CLOSING`, `NEW_SYN_RECV`.
