"""Go-style duration strings ("15m", "1h30m", "200ms"), so configuration
files are interchangeable with the Go service."""

import re
from datetime import timedelta
from typing import Final

_PART: Final = re.compile(r"(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)")
_UNIT_SECONDS: Final = frozendict({"ns": 1e-9, "us": 1e-6, "µs": 1e-6, "ms": 1e-3, "s": 1.0, "m": 60.0, "h": 3600.0})


def parse_duration(text: str) -> timedelta:
    s = text.strip()
    sign = -1 if s.startswith("-") else 1
    s = s.lstrip("+-")
    if s == "0":
        return timedelta(0)
    pos, seconds = 0, 0.0
    for m in _PART.finditer(s):
        if m.start() != pos:
            break
        seconds += float(m.group(1)) * _UNIT_SECONDS[m.group(2)]
        pos = m.end()
    if pos == 0 or pos != len(s):
        raise ValueError(f"invalid duration {text!r} (examples: 300ms, 15m, 1h30m)")
    return timedelta(seconds=sign * seconds)


def format_duration(d: timedelta) -> str:
    total_ms = round(d.total_seconds() * 1000)
    if total_ms == 0:
        return "0s"
    sign = "-" if total_ms < 0 else ""
    total_ms = abs(total_ms)
    h, rem = divmod(total_ms, 3_600_000)
    m, rem = divmod(rem, 60_000)
    s, ms = divmod(rem, 1000)
    if not (h or m or s):
        return f"{sign}{ms}ms"
    out = (f"{h}h" if h else "") + (f"{m}m" if m else "")
    if s or ms:
        out += f"{s + ms / 1000:g}s"
    return sign + out
