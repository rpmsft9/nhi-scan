"""Shared helpers for nhi-scan collectors.

Every collector is a **pure transform**: it takes JSON that you already fetched from a source
(via `az`, `aws`, `gcloud`, or a CSV export) and returns nhi-scan records. Collectors never
handle credentials themselves — you run the read-only source command, they map the output. That
keeps them safe, decoupled from auth, and testable offline against recorded sample data.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from typing import Iterable

# The schema fields nhi-scan understands. Anything else is dropped so output stays clean.
KNOWN_FIELDS = {
    "id", "name", "type", "owner", "environment", "privilege", "credential", "secret_storage",
    "last_rotated_days", "last_used_days", "exposure", "scopes", "autonomous", "third_party",
    "human_used", "shared_across_env", "used_by", "tools",
}


def days_since(value, now: datetime | None = None) -> int | None:
    """Whole days between an ISO-8601 timestamp and `now` (default: current UTC).

    Tolerates trailing 'Z', timezone offsets, fractional seconds, and date-only strings.
    Returns None for empty/unparseable input. `now` is injectable so tests are deterministic.
    """
    if not value:
        return None
    now = now or datetime.now(timezone.utc)
    s = str(value).strip().replace("Z", "+00:00")
    dt = None
    for candidate in (s, s[:19], s[:10]):  # full, seconds-precision, date-only
        try:
            dt = datetime.fromisoformat(candidate)
            break
        except ValueError:
            continue
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return max(0, (now - dt).days)


def newest(values: Iterable) -> str | None:
    """The most recent (max) of a set of ISO timestamps, or None."""
    vals = [v for v in values if v]
    return max(vals) if vals else None


def record(**kw) -> dict:
    """Build an nhi-scan record, keeping only known fields and dropping None/empty values."""
    out = {}
    for k, v in kw.items():
        if k not in KNOWN_FIELDS or v is None:
            continue
        if isinstance(v, (list, str)) and len(v) == 0:
            continue
        out[k] = v
    return out


def read_input(argv: list[str]):
    """Load JSON from a file argument, or from stdin if none/`-` is given."""
    if len(argv) > 1 and argv[1] not in ("-", ""):
        with open(argv[1], encoding="utf-8") as f:
            return json.load(f)
    return json.load(sys.stdin)


def emit(records: list[dict]) -> None:
    """Write records as a pretty JSON array to stdout."""
    json.dump(list(records), sys.stdout, indent=2)
    sys.stdout.write("\n")
