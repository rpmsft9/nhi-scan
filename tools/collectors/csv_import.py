"""CSV export -> nhi-scan records. The no-cloud-CLI path for enterprises.

Export a spreadsheet where the header row uses nhi-scan field names, then:

    python -m tools.collectors.csv_import identities.csv > inventory.json

- Integer columns (`last_rotated_days`, `last_used_days`): blank -> null.
- Boolean columns (`autonomous`, `third_party`, `human_used`, `shared_across_env`):
  true/1/yes/y (case-insensitive) -> true; anything else -> false.
- List columns (`scopes`, `used_by`): separate multiple values with `;`, `|`, or `,`.
- Unknown columns are ignored; blank cells fall back to nhi-scan defaults.
"""

from __future__ import annotations

import csv
import io
import sys

from .common import KNOWN_FIELDS, emit, record

_INT_FIELDS = {"last_rotated_days", "last_used_days"}
_BOOL_FIELDS = {"autonomous", "third_party", "human_used", "shared_across_env"}
_LIST_FIELDS = {"scopes", "used_by"}
_TRUE = {"true", "1", "yes", "y", "t"}


def _split(value: str) -> list[str]:
    for sep in (";", "|", ","):
        if sep in value:
            return [p.strip() for p in value.split(sep) if p.strip()]
    return [value.strip()] if value.strip() else []


def _coerce(field: str, raw: str):
    value = (raw or "").strip()
    if field in _INT_FIELDS:
        try:
            return int(value)
        except ValueError:
            return None
    if field in _BOOL_FIELDS:
        return value.lower() in _TRUE
    if field in _LIST_FIELDS:
        return _split(value)
    return value or None


def transform(rows: list[dict]) -> list[dict]:
    out: list[dict] = []
    for row in rows:
        fields = {}
        for col, raw in row.items():
            key = (col or "").strip()
            if key in KNOWN_FIELDS:
                fields[key] = _coerce(key, raw)
        out.append(record(**fields))
    return out


def transform_csv_text(text: str) -> list[dict]:
    return transform(list(csv.DictReader(io.StringIO(text))))


def main(argv: list[str]) -> int:
    if len(argv) > 1 and argv[1] not in ("-", ""):
        text = open(argv[1], encoding="utf-8-sig").read()
    else:
        text = sys.stdin.read()
    emit(transform_csv_text(text))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
