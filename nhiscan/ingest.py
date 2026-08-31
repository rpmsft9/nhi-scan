"""Load a non-human-identity inventory from JSON or YAML into the data model.

The inventory is a list of NHI records (or an object with an ``identities`` key). Unknown
enum values fall back to a safe default via each enum's ``parse``, and unknown fields are
ignored, so a partial inventory still loads and assesses.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import (
    NHI,
    CredentialType,
    Environment,
    Exposure,
    Fleet,
    NHIType,
    Privilege,
    SecretStorage,
)


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [str(v) for v in value]


def _record_to_nhi(rec: dict) -> NHI:
    return NHI(
        id=str(rec.get("id") or rec.get("name") or "unknown"),
        name=str(rec.get("name") or rec.get("id") or "unknown"),
        type=NHIType.parse(rec.get("type")),
        owner=(rec.get("owner") or None),
        environment=Environment.parse(rec.get("environment")),
        privilege=Privilege.parse(rec.get("privilege")),
        credential=CredentialType.parse(rec.get("credential")),
        secret_storage=SecretStorage.parse(rec.get("secret_storage")),
        last_rotated_days=rec.get("last_rotated_days"),
        last_used_days=rec.get("last_used_days"),
        exposure=Exposure.parse(rec.get("exposure")),
        scopes=_as_list(rec.get("scopes")),
        autonomous=bool(rec.get("autonomous", False)),
        third_party=bool(rec.get("third_party", False)),
        human_used=bool(rec.get("human_used", False)),
        shared_across_env=bool(rec.get("shared_across_env", False)),
        used_by=_as_list(rec.get("used_by")),
        tools=_as_list(rec.get("tools")),
    )


def _parse_text(text: str, suffix: str) -> Any:
    if suffix in (".yaml", ".yml"):
        try:
            import yaml  # optional dependency
        except ImportError as exc:  # pragma: no cover - depends on environment
            raise RuntimeError(
                "YAML inventory requires PyYAML. Install with `pip install nhi-scan[yaml]` "
                "or provide the inventory as JSON."
            ) from exc
        return yaml.safe_load(text)
    return json.loads(text)


def load_fleet(path: str | Path) -> Fleet:
    p = Path(path)
    # utf-8-sig tolerates a leading BOM (Windows PowerShell writes one via `>` / Out-File),
    # which plain utf-8 decoding would carry into the parser and reject.
    data = _parse_text(p.read_text(encoding="utf-8-sig"), p.suffix.lower())
    records = data.get("identities", data) if isinstance(data, dict) else data
    if not isinstance(records, list):
        raise ValueError("Inventory must be a list of NHI records or an object with 'identities'.")
    return Fleet(identities=[_record_to_nhi(r) for r in records])
