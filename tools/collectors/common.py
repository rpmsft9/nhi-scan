"""Shared helpers for nhi-scan collectors.

Every collector is a **pure transform**: it takes JSON that you already fetched from a source
(via `az`, `aws`, `gcloud`, or a CSV export) and returns nhi-scan records. Collectors never
handle credentials themselves — you run the read-only source command, they map the output. That
keeps them safe, decoupled from auth, and testable offline against recorded sample data.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
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
    """Load JSON from a file argument, or from stdin if none/`-` is given.

    Reads as UTF-8 tolerant of a leading byte-order mark (``utf-8-sig``). Windows shells
    (PowerShell's ``>`` redirection, ``Out-File``) prepend a BOM, and plain ``json.load`` on
    a BOM-prefixed file raises ``Unexpected UTF-8 BOM`` — so a bundle produced on Windows and
    piped back in would fail without this.
    """
    if len(argv) > 1 and argv[1] not in ("-", ""):
        with open(argv[1], encoding="utf-8-sig") as f:
            return json.load(f)
    return json.loads(sys.stdin.buffer.read().decode("utf-8-sig"))


# Characters that must never reach the Windows cmd.exe command line, even inside double quotes:
# a literal quote could close the quoting, and CR/NL/NUL could split or truncate the command.
_UNSAFE_SHELL_CHARS = ('"', "\n", "\r", "\x00")


def _assert_shell_safe(args) -> None:
    """Defence-in-depth for the Windows ``shell=True`` path (see :func:`run_cli`).

    All arguments are built internally — fixed CLI flags, API URLs delivered over TLS, GUID
    resource ids, and temp-file paths — never untrusted free text. As a backstop, refuse any
    argument carrying a character that could break out of the per-argument quoting.
    """
    for a in args:
        if any(c in str(a) for c in _UNSAFE_SHELL_CHARS):
            raise ValueError(f"refusing to shell-execute argument with unsafe character: {a!r}")


def run_cli(args: list[str]) -> str:
    """Run a read-only CLI command (``az`` / ``aws`` / ``gcloud``) and return its stdout.

    Cross-platform. On Windows these CLIs ship as ``.cmd`` shims (``az.cmd``, ``gcloud.cmd``)
    that ``CreateProcess`` cannot launch directly, so ``subprocess([...])`` raises
    ``FileNotFoundError`` there — the reason the gather scripts previously failed on Windows.
    This resolves the executable via ``PATH`` (honouring ``PATHEXT``) and, on Windows, runs it
    through ``cmd.exe`` with every argument double-quoted, so URL query metacharacters
    (``$select``, ``?``, ``&``, parentheses) are passed through literally rather than interpreted
    by the shell. On POSIX the argument list is executed directly, no shell.

    The Windows path uses ``shell=True`` out of necessity (the ``.cmd`` shim), so every argument
    is first checked by :func:`_assert_shell_safe`; the arguments are internally constructed, so
    this only ever fires on a bug, not on normal input.

    Raises ``FileNotFoundError`` if the executable is not on ``PATH``, ``ValueError`` on an unsafe
    argument, and ``subprocess.CalledProcessError`` on a non-zero exit — callers keep their own
    messaging.
    """
    exe = shutil.which(args[0])
    if exe is None:
        raise FileNotFoundError(args[0])
    if os.name == "nt":
        _assert_shell_safe([exe, *args[1:]])
        cmdline = " ".join('"{}"'.format(a) for a in (exe, *args[1:]))
        return subprocess.check_output(cmdline, shell=True, text=True, stderr=subprocess.PIPE)
    return subprocess.check_output([exe, *args[1:]], text=True, stderr=subprocess.PIPE)


def emit(records: list[dict]) -> None:
    """Write records as a pretty JSON array to stdout."""
    json.dump(list(records), sys.stdout, indent=2)
    sys.stdout.write("\n")
