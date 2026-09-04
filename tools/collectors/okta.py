"""Okta non-human identities (service apps + API tokens) -> nhi-scan records.

Gather (read-only) with :mod:`tools.collectors.gather_okta`, then transform:

    python -m tools.collectors.gather_okta > okta-bundle.json
    python -m tools.collectors.okta okta-bundle.json > okta-nhi.json

The two non-human identity classes Okta exposes:

* **OAuth service apps** — apps that authenticate as themselves via the `client_credentials`
  grant (machine-to-machine). Their credential is a client secret (`client_secret_*`), a
  key/JWT (`private_key_jwt` — better, no shared secret), or none (public client). When the
  gather step also pulled each app's **grants**, the granted OAuth scopes populate `scopes` and
  drive `privilege` (an `okta.*.manage` scope is write access; `okta.*` is effectively admin).
  Without grant data, `privilege`/`scopes` are omitted rather than guessed.
* **API tokens** — org-level SSWS tokens: long-lived static secrets. Emitted as `type: api_key`
  so NHI4 (insecure auth) fires, with rotation age from the token's creation date so a
  never-rotated token surfaces under NHI7.

Accepts the bundle from ``gather_okta`` (``{"orgUrl", "apps": [...], "apiTokens": [...]}``) or a
bare list of apps.
"""

from __future__ import annotations

import sys
from datetime import datetime

from .common import days_since, emit, newest, read_input, record

# OAuth scopes that grant write / admin access to the Okta org.
_MANAGE_HINTS = (".manage", "fullaccess")


def _privilege(scopes: list[str]) -> str:
    low = [s.lower() for s in scopes]
    # A bare-wildcard or `okta.*` grant is effectively org admin.
    if any(s == "okta.*" or s.endswith(":*") or s.endswith(".*") or s == "*" for s in low):
        return "admin"
    if any(any(h in s for h in _MANAGE_HINTS) for s in low):
        return "privileged"
    return "scoped" if scopes else "read_only"


def _app_credential(app: dict) -> str:
    """Credential class from the app's OAuth client-authentication method."""
    oauth = (app.get("settings") or {}).get("oauthClient") or {}
    method = (oauth.get("token_endpoint_auth_method") or "").lower()
    if method == "private_key_jwt":
        return "certificate"       # key/JWT auth — no shared secret to leak
    if method in ("client_secret_basic", "client_secret_post", "client_secret_jwt"):
        return "static_secret"
    if method == "none":
        return "federated"         # public client, no stored secret
    return "static_secret" if oauth else "federated"


def _scopes(app: dict) -> list[str]:
    """Granted OAuth scope names from the app's grants (empty if grants weren't gathered)."""
    out: list[str] = []
    for g in app.get("grants") or []:
        value = g.get("scopeId") or g.get("scope")
        if value:
            out.append(value)
    seen: set[str] = set()
    return [s for s in out if not (s in seen or seen.add(s))]


def transform(data, now: datetime | None = None) -> list[dict]:
    if isinstance(data, dict):
        apps = data.get("apps") or []
        tokens = data.get("apiTokens") or data.get("api_tokens") or []
    else:
        apps = data or []
        tokens = []

    out: list[dict] = []

    for app in apps:
        has_grants = "grants" in app
        scopes = _scopes(app)
        out.append(record(
            id=app.get("id"),
            name=app.get("label") or app.get("name") or app.get("id"),
            type="oauth_app",
            # Okta carries no environment signal; assume production rather than under-report.
            environment="prod",
            credential=_app_credential(app),
            secret_storage=("none" if _app_credential(app) in ("federated", "managed") else "vault"),
            privilege=(_privilege(scopes) if has_grants else None),
            scopes=(scopes or None),
        ))

    for t in tokens:
        # An SSWS API token is a long-lived static secret. Rotation age = time since it was
        # created (Okta tokens are not rotated in place). The creating admin (userId) is the
        # closest thing to an accountable owner.
        out.append(record(
            id=t.get("id"),
            name=t.get("name") or t.get("id"),
            type="api_key",
            owner=(t.get("userId") or None),
            environment="prod",
            credential="api_key",
            last_rotated_days=days_since(t.get("created"), now=now),
        ))

    return out


def main(argv: list[str]) -> int:
    emit(transform(read_input(argv)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
