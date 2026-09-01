"""Fetch Okta service apps + API tokens into a bundle for :mod:`okta`.

Okta has no ubiquitous CLI session to borrow (unlike ``az``/``aws``/``gcloud``), so auth is read
from your environment and used only to sign the read-only GETs — the token is never stored or
written anywhere:

    export OKTA_ORG_URL=https://your-org.okta.com
    export OKTA_API_TOKEN=<SSWS token>          # PowerShell: $env:OKTA_API_TOKEN="..."
    python -m tools.collectors.gather_okta > okta-bundle.json
    python -m tools.collectors.okta okta-bundle.json > okta-nhi.json

Read-only throughout (every call is a GET). Least-privilege: a **Read-Only Administrator** SSWS
token, or an OAuth token with ``okta.apps.read`` + ``okta.apiTokens.read`` (add
``okta.apps.grants.read`` — implied by apps.read — for scope expansion). Uses only the Python
standard library (no third-party HTTP dependency).

Options:
    --no-expand   skip each app's grant lookup (one fewer call per app; no scopes/privilege)
    --all-apps    emit every app, not just OAuth service apps (client_credentials)
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

_HELP = ("Set OKTA_ORG_URL (https://your-org.okta.com) and OKTA_API_TOKEN (a read-only SSWS "
         "token) in your environment first.")


def next_link(link_header: str) -> str | None:
    """Return the absolute URL of the ``rel="next"`` entry in an Okta ``Link`` header, or None."""
    for part in (link_header or "").split(","):
        segs = part.split(";")
        if len(segs) >= 2 and 'rel="next"' in segs[1]:
            return segs[0].strip().lstrip("<").rstrip(">").strip()
    return None


def _request(url: str, token: str):
    req = urllib.request.Request(url, headers={
        "Authorization": f"SSWS {token}",
        "Accept": "application/json",
    })
    with urllib.request.urlopen(req) as resp:           # noqa: S310 (trusted org URL)
        body = resp.read().decode("utf-8")
        link = resp.headers.get("Link", "")
    return (json.loads(body) if body.strip() else []), link


def paged(org: str, token: str, path: str) -> list:
    """GET ``path`` and follow Okta's ``Link: rel="next"`` cursor until exhausted."""
    items: list = []
    url = org.rstrip("/") + path
    while url:
        try:
            data, link = _request(url, token)
        except urllib.error.HTTPError as e:
            sys.stderr.write(f"# warn: GET {url} -> HTTP {e.code}\n")
            break
        except urllib.error.URLError as e:
            sys.stderr.write(f"# warn: GET {url} failed: {e.reason}\n")
            break
        items.extend(data if isinstance(data, list) else [data])
        url = next_link(link)  # Okta's next link is absolute
    return items


def _is_service_app(app: dict) -> bool:
    grant_types = ((app.get("settings") or {}).get("oauthClient") or {}).get("grant_types") or []
    return "client_credentials" in grant_types


def main(argv: list[str]) -> int:
    org = os.environ.get("OKTA_ORG_URL")
    token = os.environ.get("OKTA_API_TOKEN")
    if not org or not token:
        sys.exit(f"OKTA_ORG_URL / OKTA_API_TOKEN not set. {_HELP}")

    expand = "--no-expand" not in argv
    all_apps = "--all-apps" in argv

    apps = paged(org, token, "/api/v1/apps?limit=200")
    if not all_apps:
        apps = [a for a in apps if _is_service_app(a)]
    sys.stderr.write(f"# {len(apps)} app(s)"
                     f"{'' if all_apps else ' (OAuth service apps)'}\n")

    if expand:
        for i, app in enumerate(apps, 1):
            aid = app.get("id")
            if not aid:
                continue
            sys.stderr.write(f"\r# expanding grants {i}/{len(apps)}")
            app["grants"] = paged(org, token, f"/api/v1/apps/{aid}/grants?limit=200")
        if apps:
            sys.stderr.write("\n")

    tokens = paged(org, token, "/api/v1/api-tokens")
    sys.stderr.write(f"# {len(tokens)} API token(s)\n")

    json.dump({"orgUrl": org, "apps": apps, "apiTokens": tokens}, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
