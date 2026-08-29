"""Assemble the GCP bundle for :mod:`gcp` — service accounts, keys, AND IAM role bindings.

Auth stays with the gcloud CLI; every call is a read (``roles/iam.securityReviewer`` or
project viewer is sufficient):

    python -m tools.collectors.gather_gcp > gcp-accounts.json
    python -m tools.collectors.gcp gcp-accounts.json > gcp-nhi.json

Uses the active gcloud project by default; pass one or more ``--project <id>`` flags to
gather several. For each project this fetches the IAM policy once and joins its bindings to
service accounts by member (``serviceAccount:<email>``), so every account carries the
``roles`` list the transform needs for privilege inference. Without bindings, a
``roles/owner`` service account and a nobody look identical.

Bindings are project-level. Folder/org-level grants and resource-level grants (a bucket, a
dataset) are not gathered — an account can hold more than shown here, never less.
"""

from __future__ import annotations

import json
import subprocess
import sys


def gcloud(*args) -> list | dict:
    try:
        raw = subprocess.check_output(["gcloud", *args, "--format=json"],
                                      stderr=subprocess.PIPE, text=True)
    except FileNotFoundError:
        sys.exit("gcloud CLI not found. Install it and authenticate first.")
    except subprocess.CalledProcessError as e:
        detail = (e.stderr or "").strip().splitlines()
        sys.stderr.write(f"# warn: gcloud {' '.join(args[:3])}... failed: "
                         f"{detail[-1] if detail else e}\n")
        return []
    return json.loads(raw) if raw.strip() else []


def main(argv: list[str]) -> int:
    projects = [argv[i + 1] for i, a in enumerate(argv) if a == "--project" and i + 1 < len(argv)]
    if not projects:
        try:
            current = subprocess.check_output(
                ["gcloud", "config", "get-value", "project"],
                text=True, stderr=subprocess.DEVNULL).strip()
        except Exception:
            current = ""
        if not current or current == "(unset)":
            sys.exit("No project. Pass --project <id> or set one with "
                     "`gcloud config set project <id>`.")
        projects = [current]

    out = []
    for project in projects:
        accounts = gcloud("iam", "service-accounts", "list", "--project", project)
        sys.stderr.write(f"# {project}: {len(accounts)} service accounts\n")

        # One IAM policy read per project; join bindings to accounts by member.
        roles_by_member: dict[str, list[str]] = {}
        policy = gcloud("projects", "get-iam-policy", project)
        for b in (policy.get("bindings") if isinstance(policy, dict) else None) or []:
            for m in b.get("members") or []:
                roles_by_member.setdefault(m, []).append(b.get("role"))

        for sa in accounts:
            email = sa.get("email")
            keys = gcloud("iam", "service-accounts", "keys", "list",
                          "--iam-account", email, "--project", project)
            out.append({
                "email": email,
                "displayName": sa.get("displayName"),
                "disabled": sa.get("disabled", False),
                "labels": sa.get("labels") or {},
                "roles": sorted(r for r in roles_by_member.get(f"serviceAccount:{email}", []) if r),
                "keys": [{"keyType": k.get("keyType"),
                          "validAfterTime": k.get("validAfterTime")} for k in (keys or [])],
            })

    json.dump(out, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
