"""Assemble the AWS IAM bundle for :mod:`aws` — including inherited and inline permissions.

Auth stays with the AWS CLI; every call is a read (``iam:List*`` / ``iam:Get*`` — the
AWS-managed ``IAMReadOnlyAccess`` policy is sufficient):

    python -m tools.collectors.gather_aws > aws-bundle.json
    python -m tools.collectors.aws aws-bundle.json > aws-nhi.json

Per user this collects: access keys (+ last-used), attached policy names, **inline policy
names**, and **policy names inherited through group membership** — attached-only gathering is
how a group-granted administrator scores as ``scoped``. It also scans reachable policy
documents (attached user/group policies at their default version, plus inline user policies)
and sets ``HasWildcardAction`` when any statement grants ``"Action": "*"`` — the transform
turns that into a wildcard scope so overprivilege detection fires.

Pass ``--no-documents`` to skip the document scan (fewer API calls; no wildcard detection).
Group policy lookups and policy documents are cached, so shared groups/policies cost one call
each regardless of member count.
"""

from __future__ import annotations

import json
import subprocess
import sys

from .common import run_cli


def aws(*args) -> dict:
    try:
        raw = run_cli(["aws", *args, "--output", "json"])
    except FileNotFoundError:
        sys.exit("aws CLI not found. Install it and configure read-only credentials first.")
    except subprocess.CalledProcessError as e:
        detail = (e.stderr or "").strip().splitlines()
        sys.stderr.write(f"# warn: aws {' '.join(args[:4])}... failed: "
                         f"{detail[-1] if detail else e}\n")
        return {}
    return json.loads(raw) if raw.strip() else {}


def _wildcard_in(document) -> bool:
    """True if any statement grants Action "*" (string or list form)."""
    statements = (document or {}).get("Statement") or []
    if isinstance(statements, dict):
        statements = [statements]
    for st in statements:
        if st.get("Effect") != "Allow":
            continue
        action = st.get("Action")
        if action == "*" or (isinstance(action, list) and "*" in action):
            return True
    return False


def main(argv: list[str]) -> int:
    scan_documents = "--no-documents" not in argv

    users = aws("iam", "list-users").get("Users") or []
    sys.stderr.write(f"# {len(users)} IAM users\n")

    group_cache: dict[str, dict] = {}       # group -> {"names": [...], "wildcard": bool}
    policy_doc_cache: dict[str, bool] = {}  # policy ARN -> has wildcard

    def attached_policy_wildcard(arn: str) -> bool:
        if arn not in policy_doc_cache:
            has = False
            if scan_documents:
                pol = aws("iam", "get-policy", "--policy-arn", arn).get("Policy") or {}
                ver = pol.get("DefaultVersionId")
                if ver:
                    doc = aws("iam", "get-policy-version", "--policy-arn", arn,
                              "--version-id", ver).get("PolicyVersion") or {}
                    has = _wildcard_in(doc.get("Document"))
            policy_doc_cache[arn] = has
        return policy_doc_cache[arn]

    bundle = []
    for i, u in enumerate(users, 1):
        name = u["UserName"]
        sys.stderr.write(f"\r# gathering {i}/{len(users)}")
        wildcard = False

        keys = []
        for k in (aws("iam", "list-access-keys", "--user-name", name)
                  .get("AccessKeyMetadata") or []):
            used = aws("iam", "get-access-key-last-used",
                       "--access-key-id", k["AccessKeyId"]).get("AccessKeyLastUsed") or {}
            keys.append({"AccessKeyId": k["AccessKeyId"], "Status": k["Status"],
                         "CreateDate": str(k.get("CreateDate") or ""),
                         "LastUsedDate": str(used.get("LastUsedDate") or "")})

        attached = aws("iam", "list-attached-user-policies",
                       "--user-name", name).get("AttachedPolicies") or []
        attached_names = [p["PolicyName"] for p in attached]
        for p in attached:
            wildcard = wildcard or attached_policy_wildcard(p["PolicyArn"])

        inline_names = aws("iam", "list-user-policies",
                           "--user-name", name).get("PolicyNames") or []
        if scan_documents:
            for pn in inline_names:
                doc = aws("iam", "get-user-policy", "--user-name", name,
                          "--policy-name", pn).get("PolicyDocument")
                wildcard = wildcard or _wildcard_in(doc)

        group_names: list[str] = []
        for g in (aws("iam", "list-groups-for-user", "--user-name", name)
                  .get("Groups") or []):
            gname = g["GroupName"]
            if gname not in group_cache:
                g_attached = aws("iam", "list-attached-group-policies",
                                 "--group-name", gname).get("AttachedPolicies") or []
                g_inline = aws("iam", "list-group-policies",
                               "--group-name", gname).get("PolicyNames") or []
                g_wild = any(attached_policy_wildcard(p["PolicyArn"]) for p in g_attached)
                group_cache[gname] = {
                    "names": [p["PolicyName"] for p in g_attached] + list(g_inline),
                    "wildcard": g_wild,
                }
            group_names.extend(group_cache[gname]["names"])
            wildcard = wildcard or group_cache[gname]["wildcard"]

        bundle.append({
            "UserName": name,
            "Tags": aws("iam", "list-user-tags", "--user-name", name).get("Tags") or [],
            "AttachedPolicies": attached_names,
            "InlinePolicyNames": list(inline_names),
            "GroupPolicies": group_names,
            "HasWildcardAction": wildcard,
            "AccessKeys": keys,
        })
    sys.stderr.write("\n")

    json.dump(bundle, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
