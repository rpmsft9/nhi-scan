# nhi-scan collectors

Generate an nhi-scan inventory from your real environment instead of writing it by hand.

Each collector is a **pure transform**: you run a read-only source command, pipe (or save) its
JSON, and the collector maps it to nhi-scan records. Collectors never touch credentials
themselves — auth stays with the `az` / `aws` / `gcloud` CLIs you already trust. That also makes
them testable offline; see [`tests/test_collectors.py`](../../tests/test_collectors.py), which runs
every collector against the recorded samples in [`../samples`](../samples).

The flow is always: **collect (per source) → merge → scan.**

## Entra ID (Azure AD)

Read-only permission: `Directory.Read.All`.

```bash
az ad sp list --all -o json | python -m tools.collectors.entra --tenant <YOUR_TENANT_ID> > entra-nhi.json
```

Infers credential type (certificate / secret / federated), rotation age from the newest
credential, and third-party status from the app's owning tenant. Role assignments (privilege)
need extra Graph calls and are left at the default.

## AWS IAM

Read-only permission: the AWS-managed `IAMReadOnlyAccess` policy. Assemble a bundle, then transform
(one record per access key):

```bash
python - <<'PY' > aws-bundle.json
import json, subprocess
def aws(*a): return json.loads(subprocess.check_output(["aws", *a, "--output", "json"]))
users = []
for u in aws("iam", "list-users")["Users"]:
    name = u["UserName"]
    keys = []
    for k in aws("iam", "list-access-keys", "--user-name", name)["AccessKeyMetadata"]:
        used = aws("iam", "get-access-key-last-used", "--access-key-id", k["AccessKeyId"]).get("AccessKeyLastUsed", {})
        keys.append({"AccessKeyId": k["AccessKeyId"], "Status": k["Status"],
                     "CreateDate": str(k["CreateDate"]), "LastUsedDate": str(used.get("LastUsedDate") or "")})
    pols = [p["PolicyName"] for p in aws("iam", "list-attached-user-policies", "--user-name", name)["AttachedPolicies"]]
    tags = aws("iam", "list-user-tags", "--user-name", name).get("Tags", [])
    users.append({"UserName": name, "Tags": tags, "AttachedPolicies": pols, "AccessKeys": keys})
print(json.dumps(users))
PY
python -m tools.collectors.aws aws-bundle.json > aws-nhi.json
```

Infers `admin` from `AdministratorAccess`, `owner`/`env` from tags, and rotation/last-used from
key dates.

## GCP service accounts

Read-only role: `roles/iam.securityReviewer` (or viewer). Assemble accounts + keys, then transform:

```bash
python - <<'PY' > gcp-accounts.json
import json, subprocess
def g(*a): return json.loads(subprocess.check_output(["gcloud", *a, "--format=json"]))
out = []
for sa in g("iam", "service-accounts", "list"):
    keys = g("iam", "service-accounts", "keys", "list", "--iam-account", sa["email"])
    out.append({"email": sa["email"], "displayName": sa.get("displayName"),
                "disabled": sa.get("disabled", False),
                "labels": sa.get("labels") or {},
                "keys": [{"keyType": k.get("keyType"), "validAfterTime": k.get("validAfterTime")} for k in keys]})
print(json.dumps(out))
PY
python -m tools.collectors.gcp gcp-accounts.json > gcp-nhi.json
```

A user-managed key is treated as a long-lived static credential; accounts without one are
`managed`.

## CSV export (no cloud CLI needed)

Export a spreadsheet whose header row uses nhi-scan field names (see
[`../samples/identities.csv`](../samples/identities.csv)), then:

```bash
python -m tools.collectors.csv_import identities.csv > csv-nhi.json
```

## Merge and scan

Combine every source into one inventory and scan it:

```bash
# with jq
jq -s 'add' entra-nhi.json aws-nhi.json gcp-nhi.json csv-nhi.json > inventory.json

# or without jq
python -c "import json,sys; json.dump([r for f in sys.argv[1:] for r in json.load(open(f))], open('inventory.json','w'))" entra-nhi.json aws-nhi.json gcp-nhi.json csv-nhi.json

nhi-scan scan inventory.json
```

## Run it on a schedule

Wire the collect → merge → scan pipeline into a nightly or weekly job (cron, a scheduled task, or
a CI pipeline with read-only cloud credentials) so the inventory stays live rather than being a
one-time snapshot. Emit `--json` and feed it into a dashboard or ticketing system.

## Writing your own collector

Add a module here that exposes `transform(raw, now=None) -> list[dict]`, using
[`common.record()`](common.py) to build records and `common.days_since()` for credential ages.
Keep it a pure function of already-fetched data, drop a sample into [`../samples`](../samples), and
add a test. That's the whole contract.
