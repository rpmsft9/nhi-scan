"""Core data model for nhi-scan.

The unit of analysis is a **non-human identity (NHI)** — a service account, API key,
OAuth app, service principal / managed identity, workload identity, CI/CD token, PAT,
webhook, or **AI agent**. You describe each NHI's real posture (who owns it, how it
authenticates, how privileged it is, when it was last rotated/used, what it can reach).
Everything downstream — the risk tier and the OWASP NHI Top 10 findings — is a pure
function of these fields, so an assessment is explainable and reproducible. No LLM is
involved in the verdict.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

# --- Policy thresholds (edit here, not scattered through the engine) -------------------
ROTATION_MAX_DAYS = 90   # a static secret older than this is "long-lived" (OWASP NHI7)
STALE_DAYS = 90          # an NHI unused for longer than this is an offboarding candidate

# Scope strings that grant effectively unbounded access.
WILDCARD_SCOPES = {"*", "**", ".*", "all", "full_access", "owner", "admin", "*:*"}


class NHIType(str, Enum):
    SERVICE_ACCOUNT = "service_account"
    API_KEY = "api_key"
    OAUTH_APP = "oauth_app"
    SERVICE_PRINCIPAL = "service_principal"
    MANAGED_IDENTITY = "managed_identity"
    WORKLOAD_IDENTITY = "workload_identity"
    CI_CD_TOKEN = "ci_cd_token"
    PAT = "pat"
    WEBHOOK = "webhook"
    SECRET = "secret"
    AI_AGENT = "ai_agent"

    @classmethod
    def parse(cls, value: str | None) -> "NHIType":
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            return cls.SERVICE_ACCOUNT


class CredentialType(str, Enum):
    """How the NHI authenticates. Static credentials are long-lived secrets an attacker
    can steal and replay; federated/managed/short-lived credentials are not."""

    STATIC_SECRET = "static_secret"      # password / shared secret
    API_KEY = "api_key"
    CERTIFICATE = "certificate"          # long-lived cert
    FEDERATED = "federated"              # OIDC / SAML workload federation — no stored secret
    MANAGED = "managed"                  # cloud-managed identity — no stored secret
    SHORT_LIVED_TOKEN = "short_lived_token"
    NONE = "none"

    @classmethod
    def parse(cls, value: str | None) -> "CredentialType":
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            return cls.STATIC_SECRET

    @property
    def is_static(self) -> bool:
        return self in (CredentialType.STATIC_SECRET, CredentialType.API_KEY, CredentialType.CERTIFICATE)


class SecretStorage(str, Enum):
    VAULT = "vault"          # sourced from a secrets manager
    ENV = "env"              # injected via environment variable
    PLAINTEXT = "plaintext"  # hardcoded / committed / config file
    NONE = "none"            # no stored secret (federated/managed)

    @classmethod
    def parse(cls, value: str | None) -> "SecretStorage":
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            return cls.VAULT


class Privilege(str, Enum):
    ADMIN = "admin"
    PRIVILEGED = "privileged"   # write / elevated but not full admin
    SCOPED = "scoped"           # narrow, task-specific
    READ_ONLY = "read_only"

    @classmethod
    def parse(cls, value: str | None) -> "Privilege":
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            return cls.SCOPED

    @property
    def is_elevated(self) -> bool:
        return self in (Privilege.ADMIN, Privilege.PRIVILEGED)


class Environment(str, Enum):
    PROD = "prod"
    NONPROD = "nonprod"
    DEV = "dev"
    SANDBOX = "sandbox"

    @classmethod
    def parse(cls, value: str | None) -> "Environment":
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            return cls.PROD


class Exposure(str, Enum):
    INTERNET = "internet"                  # reachable from the public internet
    EXTERNAL_PARTNER = "external_partner"  # used by / shared with a third party
    INTERNAL = "internal"

    @classmethod
    def parse(cls, value: str | None) -> "Exposure":
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            return cls.INTERNAL


class RiskTier(int, Enum):
    """Lower is more severe, so `min()` over floors gives the final tier."""

    TIER_1 = 1  # critical — crown-jewel NHI, immediate governance
    TIER_2 = 2  # high
    TIER_3 = 3  # moderate
    TIER_4 = 4  # baseline

    @property
    def label(self) -> str:
        return {1: "Critical", 2: "High", 3: "Moderate", 4: "Baseline"}[int(self)]


@dataclass
class NHI:
    """A single non-human identity and its real posture."""

    id: str
    name: str
    type: NHIType = NHIType.SERVICE_ACCOUNT
    owner: Optional[str] = None
    environment: Environment = Environment.PROD
    privilege: Privilege = Privilege.SCOPED
    credential: CredentialType = CredentialType.STATIC_SECRET
    secret_storage: SecretStorage = SecretStorage.VAULT
    last_rotated_days: Optional[int] = None   # age of current credential; None = never/unknown
    last_used_days: Optional[int] = None      # days since last activity; None = unknown
    exposure: Exposure = Exposure.INTERNAL
    scopes: list[str] = field(default_factory=list)
    autonomous: bool = False                  # AI agent that acts without per-action human approval
    third_party: bool = False                 # issued to / operated by an outside vendor
    human_used: bool = False                  # a human logs in interactively with this NHI
    shared_across_env: bool = False           # same identity used in both prod and non-prod
    used_by: list[str] = field(default_factory=list)  # systems/workloads consuming this NHI
    tools: list[str] = field(default_factory=list)    # agent's tools/connectors/MCP servers — its *reach*

    # --- derived posture ---------------------------------------------------------------
    @property
    def reach(self) -> int:
        """Blast-radius proxy: distinct tools/connectors plus scopes the identity can invoke.
        For an AI agent, ``tools`` can grow (a new connector) without any change to
        privilege, credential age, or owner — which is why drift detection matters."""
        return len(self.tools) + len(self.scopes)

    @property
    def is_orphaned(self) -> bool:
        return not (self.owner and self.owner.strip())

    @property
    def has_static_secret(self) -> bool:
        return self.credential.is_static

    @property
    def is_long_lived(self) -> bool:
        """Static credential never rotated, or older than the rotation window (OWASP NHI7)."""
        if not self.has_static_secret:
            return False
        if self.last_rotated_days is None:
            return True
        return self.last_rotated_days > ROTATION_MAX_DAYS

    @property
    def is_stale(self) -> bool:
        return self.last_used_days is not None and self.last_used_days > STALE_DAYS

    @property
    def has_wildcard_scope(self) -> bool:
        for s in self.scopes:
            low = s.strip().lower()
            if low in WILDCARD_SCOPES or low.endswith("*") or low.endswith(":*"):
                return True
        return False

    @property
    def is_overprivileged(self) -> bool:
        return self.privilege is Privilege.ADMIN or self.has_wildcard_scope

    @property
    def is_reused(self) -> bool:
        return len(self.used_by) > 1


@dataclass
class Fleet:
    """The full set of inventoried non-human identities."""

    identities: list[NHI] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.identities)

    def get(self, nhi_id: str | None) -> Optional[NHI]:
        if nhi_id is None:
            return None
        for n in self.identities:
            if n.id == nhi_id:
                return n
        return None
