"""Shared names for the security layer (single source of truth)."""

RED_TEAM = "red-team"
BLUE_TEAM = "blue-team"
CLIENT_LLM = "client-llm"
TENANTS = (RED_TEAM, BLUE_TEAM, CLIENT_LLM)
CANARY_TYPES = ("file", "credential", "network", "process")
UNKNOWN_ACTOR = "unknown"
GENESIS_HASH = "GENESIS"

# Short names used by the container infrastructure (compose service names,
# canary token prefixes, decoy process names).
_SHORT_TO_TENANT = {"red": RED_TEAM, "blue": BLUE_TEAM, "llm": CLIENT_LLM}
_TENANT_TO_SHORT = {tenant: short for short, tenant in _SHORT_TO_TENANT.items()}


def normalize_tenant(name: str) -> str:
    """Return the contract tenant name for a contract or short name.

    Raises ValueError for anything that is not a known tenant.
    """
    tenant = _SHORT_TO_TENANT.get(name, name)
    if tenant not in TENANTS:
        raise ValueError(f"unknown tenant: {name!r}")
    return tenant


def short_name(tenant: str) -> str:
    """Return the infrastructure short name ("red", "blue", "llm")."""
    return _TENANT_TO_SHORT[normalize_tenant(tenant)]
