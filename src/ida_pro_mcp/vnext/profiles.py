"""Built-in safety profiles shared by the IDA configuration UI and tests."""

from __future__ import annotations

from collections.abc import Mapping

from .contracts import SafetyScope
from .policy import CANONICAL_TOOLS, ToolPolicyRegistry


# Quick profiles stay bounded. A new install enables every registered tool;
# _configure_scopes then activates whatever safety scopes those tools need.
DEFAULT_PROFILE_SCOPES = frozenset(
    {SafetyScope.READ, SafetyScope.ANNOTATE, SafetyScope.MODIFY}
)

QUICK_PROFILE_SCOPES: dict[str, frozenset[SafetyScope]] = {
    "read": frozenset({SafetyScope.READ}),
    "annotate": frozenset({SafetyScope.READ, SafetyScope.ANNOTATE}),
    "modify": DEFAULT_PROFILE_SCOPES,
}


def default_profile_enabled(name: str, policy_registry: ToolPolicyRegistry) -> bool:
    """Return whether *name* is enabled on a new install.

    The default profile is allow-all. Bounded subsets are the Read / Annotate /
    Modify quick profiles, not the first-run selection.
    """

    del name, policy_registry
    return True


def quick_profile_selection(
    profile_name: str,
    tools: Mapping[str, object],
    policy_registry: ToolPolicyRegistry,
) -> tuple[dict[str, bool], set[SafetyScope]]:
    """Return enabled tools and explicit scopes for a built-in quick profile."""

    normalized = str(profile_name).strip().lower()
    scopes = QUICK_PROFILE_SCOPES.get(normalized)
    if scopes is None:
        raise ValueError(
            f"Unknown quick profile '{profile_name}'. Choose read, annotate, or modify."
        )
    enabled = {
        name: name in CANONICAL_TOOLS and policy_registry.get(name).scopes <= scopes
        for name in tools
    }
    return enabled, set(scopes - {SafetyScope.READ})
