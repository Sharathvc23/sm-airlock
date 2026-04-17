"""Allowlist specification and identity Protocol for the Airlock.

The Airlock does not ship with a default allowlist or a hard-coded way to
read agent identity. Callers describe the plugin's permitted surface via
``AllowlistSpec`` and provide an ``AgentIdentity`` (or use ``NullIdentity``
when they do not care about identity in their host system).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

#: Special rate-limit key meaning "applies to any method not listed explicitly".
DEFAULT_RATE_LIMIT_KEY = "*"


@dataclass(frozen=True)
class AllowlistSpec:
    """Declares what a plugin is allowed to call on the host agent.

    Attributes:
        methods: Names of methods the plugin may invoke. Anything else raises
            ``AirlockViolation``.
        properties: Names of properties the plugin may read. Anything else
            raises ``AirlockViolation``.
        rate_limits: Per-method call caps measured over a 60-second window.
            Keyed by method name. The special key ``"*"`` sets the default
            limit applied to any method not listed explicitly. If ``"*"`` is
            absent and a method has no entry, no rate limit is enforced for
            that method.
    """

    methods: frozenset[str] = field(default_factory=frozenset)
    properties: frozenset[str] = field(default_factory=frozenset)
    rate_limits: dict[str, int] = field(default_factory=dict)

    def rate_limit_for(self, method: str) -> int | None:
        """Return the limit for ``method`` or ``None`` if no limit applies.

        Looks up the method name first; falls back to the ``"*"`` default
        key; returns ``None`` if neither is set.
        """
        if method in self.rate_limits:
            return self.rate_limits[method]
        return self.rate_limits.get(DEFAULT_RATE_LIMIT_KEY)


@runtime_checkable
class AgentIdentity(Protocol):
    """Structural Protocol for agent identity information.

    Any object with ``agent_id``, ``did``, and ``tenant_id`` read-only
    properties satisfies this Protocol. The Airlock surfaces these values
    to plugins and violation callbacks without reaching into the host
    agent's internals.
    """

    @property
    def agent_id(self) -> str: ...

    @property
    def did(self) -> str: ...

    @property
    def tenant_id(self) -> str: ...


@dataclass(frozen=True)
class NullIdentity:
    """Default identity that exposes empty strings.

    Use this when the host system does not need to surface agent identity
    to plugins (or when the three fields are not meaningful in the caller's
    domain). Violation callbacks will receive empty strings for the
    corresponding fields.
    """

    agent_id: str = ""
    did: str = ""
    tenant_id: str = ""


__all__ = [
    "DEFAULT_RATE_LIMIT_KEY",
    "AgentIdentity",
    "AllowlistSpec",
    "NullIdentity",
]
