"""Airlock exceptions.

Defines the exception hierarchy for sandbox violations and rate limiting.
"""

from __future__ import annotations


class AgentError(Exception):
    """Base for agent framework errors."""

    def __init__(self, message: str) -> None:
        super().__init__(message)


class AirlockViolation(AgentError):
    """Agent attempted an operation outside its sandbox."""

    def __init__(
        self, agent_did: str, attempted_operation: str, sandbox_boundary: str
    ) -> None:
        self.agent_did = agent_did
        self.attempted_operation = attempted_operation
        self.sandbox_boundary = sandbox_boundary
        super().__init__(
            f"Agent {agent_did} sandbox violation: "
            f"'{attempted_operation}' outside boundary "
            f"'{sandbox_boundary}'"
        )


class PluginRateLimitExceeded(Exception):
    """Plugin exceeded its per-method rate limit."""

    def __init__(self, plugin_name: str, method: str, limit: int) -> None:
        self.plugin_name = plugin_name
        self.method = method
        self.limit = limit
        super().__init__(
            f"Plugin '{plugin_name}' exceeded rate limit for {method}: {limit}/min"
        )


__all__ = [
    "AgentError",
    "AirlockViolation",
    "PluginRateLimitExceeded",
]
