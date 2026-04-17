"""sm-airlock: capability-gated plugin sandbox for autonomous agents."""

from .airlock import (
    AgentPlugin,
    Airlock,
    PluginLoadError,
    PluginManifest,
    PluginRegistry,
)
from .exceptions import AirlockViolation, PluginRateLimitExceeded
from .spec import (
    DEFAULT_RATE_LIMIT_KEY,
    AgentIdentity,
    AllowlistSpec,
    NullIdentity,
)

__version__ = "0.2.0"

__all__ = [
    "DEFAULT_RATE_LIMIT_KEY",
    "AgentIdentity",
    "AgentPlugin",
    "Airlock",
    "AirlockViolation",
    "AllowlistSpec",
    "NullIdentity",
    "PluginLoadError",
    "PluginManifest",
    "PluginRateLimitExceeded",
    "PluginRegistry",
]
