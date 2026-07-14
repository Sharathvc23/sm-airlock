"""Agent plugin sandbox.

An ``Airlock`` restricts a plugin's access to the host agent's public
surface. The allowlist of methods and properties the plugin may touch is
supplied by the caller, not hard-coded. Identity information (``agent_id``,
``did``, ``tenant_id``) is injected via an ``AgentIdentity`` Protocol
implementation so the Airlock never needs to know how the host agent
represents itself internally.

Effect staging is intentionally not part of the Airlock. Callers that need
speculative side-effect staging should compose with a separate staging
primitive (for example, the ``Enclave`` type in ``sm-enclave``).
"""

from __future__ import annotations

import logging
import threading
import time
from abc import ABC, abstractmethod
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .exceptions import AirlockViolation, PluginRateLimitExceeded
from .spec import AgentIdentity, AllowlistSpec

logger = logging.getLogger(__name__)


class PluginLoadError(Exception):
    """Raised when a plugin fails to load or validate."""

    def __init__(self, plugin_name: str, reason: str) -> None:
        self.plugin_name = plugin_name
        self.reason = reason
        super().__init__(f"Plugin '{plugin_name}' failed to load: {reason}")


class AgentPlugin(ABC):
    """Abstract base class for agent plugins.

    Plugins extend agent behaviour via lifecycle hooks. They receive a
    sandboxed ``Airlock`` reference and the tenant context string.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique plugin name (e.g. ``'my-plugin'``)."""
        ...

    @property
    @abstractmethod
    def version(self) -> str:
        """Semantic version string (e.g. ``'1.0.0'``)."""
        ...

    def on_load(self, agent: Any, tenant_id: str) -> None:  # noqa: B027
        """Called once when the plugin is registered with an agent.

        Args:
            agent: Sandboxed agent reference (public API only).
            tenant_id: Tenant context for isolation.
        """

    def on_bootstrap(self, agent: Any, tenant_id: str) -> None:  # noqa: B027
        """Called during agent bootstrap, after identity is available.

        Args:
            agent: Sandboxed agent reference.
            tenant_id: Tenant context.
        """

    def on_event(
        self,
        event_type: str,
        payload: dict[str, Any],
        *,
        tenant_id: str = "",
    ) -> dict[str, Any] | None:
        """Handle an event dispatched by the agent.

        Args:
            event_type: Event identifier.
            payload: Event data.
            tenant_id: Tenant context.

        Returns:
            Optional response dict, or ``None`` if not handled.
        """
        return None

    def capabilities(self) -> list[str]:
        """Return the extra capabilities this plugin provides."""
        return []

    def manifest(self) -> PluginManifest | None:
        """Return an attestation manifest for integrity verification.

        Returns ``None`` by default (unattested plugin). Override to provide
        a signed manifest where environments require plugin attestation.
        """
        return None


@dataclass(frozen=True)
class PluginManifest:
    """Attestation manifest for plugin integrity verification.

    When plugin attestation is required (via
    ``PluginRegistry.set_attestation_required``), plugins must provide a
    signed manifest. The manifest binds the plugin identity to a content
    hash, signed by the publisher's Ed25519 key.

    Attributes:
        plugin_name: Must match ``AgentPlugin.name``.
        version: Must match ``AgentPlugin.version``.
        content_hash: SHA-256 hex digest of plugin source.
        signer_did: DID of the plugin publisher.
        signature_b64: Base64-encoded Ed25519 signature over
            ``f"{plugin_name}|{version}|{content_hash}"``.
        signed_at: ISO 8601 timestamp of signing.
    """

    plugin_name: str
    version: str
    content_hash: str
    signer_did: str
    signature_b64: str
    signed_at: str


class Airlock:
    """Restricts plugin access to the host agent's public API surface.

    The ``Airlock`` is the agent-level capability boundary. Attribute
    access goes through an explicit allowlist; anything outside raises
    ``AirlockViolation`` and fires the violation callback.

    The allowlist and agent identity are both injected dependencies. The
    ``Airlock`` never inspects the host agent's private state.
    """

    def __init__(
        self,
        agent: Any,
        identity: AgentIdentity,
        allowlist: AllowlistSpec,
        *,
        plugin_name: str = "",
        violation_callback: Callable[[str, dict[str, Any]], None] | None = None,
    ) -> None:
        """Initialise the Airlock.

        Args:
            agent: The real agent instance the plugin will see through the
                sandbox.
            identity: Object implementing ``AgentIdentity``. Supplies
                ``agent_id``, ``did``, and ``tenant_id`` to plugins and
                violation callbacks.
            allowlist: ``AllowlistSpec`` describing permitted methods,
                properties, and per-method rate limits.
            plugin_name: Optional plugin name for audit logs and callback
                metadata.
            violation_callback: Optional callback ``fn(event_type, metadata)``
                fired when a plugin attempts out-of-allowlist access or
                exceeds a rate limit.
        """
        self._agent = agent
        self._identity = identity
        self._allowlist = allowlist
        self._plugin_name = plugin_name
        self._violation_callback = violation_callback

        self._call_timestamps: dict[str, deque[float]] = {}
        self._rate_limit_lock = threading.Lock()

    @property
    def tenant_id(self) -> str:
        return self._identity.tenant_id

    @property
    def agent_id(self) -> str:
        return self._identity.agent_id

    @property
    def did(self) -> str:
        return self._identity.did

    def __getattr__(self, name: str) -> Any:
        """Allowlist-based attribute access for plugins."""
        if name in self._allowlist.methods:
            method = getattr(self._agent, name, None)
            if method is None:
                return None

            def _rate_limited_wrapper(*args: Any, **kwargs: Any) -> Any:
                self._check_rate_limit(name)
                return method(*args, **kwargs)

            return _rate_limited_wrapper
        if name in self._allowlist.properties:
            return getattr(self._agent, name, None)
        self._report_violation(name)
        raise AirlockViolation(
            agent_did=self.did,
            attempted_operation=f"access '{name}'",
            sandbox_boundary="plugin sandbox",
        )

    def _report_violation(self, attr_name: str) -> None:
        """Report a sandbox violation via callback and logging.

        Does not raise — callers raise after this returns.
        """
        metadata: dict[str, Any] = {
            "attempted_attr": attr_name,
            "plugin_name": self._plugin_name,
            "tenant_id": self.tenant_id,
            "agent_did": self.did,
        }
        if self._violation_callback is not None:
            try:
                self._violation_callback("sandbox.violation", metadata)
            except Exception:
                logger.warning(
                    "Violation callback failed for attr=%s",
                    attr_name,
                    exc_info=True,
                )
        logger.warning(
            "Airlock violation: plugin=%s attempted access to '%s'",
            self._plugin_name,
            attr_name,
        )

    def _check_rate_limit(self, method: str) -> None:
        """Enforce the per-method rate limit configured on the allowlist.

        Raises:
            PluginRateLimitExceeded: If the method has been called too many
                times within the current 60-second window.
        """
        limit = self._allowlist.rate_limit_for(method)
        if limit is None:
            return

        with self._rate_limit_lock:
            now = time.monotonic()
            cutoff = now - 60.0
            timestamps = self._call_timestamps.setdefault(method, deque())
            # Prune entries older than 60 seconds. deque.popleft is O(1).
            while timestamps and timestamps[0] <= cutoff:
                timestamps.popleft()

            if len(timestamps) >= limit:
                self._report_violation(method)
                raise PluginRateLimitExceeded(self._plugin_name, method, limit)
            timestamps.append(now)


class PluginRegistry:
    """Thread-safe registry for agent plugins.

    Validates plugin names, prevents duplicates, and provides ordered
    iteration for lifecycle dispatch. Optionally enforces plugin
    attestation via Ed25519-signed manifests.
    """

    def __init__(self) -> None:
        self._plugins: dict[str, AgentPlugin] = {}
        self._lock = threading.Lock()
        self._attestation_required = False

    def set_attestation_required(self, required: bool) -> None:
        """Enable or disable mandatory plugin attestation.

        When enabled, plugins must provide a valid ``PluginManifest`` via
        their ``manifest()`` method during registration.
        """
        self._attestation_required = required

    def register(self, plugin: AgentPlugin) -> None:
        """Register a plugin.

        Raises:
            PluginLoadError: If validation fails or the name already exists.
        """
        if not isinstance(plugin, AgentPlugin):
            raise PluginLoadError(
                str(type(plugin).__name__),
                "must be an AgentPlugin subclass",
            )
        name = plugin.name
        if not name or not name.strip():
            raise PluginLoadError("(unnamed)", "plugin name must be non-empty")

        manifest = plugin.manifest()
        if self._attestation_required and manifest is None:
            raise PluginLoadError(
                name,
                "attestation manifest required but not provided",
            )
        if manifest is not None:
            if manifest.plugin_name != name:
                raise PluginLoadError(
                    name,
                    f"manifest name mismatch: '{manifest.plugin_name}' != '{name}'",
                )
            if manifest.version != plugin.version:
                raise PluginLoadError(
                    name,
                    f"manifest version mismatch: "
                    f"'{manifest.version}' != '{plugin.version}'",
                )

        with self._lock:
            if name in self._plugins:
                raise PluginLoadError(name, f"plugin '{name}' already registered")
            self._plugins[name] = plugin
        logger.info("Plugin registered: %s v%s", name, plugin.version)

    def unregister(self, name: str) -> bool:
        """Remove a plugin by name.

        Returns:
            ``True`` if the plugin was found and removed.
        """
        with self._lock:
            if name in self._plugins:
                del self._plugins[name]
                logger.info("Plugin unregistered: %s", name)
                return True
        return False

    def get_plugins(self) -> list[AgentPlugin]:
        """Return all registered plugins in registration order."""
        with self._lock:
            return list(self._plugins.values())

    def get_plugin(self, name: str) -> AgentPlugin | None:
        """Get a specific plugin by name."""
        with self._lock:
            return self._plugins.get(name)

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._plugins)

    def clear(self) -> None:
        """Remove all plugins. For test isolation."""
        with self._lock:
            self._plugins.clear()


__all__ = [
    "AgentPlugin",
    "Airlock",
    "PluginLoadError",
    "PluginManifest",
    "PluginRegistry",
]
