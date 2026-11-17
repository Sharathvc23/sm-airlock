"""Agent plugin sandbox.

An ``Airlock`` restricts a plugin's access to the host agent's public
surface. The allowlist of methods and properties the plugin may touch is
supplied by the caller, not hard-coded. Identity information (``agent_id``,
``did``, ``tenant_id``) is injected via an ``AgentIdentity`` Protocol
implementation so the Airlock never needs to know how the host agent
represents itself internally.

The ``Airlock`` filters attribute access on the proxy object it hands to
plugins. It is not an isolation boundary: plugin code shares the host's
interpreter, so introspection such as ``object.__getattribute__``, the
``gc`` module or frame objects can still reach the host agent. See the
``Airlock`` class docstring for details.

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
from typing import Any, NoReturn

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


#: Names served by the ``Airlock`` itself rather than through the allowlist.
_OWN_ATTRIBUTES = frozenset({"agent_id", "did", "tenant_id"})


class _AirlockState:
    """Internal state of one ``Airlock``. Never handed to plugins."""

    __slots__ = (
        "agent",
        "allowlist",
        "call_timestamps",
        "identity",
        "plugin_name",
        "rate_limit_lock",
        "violation_callback",
    )

    def __init__(
        self,
        agent: Any,
        identity: AgentIdentity,
        allowlist: AllowlistSpec,
        plugin_name: str,
        violation_callback: Callable[[str, dict[str, Any]], None] | None,
    ) -> None:
        self.agent = agent
        self.identity = identity
        self.allowlist = allowlist
        self.plugin_name = plugin_name
        self.violation_callback = violation_callback
        self.call_timestamps: dict[str, deque[float]] = {}
        self.rate_limit_lock = threading.Lock()

    def resolve(self, name: str) -> Any:
        """Return the allowlisted member ``name`` or refuse the access."""
        if name in self.allowlist.methods:
            target = getattr(self.agent, name, None)
            if target is None:
                return None
            return _GatedMethod(self, name, target)
        if name in self.allowlist.properties:
            return getattr(self.agent, name, None)
        self.deny(name)

    def deny(self, attr_name: str, operation: str = "access") -> NoReturn:
        """Report a violation and raise ``AirlockViolation``."""
        self.report_violation(attr_name)
        raise AirlockViolation(
            agent_did=self.identity.did,
            attempted_operation=f"{operation} '{attr_name}'",
            sandbox_boundary="plugin sandbox",
        )

    def report_violation(self, attr_name: str) -> None:
        """Report a sandbox violation via callback and logging.

        Does not raise — callers raise after this returns.
        """
        metadata: dict[str, Any] = {
            "attempted_attr": attr_name,
            "plugin_name": self.plugin_name,
            "tenant_id": self.identity.tenant_id,
            "agent_did": self.identity.did,
        }
        if self.violation_callback is not None:
            try:
                self.violation_callback("sandbox.violation", metadata)
            except Exception:
                logger.warning(
                    "Violation callback failed for attr=%s",
                    attr_name,
                    exc_info=True,
                )
        logger.warning(
            "Airlock violation: plugin=%s attempted access to '%s'",
            self.plugin_name,
            attr_name,
        )

    def check_rate_limit(self, method: str) -> None:
        """Enforce the per-method rate limit configured on the allowlist.

        Raises:
            PluginRateLimitExceeded: If the method has been called too many
                times within the current 60-second window.
        """
        limit = self.allowlist.rate_limit_for(method)
        if limit is None:
            return

        with self.rate_limit_lock:
            now = time.monotonic()
            cutoff = now - 60.0
            timestamps = self.call_timestamps.setdefault(method, deque())
            # Prune entries older than 60 seconds. deque.popleft is O(1).
            while timestamps and timestamps[0] <= cutoff:
                timestamps.popleft()

            if len(timestamps) >= limit:
                self.report_violation(method)
                raise PluginRateLimitExceeded(self.plugin_name, method, limit)
            timestamps.append(now)


class _GatedMethod:
    """Callable returned for an allowlisted method.

    Calling it applies the rate limit and forwards to the host agent's
    method. Unlike a plain closure or bound method, it does not expose the
    host agent through ``__self__``, ``__closure__``, ``__func__`` or
    similar attributes: attribute access other than ``__name__`` and
    ``__class__`` is refused.
    """

    __slots__ = ("_name", "_state", "_target")

    def __init__(self, state: _AirlockState, name: str, target: Any) -> None:
        object.__setattr__(self, "_state", state)
        object.__setattr__(self, "_name", name)
        object.__setattr__(self, "_target", target)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        state: _AirlockState = object.__getattribute__(self, "_state")
        state.check_rate_limit(object.__getattribute__(self, "_name"))
        return object.__getattribute__(self, "_target")(*args, **kwargs)

    def __getattribute__(self, attr: str) -> Any:
        if attr == "__class__":
            return object.__getattribute__(self, attr)
        name: str = object.__getattribute__(self, "_name")
        if attr == "__name__":
            return name
        state: _AirlockState = object.__getattribute__(self, "_state")
        state.deny(f"{name}.{attr}")

    def __setattr__(self, attr: str, value: Any) -> None:
        state: _AirlockState = object.__getattribute__(self, "_state")
        state.deny(f"{object.__getattribute__(self, '_name')}.{attr}", "set")

    def __delattr__(self, attr: str) -> None:
        state: _AirlockState = object.__getattribute__(self, "_state")
        state.deny(f"{object.__getattribute__(self, '_name')}.{attr}", "delete")

    def __repr__(self) -> str:
        return f"<airlock method {object.__getattribute__(self, '_name')!r}>"


def _state_of(airlock: Airlock) -> _AirlockState:
    state: _AirlockState = object.__getattribute__(airlock, "_state")
    return state


class Airlock:
    """Restricts plugin access to the host agent's public API surface.

    Attribute access on the ``Airlock`` goes through an explicit allowlist;
    anything outside it raises ``AirlockViolation`` and fires the violation
    callback. Besides the allowlisted members, the ``Airlock`` serves only
    ``agent_id``, ``did`` and ``tenant_id`` (from the injected identity) and
    ``__class__``. Its own state, including the reference to the host agent,
    is not readable through attribute access: ``airlock._agent``,
    ``airlock.__dict__``, ``vars(airlock)``, ``copy``/``pickle`` hooks, and
    the ``__self__``/``__closure__`` of returned methods are all refused.
    Setting or deleting attributes on the ``Airlock`` is refused as well.

    Limits: this is an in-process attribute filter, not an isolation
    boundary. Plugin code runs in the same interpreter as the host and can
    still reach the host agent by interpreter-level means, for example
    ``object.__getattribute__(airlock, "_state")``, descriptors on
    ``type(airlock)``, the ``gc`` module, or frame objects
    (``sys._getframe()``, exception tracebacks). Values returned by
    allowlisted methods and properties are passed through unchanged, so an
    allowlisted member that returns the agent, or an object that references
    it, gives the plugin that reference. Code that must not reach the host
    agent has to run in a separate process.

    The allowlist and agent identity are both injected dependencies. The
    ``Airlock`` never inspects the host agent's private state.
    """

    __slots__ = ("__weakref__", "_state")

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
        object.__setattr__(
            self,
            "_state",
            _AirlockState(agent, identity, allowlist, plugin_name, violation_callback),
        )

    @property
    def tenant_id(self) -> str:
        return _state_of(self).identity.tenant_id

    @property
    def agent_id(self) -> str:
        return _state_of(self).identity.agent_id

    @property
    def did(self) -> str:
        return _state_of(self).identity.did

    def __getattribute__(self, name: str) -> Any:
        """Allowlist-based attribute access for plugins.

        Runs for every attribute lookup on the instance, so names defined
        on the ``Airlock`` itself (its state, methods, ``__dict__`` and so
        on) are refused like any other name outside the allowlist.
        """
        if name in _OWN_ATTRIBUTES or name == "__class__":
            return object.__getattribute__(self, name)
        return _state_of(self).resolve(name)

    def __setattr__(self, name: str, value: Any) -> None:
        _state_of(self).deny(name, "set")

    def __delattr__(self, name: str) -> None:
        _state_of(self).deny(name, "delete")

    def __dir__(self) -> list[str]:
        allowlist = _state_of(self).allowlist
        return sorted(_OWN_ATTRIBUTES | allowlist.methods | allowlist.properties)

    def __repr__(self) -> str:
        return f"<Airlock plugin={_state_of(self).plugin_name!r}>"


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
