"""Tests for the AgentPlugin ABC, PluginRegistry, and PluginManifest."""

from __future__ import annotations

import threading
from dataclasses import FrozenInstanceError
from typing import Any

import pytest

from sm_airlock import (
    AgentPlugin,
    PluginLoadError,
    PluginManifest,
    PluginRegistry,
)

# ---------------------------------------------------------------------------
# Test plugins
# ---------------------------------------------------------------------------


class _BasicPlugin(AgentPlugin):
    @property
    def name(self) -> str:
        return "basic"

    @property
    def version(self) -> str:
        return "1.0.0"


class _EmptyNamePlugin(AgentPlugin):
    @property
    def name(self) -> str:
        return ""

    @property
    def version(self) -> str:
        return "1.0.0"


class _WhitespaceNamePlugin(AgentPlugin):
    @property
    def name(self) -> str:
        return "   "

    @property
    def version(self) -> str:
        return "1.0.0"


def _manifest(name: str = "signed", version: str = "1.0.0") -> PluginManifest:
    return PluginManifest(
        plugin_name=name,
        version=version,
        content_hash="a" * 64,
        signer_did="did:web:publisher.example",
        signature_b64="ZmFrZS1zaWc=",
        signed_at="2026-04-17T00:00:00Z",
    )


class _SignedPlugin(AgentPlugin):
    @property
    def name(self) -> str:
        return "signed"

    @property
    def version(self) -> str:
        return "1.0.0"

    def manifest(self) -> PluginManifest | None:
        return _manifest()


# ---------------------------------------------------------------------------
# AgentPlugin ABC
# ---------------------------------------------------------------------------


class TestAgentPluginABC:
    def test_cannot_instantiate_abstract(self) -> None:
        with pytest.raises(TypeError):
            AgentPlugin()  # type: ignore[abstract]

    def test_subclass_must_provide_name_and_version(self) -> None:
        class Missing(AgentPlugin):
            @property
            def name(self) -> str:
                return "x"

            # version not provided

        with pytest.raises(TypeError):
            Missing()  # type: ignore[abstract]

    def test_default_lifecycle_hooks_do_nothing(self) -> None:
        plugin = _BasicPlugin()
        plugin.on_load(object(), "tenant-1")
        plugin.on_bootstrap(object(), "tenant-1")

    def test_default_on_event_returns_none(self) -> None:
        plugin = _BasicPlugin()
        assert plugin.on_event("x", {}) is None

    def test_default_capabilities_is_empty_list(self) -> None:
        plugin = _BasicPlugin()
        assert plugin.capabilities() == []

    def test_default_manifest_returns_none(self) -> None:
        plugin = _BasicPlugin()
        assert plugin.manifest() is None


# ---------------------------------------------------------------------------
# PluginRegistry basics
# ---------------------------------------------------------------------------


class TestRegistryBasics:
    def test_register_and_retrieve(self) -> None:
        registry = PluginRegistry()
        plugin = _BasicPlugin()
        registry.register(plugin)
        assert registry.count == 1
        assert registry.get_plugin("basic") is plugin

    def test_register_rejects_non_plugin(self) -> None:
        registry = PluginRegistry()
        with pytest.raises(PluginLoadError):
            registry.register("not-a-plugin")  # type: ignore[arg-type]
        with pytest.raises(PluginLoadError):
            registry.register({})  # type: ignore[arg-type]
        with pytest.raises(PluginLoadError):
            registry.register(None)  # type: ignore[arg-type]

    def test_register_rejects_empty_name(self) -> None:
        registry = PluginRegistry()
        with pytest.raises(PluginLoadError):
            registry.register(_EmptyNamePlugin())

    def test_register_rejects_whitespace_name(self) -> None:
        registry = PluginRegistry()
        with pytest.raises(PluginLoadError):
            registry.register(_WhitespaceNamePlugin())

    def test_duplicate_registration_rejected(self) -> None:
        registry = PluginRegistry()
        registry.register(_BasicPlugin())
        with pytest.raises(PluginLoadError):
            registry.register(_BasicPlugin())

    def test_unregister_returns_true_when_found(self) -> None:
        registry = PluginRegistry()
        registry.register(_BasicPlugin())
        assert registry.unregister("basic") is True
        assert registry.count == 0

    def test_unregister_returns_false_when_missing(self) -> None:
        registry = PluginRegistry()
        assert registry.unregister("missing") is False

    def test_get_plugin_returns_none_when_missing(self) -> None:
        registry = PluginRegistry()
        assert registry.get_plugin("missing") is None

    def test_get_plugins_returns_registration_order(self) -> None:
        class _Second(AgentPlugin):
            @property
            def name(self) -> str:
                return "second"

            @property
            def version(self) -> str:
                return "1.0.0"

        registry = PluginRegistry()
        first = _BasicPlugin()
        second = _Second()
        registry.register(first)
        registry.register(second)
        assert registry.get_plugins() == [first, second]

    def test_clear_empties_registry(self) -> None:
        registry = PluginRegistry()
        registry.register(_BasicPlugin())
        registry.clear()
        assert registry.count == 0


# ---------------------------------------------------------------------------
# PluginManifest
# ---------------------------------------------------------------------------


class TestPluginManifest:
    def test_manifest_is_frozen(self) -> None:
        manifest = _manifest()
        with pytest.raises(FrozenInstanceError):
            manifest.plugin_name = "other"  # type: ignore[misc]

    def test_manifest_fields_are_preserved(self) -> None:
        manifest = _manifest(name="foo", version="2.1.0")
        assert manifest.plugin_name == "foo"
        assert manifest.version == "2.1.0"
        assert manifest.content_hash == "a" * 64
        assert manifest.signer_did == "did:web:publisher.example"
        assert manifest.signature_b64 == "ZmFrZS1zaWc="
        assert manifest.signed_at == "2026-04-17T00:00:00Z"


# ---------------------------------------------------------------------------
# Attestation enforcement
# ---------------------------------------------------------------------------


class TestAttestation:
    def test_signed_plugin_registers_without_attestation_required(self) -> None:
        registry = PluginRegistry()
        registry.register(_SignedPlugin())
        assert registry.count == 1

    def test_unsigned_plugin_rejected_when_attestation_required(self) -> None:
        registry = PluginRegistry()
        registry.set_attestation_required(True)
        with pytest.raises(PluginLoadError) as excinfo:
            registry.register(_BasicPlugin())
        assert "attestation" in str(excinfo.value).lower()

    def test_signed_plugin_passes_when_attestation_required(self) -> None:
        registry = PluginRegistry()
        registry.set_attestation_required(True)
        registry.register(_SignedPlugin())
        assert registry.count == 1

    def test_manifest_name_mismatch_rejected(self) -> None:
        class _Mismatch(AgentPlugin):
            @property
            def name(self) -> str:
                return "real-name"

            @property
            def version(self) -> str:
                return "1.0.0"

            def manifest(self) -> PluginManifest | None:
                return _manifest(name="different-name")

        registry = PluginRegistry()
        with pytest.raises(PluginLoadError) as excinfo:
            registry.register(_Mismatch())
        assert "name mismatch" in str(excinfo.value).lower()

    def test_manifest_version_mismatch_rejected(self) -> None:
        class _VersionMismatch(AgentPlugin):
            @property
            def name(self) -> str:
                return "vmismatch"

            @property
            def version(self) -> str:
                return "2.0.0"

            def manifest(self) -> PluginManifest | None:
                return _manifest(name="vmismatch", version="1.0.0")

        registry = PluginRegistry()
        with pytest.raises(PluginLoadError) as excinfo:
            registry.register(_VersionMismatch())
        assert "version mismatch" in str(excinfo.value).lower()


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestRegistryThreadSafety:
    def test_concurrent_registration_no_lost_entries(self) -> None:
        registry = PluginRegistry()

        def make_plugin(plugin_name: str) -> AgentPlugin:
            class _P(AgentPlugin):
                @property
                def name(self) -> str:
                    return plugin_name

                @property
                def version(self) -> str:
                    return "1.0.0"

            return _P()

        names = [f"plugin-{i}" for i in range(50)]

        def worker(idx: int) -> None:
            registry.register(make_plugin(names[idx]))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert registry.count == 50
        for n in names:
            assert registry.get_plugin(n) is not None

    def test_concurrent_duplicate_registration_raises_for_some(self) -> None:
        """If multiple threads register the same name, exactly one succeeds."""
        registry = PluginRegistry()

        successes = 0
        rejections = 0
        lock = threading.Lock()

        def worker() -> None:
            nonlocal successes, rejections
            try:
                registry.register(_BasicPlugin())
            except PluginLoadError:
                with lock:
                    rejections += 1
            else:
                with lock:
                    successes += 1

        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert successes == 1
        assert rejections == 19
        assert registry.count == 1


# ---------------------------------------------------------------------------
# PluginLoadError attributes
# ---------------------------------------------------------------------------


class TestPluginLoadError:
    def test_exposes_plugin_name_and_reason(self) -> None:
        err = PluginLoadError("my-plugin", "bad stuff happened")
        assert err.plugin_name == "my-plugin"
        assert err.reason == "bad stuff happened"
        assert "my-plugin" in str(err)
        assert "bad stuff happened" in str(err)


# ---------------------------------------------------------------------------
# Plugin lifecycle hooks
# ---------------------------------------------------------------------------


class TestLifecycleHooks:
    def test_on_event_can_be_overridden(self) -> None:
        class _Responder(AgentPlugin):
            @property
            def name(self) -> str:
                return "responder"

            @property
            def version(self) -> str:
                return "1.0.0"

            def on_event(
                self,
                event_type: str,
                payload: dict[str, Any],
                *,
                tenant_id: str = "",
            ) -> dict[str, Any] | None:
                return {"echoed": event_type, "from": tenant_id}

        result = _Responder().on_event("x", {"k": "v"}, tenant_id="t")
        assert result == {"echoed": "x", "from": "t"}

    def test_capabilities_can_be_overridden(self) -> None:
        class _Capable(AgentPlugin):
            @property
            def name(self) -> str:
                return "capable"

            @property
            def version(self) -> str:
                return "1.0.0"

            def capabilities(self) -> list[str]:
                return ["metrics.collect", "health.check"]

        assert _Capable().capabilities() == ["metrics.collect", "health.check"]
