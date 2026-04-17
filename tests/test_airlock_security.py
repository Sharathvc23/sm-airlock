"""Security tests for the Airlock — allowlist, identity, rate limiting."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any

import pytest

from sm_airlock import (
    Airlock,
    AirlockViolation,
    AllowlistSpec,
    NullIdentity,
    PluginRateLimitExceeded,
)


@dataclass(frozen=True)
class _Identity:
    agent_id: str = "agent-1"
    did: str = "did:web:example.com:agent-1"
    tenant_id: str = "tenant-1"


class _Agent:
    """Minimal host agent with a few methods and properties."""

    def __init__(self) -> None:
        self.name = "host"
        self.state = "running"
        self._private = "secret"

    def do_thing(self, x: int) -> int:
        return x * 2

    def get_status(self) -> str:
        return self.state

    def dangerous(self) -> None:  # pragma: no cover
        raise AssertionError("dangerous should never be called through airlock")


@pytest.fixture
def agent() -> _Agent:
    return _Agent()


@pytest.fixture
def identity() -> _Identity:
    return _Identity()


@pytest.fixture
def basic_allowlist() -> AllowlistSpec:
    return AllowlistSpec(
        methods=frozenset({"do_thing", "get_status"}),
        properties=frozenset({"name", "state"}),
        rate_limits={"*": 300},
    )


# ---------------------------------------------------------------------------
# Allowlist enforcement
# ---------------------------------------------------------------------------


class TestMethodAllowlist:
    def test_allowlisted_method_passes_through(
        self, agent: _Agent, identity: _Identity, basic_allowlist: AllowlistSpec
    ) -> None:
        airlock = Airlock(agent, identity, basic_allowlist)
        assert airlock.do_thing(5) == 10

    def test_non_allowlisted_method_raises(
        self, agent: _Agent, identity: _Identity, basic_allowlist: AllowlistSpec
    ) -> None:
        airlock = Airlock(agent, identity, basic_allowlist)
        with pytest.raises(AirlockViolation) as excinfo:
            airlock.dangerous()
        assert "dangerous" in str(excinfo.value)
        assert excinfo.value.agent_did == identity.did

    def test_missing_method_on_agent_returns_none(
        self, agent: _Agent, identity: _Identity
    ) -> None:
        allowlist = AllowlistSpec(methods=frozenset({"nonexistent"}))
        airlock = Airlock(agent, identity, allowlist)
        assert airlock.nonexistent is None

    def test_empty_allowlist_denies_everything(
        self, agent: _Agent, identity: _Identity
    ) -> None:
        airlock = Airlock(agent, identity, AllowlistSpec())
        with pytest.raises(AirlockViolation):
            airlock.do_thing(5)
        with pytest.raises(AirlockViolation):
            _ = airlock.name


class TestPropertyAllowlist:
    def test_allowlisted_property_is_readable(
        self, agent: _Agent, identity: _Identity, basic_allowlist: AllowlistSpec
    ) -> None:
        airlock = Airlock(agent, identity, basic_allowlist)
        assert airlock.name == "host"
        assert airlock.state == "running"

    def test_non_allowlisted_property_raises(
        self, agent: _Agent, identity: _Identity, basic_allowlist: AllowlistSpec
    ) -> None:
        airlock = Airlock(agent, identity, basic_allowlist)
        with pytest.raises(AirlockViolation):
            _ = airlock._private


# ---------------------------------------------------------------------------
# Identity injection
# ---------------------------------------------------------------------------


class TestIdentityInjection:
    def test_identity_properties_are_exposed(
        self, agent: _Agent, basic_allowlist: AllowlistSpec
    ) -> None:
        identity = _Identity(
            agent_id="custom-id",
            did="did:web:example:custom",
            tenant_id="custom-tenant",
        )
        airlock = Airlock(agent, identity, basic_allowlist)
        assert airlock.agent_id == "custom-id"
        assert airlock.did == "did:web:example:custom"
        assert airlock.tenant_id == "custom-tenant"

    def test_null_identity_returns_empty_strings(
        self, agent: _Agent, basic_allowlist: AllowlistSpec
    ) -> None:
        airlock = Airlock(agent, NullIdentity(), basic_allowlist)
        assert airlock.agent_id == ""
        assert airlock.did == ""
        assert airlock.tenant_id == ""

    def test_violation_uses_identity_did(
        self, agent: _Agent, basic_allowlist: AllowlistSpec
    ) -> None:
        identity = _Identity(did="did:web:specific")
        airlock = Airlock(agent, identity, basic_allowlist)
        with pytest.raises(AirlockViolation) as excinfo:
            airlock.dangerous()
        assert excinfo.value.agent_did == "did:web:specific"


# ---------------------------------------------------------------------------
# Violation callback
# ---------------------------------------------------------------------------


class TestViolationCallback:
    def test_callback_fires_on_violation(
        self, agent: _Agent, identity: _Identity, basic_allowlist: AllowlistSpec
    ) -> None:
        events: list[tuple[str, dict[str, Any]]] = []
        airlock = Airlock(
            agent,
            identity,
            basic_allowlist,
            plugin_name="my-plugin",
            violation_callback=lambda e, m: events.append((e, m)),
        )
        with pytest.raises(AirlockViolation):
            airlock.dangerous()

        assert len(events) == 1
        event_type, metadata = events[0]
        assert event_type == "sandbox.violation"
        assert metadata["attempted_attr"] == "dangerous"
        assert metadata["plugin_name"] == "my-plugin"
        assert metadata["tenant_id"] == identity.tenant_id
        assert metadata["agent_did"] == identity.did

    def test_callback_failure_does_not_crash_airlock(
        self, agent: _Agent, identity: _Identity, basic_allowlist: AllowlistSpec
    ) -> None:
        def bad_callback(event: str, metadata: dict[str, Any]) -> None:
            raise RuntimeError("callback exploded")

        airlock = Airlock(
            agent,
            identity,
            basic_allowlist,
            violation_callback=bad_callback,
        )
        # The AirlockViolation should still propagate, not the callback error.
        with pytest.raises(AirlockViolation):
            airlock.dangerous()


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


class TestRateLimiting:
    def test_within_limit_allows_all_calls(
        self, agent: _Agent, identity: _Identity
    ) -> None:
        allowlist = AllowlistSpec(
            methods=frozenset({"do_thing"}),
            rate_limits={"do_thing": 10},
        )
        airlock = Airlock(agent, identity, allowlist, plugin_name="p")
        for _ in range(10):
            airlock.do_thing(1)

    def test_over_limit_raises(self, agent: _Agent, identity: _Identity) -> None:
        allowlist = AllowlistSpec(
            methods=frozenset({"do_thing"}),
            rate_limits={"do_thing": 3},
        )
        airlock = Airlock(agent, identity, allowlist, plugin_name="p")
        for _ in range(3):
            airlock.do_thing(1)
        with pytest.raises(PluginRateLimitExceeded) as excinfo:
            airlock.do_thing(1)
        assert excinfo.value.method == "do_thing"
        assert excinfo.value.limit == 3

    def test_default_wildcard_applies_to_unlisted_methods(
        self, agent: _Agent, identity: _Identity
    ) -> None:
        allowlist = AllowlistSpec(
            methods=frozenset({"do_thing", "get_status"}),
            rate_limits={"*": 2},
        )
        airlock = Airlock(agent, identity, allowlist, plugin_name="p")
        airlock.do_thing(1)
        airlock.do_thing(1)
        with pytest.raises(PluginRateLimitExceeded):
            airlock.do_thing(1)
        # get_status has its own bucket.
        airlock.get_status()
        airlock.get_status()
        with pytest.raises(PluginRateLimitExceeded):
            airlock.get_status()

    def test_method_specific_limit_overrides_wildcard(
        self, agent: _Agent, identity: _Identity
    ) -> None:
        allowlist = AllowlistSpec(
            methods=frozenset({"do_thing"}),
            rate_limits={"*": 100, "do_thing": 2},
        )
        airlock = Airlock(agent, identity, allowlist, plugin_name="p")
        airlock.do_thing(1)
        airlock.do_thing(1)
        with pytest.raises(PluginRateLimitExceeded):
            airlock.do_thing(1)

    def test_no_rate_limit_when_neither_method_nor_wildcard_set(
        self, agent: _Agent, identity: _Identity
    ) -> None:
        allowlist = AllowlistSpec(
            methods=frozenset({"do_thing"}),
            rate_limits={},
        )
        airlock = Airlock(agent, identity, allowlist, plugin_name="p")
        for _ in range(1000):
            airlock.do_thing(1)

    def test_rate_limit_fires_violation_callback(
        self, agent: _Agent, identity: _Identity
    ) -> None:
        events: list[str] = []
        allowlist = AllowlistSpec(
            methods=frozenset({"do_thing"}),
            rate_limits={"do_thing": 1},
        )
        airlock = Airlock(
            agent,
            identity,
            allowlist,
            plugin_name="p",
            violation_callback=lambda e, m: events.append(m["attempted_attr"]),
        )
        airlock.do_thing(1)
        with pytest.raises(PluginRateLimitExceeded):
            airlock.do_thing(1)
        assert events == ["do_thing"]


class TestRateLimitThreadSafety:
    """Adversarial concurrency: many threads hammering the same method."""

    def test_concurrent_calls_respect_limit_exactly(
        self, agent: _Agent, identity: _Identity
    ) -> None:
        allowlist = AllowlistSpec(
            methods=frozenset({"do_thing"}),
            rate_limits={"do_thing": 500},
        )
        airlock = Airlock(agent, identity, allowlist, plugin_name="p")

        successes = 0
        rejections = 0
        counter_lock = threading.Lock()

        def worker() -> None:
            nonlocal successes, rejections
            for _ in range(100):
                try:
                    airlock.do_thing(1)
                except PluginRateLimitExceeded:
                    with counter_lock:
                        rejections += 1
                else:
                    with counter_lock:
                        successes += 1

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert successes == 500
        assert rejections == 300
        assert successes + rejections == 800
