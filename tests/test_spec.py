"""Tests for ``sm_airlock.spec``."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from sm_airlock.spec import (
    DEFAULT_RATE_LIMIT_KEY,
    AgentIdentity,
    AllowlistSpec,
    NullIdentity,
)


class TestAllowlistSpec:
    def test_defaults_are_empty(self) -> None:
        spec = AllowlistSpec()
        assert spec.methods == frozenset()
        assert spec.properties == frozenset()
        assert spec.rate_limits == {}

    def test_frozen_dataclass_rejects_mutation(self) -> None:
        spec = AllowlistSpec(methods=frozenset({"a"}))
        with pytest.raises(FrozenInstanceError):
            spec.methods = frozenset({"b"})  # type: ignore[misc]

    def test_rate_limit_for_explicit_method(self) -> None:
        spec = AllowlistSpec(rate_limits={"ping": 30})
        assert spec.rate_limit_for("ping") == 30

    def test_rate_limit_for_falls_back_to_default_key(self) -> None:
        spec = AllowlistSpec(rate_limits={"*": 60, "ping": 30})
        assert spec.rate_limit_for("unknown") == 60
        assert spec.rate_limit_for("ping") == 30

    def test_rate_limit_for_returns_none_when_absent(self) -> None:
        spec = AllowlistSpec(rate_limits={})
        assert spec.rate_limit_for("anything") is None

    def test_rate_limit_for_returns_none_when_only_other_methods_listed(self) -> None:
        spec = AllowlistSpec(rate_limits={"ping": 30})
        assert spec.rate_limit_for("pong") is None

    def test_default_rate_limit_key_is_star(self) -> None:
        assert DEFAULT_RATE_LIMIT_KEY == "*"

    def test_full_construction(self) -> None:
        spec = AllowlistSpec(
            methods=frozenset({"do_thing", "get_status"}),
            properties=frozenset({"name", "state"}),
            rate_limits={"do_thing": 30, "*": 300},
        )
        assert "do_thing" in spec.methods
        assert "name" in spec.properties
        assert spec.rate_limit_for("do_thing") == 30
        assert spec.rate_limit_for("get_status") == 300


class TestNullIdentity:
    def test_all_empty_by_default(self) -> None:
        ident = NullIdentity()
        assert ident.agent_id == ""
        assert ident.did == ""
        assert ident.tenant_id == ""

    def test_satisfies_agent_identity_protocol(self) -> None:
        ident = NullIdentity()
        assert isinstance(ident, AgentIdentity)


class CustomIdentity:
    """A non-dataclass class that structurally satisfies AgentIdentity."""

    def __init__(self, agent_id: str, did: str, tenant_id: str) -> None:
        self._agent_id = agent_id
        self._did = did
        self._tenant_id = tenant_id

    @property
    def agent_id(self) -> str:
        return self._agent_id

    @property
    def did(self) -> str:
        return self._did

    @property
    def tenant_id(self) -> str:
        return self._tenant_id


class TestAgentIdentityProtocol:
    def test_structural_match_on_custom_class(self) -> None:
        ident = CustomIdentity(agent_id="a1", did="did:web:a", tenant_id="t1")
        assert isinstance(ident, AgentIdentity)

    def test_missing_attribute_fails_isinstance(self) -> None:
        class NotIdentity:
            @property
            def agent_id(self) -> str:
                return "x"

            # Missing did and tenant_id

        assert not isinstance(NotIdentity(), AgentIdentity)
