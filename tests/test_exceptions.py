"""Unit tests for airlock exceptions.

Step 1 — Assumption Audit:
- AgentError is the base class for agent framework errors
- AirlockViolation inherits from AgentError (not just Exception)
- PluginRateLimitExceeded inherits from Exception (NOT AgentError)
- All exceptions store context attributes (agent_did, operation, etc.)
- Exception messages include all relevant context for debugging

Step 2 — Gap Analysis:
- Exception messages must contain the agent DID, operation name, boundary
- PluginRateLimitExceeded must expose plugin_name, method, limit attrs
- AirlockViolation must be catchable as AgentError
- Empty strings in exception fields should not crash formatting

Step 3 — Break It List:
1. Create AirlockViolation with empty agent_did -> message still valid
2. Create PluginRateLimitExceeded with limit=0 -> message still valid
3. Catch AirlockViolation as Exception but not as PluginRateLimitExceeded
4. Verify str(error) includes ALL constructor arguments
"""

from __future__ import annotations

import pytest

from sm_airlock import AirlockViolation, PluginRateLimitExceeded
from sm_airlock.exceptions import AgentError


class TestAgentError:
    """Tests for base AgentError class."""

    def test_create_with_message(self) -> None:
        error = AgentError("Agent failure")
        assert str(error) == "Agent failure"

    def test_is_exception_subclass(self) -> None:
        assert issubclass(AgentError, Exception)


class TestAirlockViolation:
    """Tests for AirlockViolation (renamed from AgentSandboxViolation)."""

    def test_create_error(self) -> None:
        error = AirlockViolation(
            "did:nanda:003", "write /etc/passwd", "user-space only"
        )
        assert "did:nanda:003" in str(error)
        assert "write /etc/passwd" in str(error)
        assert "user-space only" in str(error)
        assert error.agent_did == "did:nanda:003"
        assert error.attempted_operation == "write /etc/passwd"
        assert error.sandbox_boundary == "user-space only"

    def test_message_format(self) -> None:
        error = AirlockViolation("did:x", "op", "boundary")
        assert "sandbox" in str(error).lower() or "violation" in str(error).lower()

    def test_is_agent_error_subclass(self) -> None:
        assert issubclass(AirlockViolation, AgentError)

    def test_can_be_caught_as_agent_error(self) -> None:
        with pytest.raises(AgentError):
            raise AirlockViolation("did:x", "op", "boundary")

    def test_can_be_caught_as_base_exception(self) -> None:
        error = AirlockViolation("did:x", "op", "boundary")
        assert isinstance(error, Exception)

    # -- Adversarial: exception messages contain relevant context ----------

    def test_message_contains_agent_did(self) -> None:
        """The string representation must include the agent DID."""
        agent_did = "did:nanda:adversarial-007"
        error = AirlockViolation(agent_did, "read_secrets", "plugin sandbox")
        assert agent_did in str(error)

    def test_message_contains_operation_name(self) -> None:
        """The string representation must include the attempted operation."""
        operation = "access '_private_key_b64'"
        error = AirlockViolation("did:x", operation, "sandbox")
        assert operation in str(error)

    def test_message_contains_sandbox_boundary(self) -> None:
        """The string representation must include the sandbox boundary."""
        boundary = "plugin sandbox"
        error = AirlockViolation("did:x", "op", boundary)
        assert boundary in str(error)

    def test_inheritance_chain_complete(self) -> None:
        """AirlockViolation -> AgentError -> Exception."""
        error = AirlockViolation("did:x", "op", "boundary")
        assert isinstance(error, AirlockViolation)
        assert isinstance(error, AgentError)
        assert isinstance(error, Exception)
        # Must NOT be catchable as PluginRateLimitExceeded
        assert not isinstance(error, PluginRateLimitExceeded)

    def test_empty_fields_do_not_crash(self) -> None:
        """Empty strings for all fields should not raise during construction."""
        error = AirlockViolation("", "", "")
        assert error.agent_did == ""
        assert error.attempted_operation == ""
        assert error.sandbox_boundary == ""
        # str() must not crash
        assert isinstance(str(error), str)


class TestPluginRateLimitExceeded:
    """Tests for PluginRateLimitExceeded."""

    def test_create_error(self) -> None:
        error = PluginRateLimitExceeded("my-plugin", "publish_fact", 60)
        assert "my-plugin" in str(error)
        assert "publish_fact" in str(error)
        assert "60" in str(error)
        assert error.plugin_name == "my-plugin"
        assert error.method == "publish_fact"
        assert error.limit == 60

    def test_is_exception_subclass(self) -> None:
        assert issubclass(PluginRateLimitExceeded, Exception)

    def test_not_agent_error_subclass(self) -> None:
        """PluginRateLimitExceeded inherits from Exception, not AgentError."""
        assert not issubclass(PluginRateLimitExceeded, AgentError)

    # -- Adversarial: verify attributes are accessible ---------------------

    def test_has_plugin_name_attribute(self) -> None:
        """PluginRateLimitExceeded must expose plugin_name."""
        error = PluginRateLimitExceeded("test-plugin", "record_trail_event", 120)
        assert error.plugin_name == "test-plugin"

    def test_has_method_attribute(self) -> None:
        """PluginRateLimitExceeded must expose method."""
        error = PluginRateLimitExceeded("test-plugin", "record_trail_event", 120)
        assert error.method == "record_trail_event"

    def test_has_limit_attribute(self) -> None:
        """PluginRateLimitExceeded must expose limit."""
        error = PluginRateLimitExceeded("test-plugin", "record_trail_event", 120)
        assert error.limit == 120

    def test_limit_zero_does_not_crash(self) -> None:
        """Limit of 0 is valid and must not crash message formatting."""
        error = PluginRateLimitExceeded("p", "m", 0)
        assert error.limit == 0
        assert "0" in str(error)

    def test_message_contains_all_constructor_args(self) -> None:
        """String representation must include plugin_name, method, and limit."""
        plugin_name = "carbon-monitor"
        method = "publish_fact"
        limit = 42
        error = PluginRateLimitExceeded(plugin_name, method, limit)
        msg = str(error)
        assert plugin_name in msg
        assert method in msg
        assert str(limit) in msg
