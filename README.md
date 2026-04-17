# sm-airlock

Capability-gated plugin sandbox for autonomous agents.

## What It Does

- **Allowlist-based access control** — Plugins can only call the methods and properties you explicitly permit on the host agent. Everything else raises `AirlockViolation` and fires a violation callback.
- **Injected identity** — The Airlock does not inspect the host agent's internals. Pass an `AgentIdentity` implementation (`agent_id`, `did`, `tenant_id`) so plugins and audit callbacks see the values you choose to expose.
- **Per-method rate limiting** — Configure call caps through `AllowlistSpec.rate_limits`, a plain dict keyed by method name. The key `"*"` sets a default applied to any method without its own limit.
- **Plugin attestation** — Optional Ed25519-signed `PluginManifest` binds plugin identity to a content hash. `PluginRegistry.set_attestation_required(True)` makes attestation mandatory at registration time.
- **Thread-safe registry** — Register, unregister, and iterate plugins safely from multiple threads.
- **Zero runtime dependencies** — Standard library only. Python 3.10+.

## Install

```bash
pip install git+https://github.com/Sharathvc23/sm-airlock.git
```

## Quick Start

```python
from dataclasses import dataclass

from sm_airlock import (
    AgentPlugin, Airlock, AllowlistSpec, PluginManifest, PluginRegistry,
)


@dataclass(frozen=True)
class MyIdentity:
    agent_id: str
    did: str
    tenant_id: str


class MetricsPlugin(AgentPlugin):
    @property
    def name(self) -> str:
        return "metrics"

    @property
    def version(self) -> str:
        return "1.0.0"

    def on_load(self, agent, tenant_id: str) -> None:
        # agent is an Airlock — only allowlisted attributes are accessible
        print(f"Loaded for tenant {agent.tenant_id}")

    def capabilities(self) -> list[str]:
        return ["metrics.collect"]


allowlist = AllowlistSpec(
    methods=frozenset({"publish_fact", "status_snapshot"}),
    properties=frozenset({"agent_id", "did", "tenant_id"}),
    rate_limits={"publish_fact": 30, "*": 300},
)

airlock = Airlock(
    agent=real_agent,
    identity=MyIdentity(agent_id="a1", did="did:web:x", tenant_id="t1"),
    allowlist=allowlist,
    plugin_name="metrics",
)

registry = PluginRegistry()
registry.register(MetricsPlugin())
```

## Plugin Attestation (optional)

```python
registry = PluginRegistry()
registry.set_attestation_required(True)

class SignedPlugin(AgentPlugin):
    @property
    def name(self) -> str:
        return "signed"

    @property
    def version(self) -> str:
        return "1.0.0"

    def manifest(self) -> PluginManifest | None:
        return PluginManifest(
            plugin_name="signed",
            version="1.0.0",
            content_hash="...",
            signer_did="did:web:publisher.example",
            signature_b64="...",
            signed_at="2026-04-17T00:00:00Z",
        )

registry.register(SignedPlugin())  # passes
```

## Effect Staging

`sm-airlock` does not stage side effects. For speculative execution with staged commit/discard semantics, use [`sm-enclave`](https://github.com/Sharathvc23/sm-enclave).

## Related Packages

| Package | Purpose |
|---------|---------|
| [sm-bridge](https://github.com/Sharathvc23/sm-bridge) | NANDA-compatible registry endpoints, AgentFacts, and delta sync |
| [sm-enclave](https://github.com/Sharathvc23/sm-enclave) | Speculative execution sandbox with staged side effects |
| [sm-locp](https://github.com/Sharathvc23/sm-locp) | Open Compliance Protocol — defeasible logic and W3C Verifiable Credentials |
| [sm-model-card](https://github.com/Sharathvc23/sm-model-card) | Unified model card schema for agent registries |
| [sm-model-provenance](https://github.com/Sharathvc23/sm-model-provenance) | Model identity and provenance metadata |
| [sm-model-integrity-layer](https://github.com/Sharathvc23/sm-model-integrity-layer) | Cryptographic integrity verification for model artifacts |
| [sm-model-governance](https://github.com/Sharathvc23/sm-model-governance) | Three-plane ML governance with Ed25519 signatures |

## License

MIT

---

*First published: 2026-04-15 | Last modified: 2026-04-17*

*Personal research contributions aligned with [Project NANDA](https://projectnanda.org) standards. [Stellarminds.ai](https://stellarminds.ai)*
