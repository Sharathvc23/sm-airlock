# sm-airlock: Capability-Gated Plugin Sandbox for Autonomous Agents

## Abstract

In autonomous agent systems, plugins extend agent behavior at runtime.
Without a principled isolation boundary, any plugin can access private
state, bypass tenant isolation, or flood the host with unbounded API
calls. sm-airlock provides an allowlist-based sandbox that restricts
plugin access to a caller-defined set of methods and properties, audits
violations, enforces per-method rate limits, and supports Ed25519-signed
plugin attestation.

## Problem

Agent plugin systems face a fundamental tension: plugins must interact
with the host agent to be useful, but unrestricted access creates
security and reliability risks.

Common failure modes:

1. **State leakage** — A plugin reads private keys, internal registries,
   or other tenants' data through unrestricted attribute access.
2. **Tenant isolation bypass** — A plugin operating under tenant A
   accesses resources belonging to tenant B via a shared agent instance.
3. **Resource exhaustion** — A misbehaving plugin floods the host with
   calls, degrading service for other tenants.
4. **Silent side effects** — A plugin mutates agent state without the
   host's knowledge, breaking auditability.
5. **Supply chain attacks** — A compromised plugin binary runs unverified
   code inside the agent process.

Blocklist approaches (deny specific attributes) fail because they
require anticipating every dangerous attribute. The safe default is to
deny everything and explicitly permit only what plugins need.

## What It Does

sm-airlock interposes an `Airlock` proxy between the plugin and the host
agent. The Airlock:

- **Allows** access to a caller-supplied set of methods and properties
  defined in an `AllowlistSpec`.
- **Denies** everything else, raising `AirlockViolation` with full
  context for audit integration.
- **Rate-limits** each method independently using a sliding 60-second
  window; limits are configured via a dict on `AllowlistSpec`.
- **Surfaces identity** (`agent_id`, `did`, `tenant_id`) through an
  injected `AgentIdentity` Protocol implementation. The Airlock never
  reads the host agent's private state.
- **Verifies** plugin integrity via optional Ed25519-signed manifests
  binding plugin identity to a content hash.

The Airlock does not stage side effects. Callers that need speculative
staging compose with a separate primitive such as `sm-enclave`.

## Architecture

```
+----------------------------------------------------------+
|                      Plugin Code                          |
+-------------------------+--------------------------------+
                          | attribute access / method call
                          v
+----------------------------------------------------------+
|                     Airlock Proxy                         |
|  +-----------+   +------------+   +------------------+   |
|  | Allowlist |   | Rate Limit |   | Identity provider |  |
|  | Check     |   | (60s win.) |   | (AgentIdentity)   |  |
|  +-----+-----+   +-----+------+   +---------+--------+   |
|        | pass          | pass               |            |
|        v               v                    v            |
|  +----------------------------------------------------+  |
|  | Violation callback (audit) <-- on deny / over-limit |  |
|  +----------------------------------------------------+  |
+-------------------------+--------------------------------+
                          | delegated call
                          v
+----------------------------------------------------------+
|                    Host Agent (real object)               |
+----------------------------------------------------------+
```

### Components

| Component | Responsibility |
|-----------|---------------|
| `Airlock` | Proxy that intercepts `__getattr__`, enforces allowlist and rate limits |
| `AllowlistSpec` | Frozen dataclass declaring permitted methods, properties, and rate limits |
| `AgentIdentity` | Protocol for identity fields (`agent_id`, `did`, `tenant_id`) |
| `NullIdentity` | Default identity returning empty strings |
| `AgentPlugin` | Abstract base class for the plugin lifecycle |
| `PluginRegistry` | Thread-safe registry with duplicate detection and attestation enforcement |
| `PluginManifest` | Frozen dataclass binding plugin identity to a content hash and Ed25519 signature |
| `AirlockViolation` | Exception raised on any disallowed access attempt |
| `PluginRateLimitExceeded` | Exception raised when a method exceeds its rate limit |

## Key Design Decisions

**Caller-defined allowlist.** There is no default allowlist. The caller
passes an `AllowlistSpec` at Airlock construction. This keeps the library
neutral with respect to host-agent API shape; no host-specific method
names are baked into the sandbox.

**Injected identity.** Identity is supplied via an `AgentIdentity`
Protocol implementation. The Airlock does not reach into the host
agent's internals, so any host object shape is supported — no attribute
names are assumed.

**Rate limiting via sliding window + deque.** Each method maintains a
`collections.deque` of call timestamps. Entries older than 60 seconds are
popped from the left (O(1)) on each call. Rate limits are stored as a
dict on `AllowlistSpec`, keyed by method name; the special key `"*"` is
the default used when a method has no explicit entry.

**Thread-safe rate limiting.** A `threading.Lock` guards timestamp
mutation to prevent races under concurrent plugin calls.

**Violation callbacks are fault-isolated.** If the violation callback
raises, the exception is caught and logged with a stack trace. The
`AirlockViolation` is still raised to the plugin. Audit infrastructure
failures never suppress security enforcement.

**Staging is out of scope.** The Airlock is a capability-gating
primitive. For speculative effect staging, compose with `sm-enclave`.

**Zero dependencies.** The package uses only the Python standard library,
minimising supply-chain risk.

## Ecosystem Integration

sm-airlock composes with other packages in the sm-* family:

| Package | Purpose |
|---------|---------|
| sm-bridge | NANDA-compatible registry endpoints and delta sync |
| sm-enclave | Speculative execution sandbox with staged side effects |
| sm-locp | Open Compliance Protocol (defeasible logic + W3C VCs) |
| sm-model-card | Unified model card schema |
| sm-model-provenance | Model identity and provenance metadata |
| sm-model-integrity-layer | Cryptographic integrity verification |
| sm-model-governance | Three-plane ML governance with Ed25519 signatures |

## References

- NANDA Protocol — Networked AI Agents in Decentralized Architecture

---

*First published: 2026-04-15 | Last modified: 2026-04-17*

*Personal research contributions aligned with [Project NANDA](https://projectnanda.org) standards. [Stellarminds.ai](https://stellarminds.ai)*
