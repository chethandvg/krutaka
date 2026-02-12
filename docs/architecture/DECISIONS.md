# Krutaka — Architecture Decision Records

> Decisions are numbered and immutable once recorded. New decisions append to the bottom.

---

## ADR-001: Use .NET 10 LTS

**Date:** 2026-02-10
**Status:** Accepted
**Context:** We need a .NET version that will remain supported through the expected maintenance horizon. .NET 8 LTS ends Nov 2026 (9 months away). .NET 9 STS also ends Nov 2026. .NET 10 LTS (released Nov 2025) is supported until Nov 2028.
**Decision:** Target .NET 10 LTS (`net10.0` / `net10.0-windows`).
**Consequences:** 3-year support runway. Access to C# 13 features. All current NuGet dependencies support .NET 10.

---

## ADR-002: Console application form factor

**Date:** 2026-02-10
**Status:** Accepted
**Context:** OpenClaw CVE-2026-25253 was caused by network-facing API/WebSocket surfaces. We need the simplest, lowest-risk form factor for a prototype.
**Decision:** Build as a console application (single-user, local-only). No HTTP listeners, no WebSocket endpoints, no network-facing surface.
**Consequences:** Eliminates the entire CVE-2026-25253 attack class. Limits distribution to developer machines. Can be extended to other host types later (the architecture supports it via separate composition roots).

---

## ADR-003: Official Anthropic C# Package (v12.4.0, GA)

**Date:** 2026-02-10
**Status:** Accepted
**Context:** Three options exist: Official `Anthropic` package (now GA v12.4.0, NuGet package name: `Anthropic`), community `Anthropic.SDK` by tghamm (unofficial, different package with a different NuGet name), or raw HTTP. The official package is now out of beta and vendor-backed.
**Decision:** Use the official `Anthropic` NuGet package (NOT `Anthropic.SDK`), wrapped behind our own `IClaudeClient` interface for testability and future migration flexibility.
**Consequences:** Long-term vendor support. Interface wrapper means we can swap implementations without touching consumer code. Trade-off: less convenience helpers than the community SDK, but safer supply chain.
**Note:** Always refer to this as the "official Anthropic package" or "Anthropic NuGet package", not "Anthropic SDK" to avoid confusion with the community `Anthropic.SDK` package.

---

## ADR-004: Zero Data Retention (ZDR) only endpoints

**Date:** 2026-02-10
**Status:** Accepted
**Context:** Anthropic's ZDR eligibility differs by endpoint. `/v1/messages` and `/v1/messages/count_tokens` are ZDR-eligible. `/v1/messages/batches` (29-day retention) and `/v1/files` (retained until deleted) are NOT ZDR-eligible.
**Decision:** Use only ZDR-eligible endpoints. Do not use Batch API or Files API.
**Consequences:** Strongest privacy posture. No async batch processing (higher cost per token). No server-side file references. All data processing is synchronous/streaming.

---

## ADR-005: Windows-first targeting (Windows 10 22H2+ / Windows 11, x64)

**Date:** 2026-02-10
**Status:** Accepted
**Context:** Need to define minimum Windows version for packaging, Credential Manager availability, and Job Object sandboxing.
**Decision:** Target Windows 10 22H2+ and Windows 11, x64 architecture only.
**Consequences:** Full access to Windows Credential Manager (DPAPI), Job Objects, and all .NET 10 Windows APIs. No ARM64 support initially (can be added later). No cross-platform support in v0.1.0.

---

## ADR-006: Manual agentic loop (Pattern A) over auto-invocation

**Date:** 2026-02-10
**Status:** Accepted
**Context:** The official Anthropic package supports both manual tool loop control and automatic function invocation via `IChatClient.UseFunctionInvocation()`. Auto-invocation strips away visibility and security control points.
**Decision:** Use Pattern A (manual loop) where the orchestrator explicitly processes each tool call, enforces approval policies, and logs every step.
**Consequences:** Full audit trail. Human-in-the-loop approval. Tool-result formatting invariants enforced in code. More code to write, but critical for security and debuggability.

---

## ADR-007: Windows Credential Manager for API key storage

**Date:** 2026-02-10
**Status:** Accepted
**Context:** API keys must be encrypted at rest. Options: .NET User Secrets (unencrypted JSON on disk), environment variables (inherited by child processes), config files (plaintext), Windows Credential Manager (DPAPI-backed).
**Decision:** Use Windows Credential Manager via `Meziantou.Framework.Win32.CredentialManager` for DPAPI-backed encrypted storage.
**Consequences:** Keys are encrypted at rest by Windows DPAPI. Not inherited by child processes. Not visible in config files. Windows-only (acceptable per ADR-005).

---

## ADR-008: No remote skill marketplace

**Date:** 2026-02-10
**Status:** Accepted
**Context:** OpenClaw's ClawHub skill marketplace was a supply-chain attack vector with hundreds of compromised packages reported.
**Decision:** Skills are local Markdown files only. No remote registry, no install command, no auto-download.
**Consequences:** Users must create or manually copy skill files. Eliminates supply-chain attack vector. Limits skill ecosystem growth (acceptable for a security-focused prototype).

---

## ADR-009: SQLite FTS5 for memory search (v1), vector search deferred to v2

**Date:** 2026-02-10
**Status:** Accepted
**Context:** Hybrid search (keyword + vector) is ideal, but vector search adds complexity (ONNX model management, embedding generation, sqlite-vec extension). FTS5 is built into Microsoft.Data.Sqlite with zero configuration.
**Decision:** Ship v1 with FTS5-only keyword search. Add vector search with local ONNX embeddings as a v2 enhancement.
**Consequences:** Faster time to working memory system. Keyword search covers most use cases. Schema designed with `embedding BLOB` column for future use.

---

## ADR-010: Spectre.Console with hybrid streaming approach

**Date:** 2026-02-10
**Status:** Accepted
**Context:** Spectre.Console's markup rendering is too slow for per-token streaming display. Need real-time token display during Claude response streaming.
**Decision:** Use raw `Console.Write()` during streaming, then re-render with full Spectre.Console Markdown formatting after the response completes.
**Consequences:** Fast streaming display. Full Markdown formatting on final output. Slight visual discontinuity between streaming and final render (acceptable trade-off).
---

## ADR-011: DI-based Security Violation Logging

**Date:** 2026-02-11
**Status:** Accepted
**Context:** Security violations (blocked paths, commands, files) occur deep in the tool layer (SafeFileOperations, CommandPolicy). Original implementation used static classes, preventing audit logging of violations. This was deferred in Issue #24 as "medium impact" because violations are still enforced, just not audited.
**Decision:** 
1. Convert `SafeFileOperations` from static class to instance-based `IFileOperations` service
2. Update `CommandPolicy` (already instance-based) to accept `IAuditLogger` via constructor
3. Add optional `CorrelationContext` parameter to `ISecurityPolicy.ValidatePath()` and `ValidateCommand()` methods
4. When both `IAuditLogger` and `CorrelationContext` are provided, log violations before throwing `SecurityException`
5. Maintain backward compatibility: logging is optional, exceptions still thrown regardless

**Consequences:**
- ✅ Security violations now logged to structured audit trail with correlation IDs
- ✅ Tools receive `IFileOperations` via DI instead of calling static methods
- ✅ Backward compatible: existing code without CorrelationContext still works
- ✅ Zero-overhead when audit logging not configured (null logger)
- ⚠️ Larger constructor signatures for security services (acceptable trade-off)
- ⚠️ Tools don't have CorrelationContext yet (will pass null initially, can be added later if needed)
- 📈 Test coverage: 8 new integration tests verify logging behavior

**Related:**
- Resolves second deferred task from Issue #24
- Complements audit logging infrastructure from Issue #24
- IFileOperations interface enables future enhancements (e.g., file operation metrics)

---

## ADR-012: Layered Access Policy Engine for Dynamic Directory Scoping

**Date:** 2026-02-12  
**Status:** Accepted  

**Context:**

v0.1.0 limits the agent to a single directory configured upfront in `appsettings.json` via `ToolOptions.WorkingDirectory`. This creates significant usability friction:
- Monorepo users cannot work across multiple subdirectories without restarting
- Multi-project workflows (e.g., editing both a library and its consumer) require separate sessions
- Exploratory tasks (e.g., "find the config file somewhere under my home directory") are blocked
- The directory must be known *before* starting the agent — the agent cannot discover it

Users work around this by setting `WorkingDirectory` to very broad paths (e.g., `C:\Users\username`), defeating the sandboxing purpose, or they restart the agent for each project, losing session context.

The root cause is that `ToolOptions.WorkingDirectory` is a **singleton string** injected at DI registration time. There is no mechanism to request, evaluate, or grant access to additional directories during a session.

**Decision:**

Implement a **four-layer access policy engine** (`LayeredAccessPolicyEngine`) that evaluates directory access requests at runtime. The agent can request access to multiple directories within a single session. Each request is evaluated through:

1. **Layer 1: Hard Deny List (Immutable)** — System directories (`C:\Windows`, `C:\Program Files`, `%APPDATA%`, etc.), UNC paths, paths above ceiling directory, paths with ADS/device names are **always blocked**. No layer can override a Layer 1 denial.

2. **Layer 2: Configurable Allow List (Glob patterns)** — Patterns from `appsettings.json` (e.g., `C:\Users\username\Projects\**`) are auto-approved if validated at startup. Overly-broad patterns (< 3 segments) are rejected.

3. **Layer 3: Session Grants (Previously approved)** — Directories previously approved in this session are granted immediately. Grants have TTL, max count (10), and strict `AccessLevel` enforcement (ReadOnly grant ≠ ReadWrite access).

4. **Layer 4: Heuristic Checks + User Prompt** — Cross-volume detection, path depth heuristics, and suspicious patterns trigger human approval prompts.

**Architecture changes:**
- New interfaces in `Krutaka.Core`: `IAccessPolicyEngine`, `ISessionAccessStore`, `DirectoryAccessRequest`, `AccessDecision`, `AccessLevel` enum
- New implementations in `Krutaka.Tools`: `LayeredAccessPolicyEngine`, `InMemorySessionAccessStore`, `PathResolver`, `GlobPatternValidator`
- Tool refactoring: All 6 tools receive `IAccessPolicyEngine` via DI instead of static `_projectRoot`
- Symlink/junction security: `PathResolver` uses `ResolveLinkTarget(returnFinalTarget: true)` before policy evaluation (closes v0.1.0 security gap)

**Consequences:**

✅ **Benefits:**
- Agent can access multiple directories in a single session (core user need)
- All v0.1.0 security guarantees preserved (system dirs remain unconditionally blocked)
- **Closes symlink escape vulnerability** (v0.1.0 gap) — symlinks/junctions resolved before evaluation
- Frequently-used paths can be auto-approved via glob patterns (reduces approval fatigue)
- Session grants expire via TTL (prevents stale permission accumulation)
- Backward compatible — v0.1.0 tests continue to pass (verified with 576+ existing tests)

⚠️ **Trade-offs:**
- Increased attack surface: dynamic requests introduce new attack vectors (social engineering, glob abuse, session accumulation)
- Complexity: 4-layer engine vs. simple `StartsWith()` check in v0.1.0
- User friction: first access to new directory requires approval (Layer 4 prompt)

🛡️ **Security mitigations:**
- Hard deny list is immutable — no justification or configuration can override Layer 1
- Glob pattern validation at startup (rejects overly-broad patterns like `C:\**`)
- Max concurrent grants (default 10), TTL enforcement, automatic pruning
- Cross-volume requests flagged for explicit approval
- ADS, device names, null bytes, Unicode confusables blocked at Layer 1
- Defense-in-depth: TOCTOU mitigation via re-resolve at access time

📊 **Testing:**
- 65+ new tests covering adversarial scenarios (social engineering, symlink escape, TOCTOU, glob abuse, etc.)
- All existing 576+ v0.1.0 tests must pass (zero regressions)
- Three new adversarial test classes verify attack vectors from threat model

**Related:**
- See `docs/versions/v0.2.0.md` for complete architecture design, data flow diagrams, and threat model
- Implementation tracked across 11 sub-issues (v0.2.0-1 through v0.2.0-11)
- Symlink resolution addresses security gap identified in v0.1.0 (SafeFileOperations did not resolve links)
