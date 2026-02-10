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

## ADR-003: Official Anthropic C# SDK (v12.4.0, GA)

**Date:** 2026-02-10
**Status:** Accepted
**Context:** Three options exist: Official `Anthropic` package (now GA v12.4.0, NuGet package name: `Anthropic`), community `Anthropic.SDK` by tghamm (unofficial, different package), or raw HTTP. The official package is now out of beta and vendor-backed.
**Decision:** Use the official `Anthropic` NuGet package, wrapped behind our own `IClaudeClient` interface for testability and future migration flexibility.
**Consequences:** Long-term vendor support. Interface wrapper means we can swap implementations without touching consumer code. Trade-off: less convenience helpers than the community SDK, but safer supply chain.

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