# Pending Tasks Before v0.5.0

> **Generated:** 2026-02-19  
> **Purpose:** Document incomplete or deferred work from v0.4.0 and v0.4.5 that should be addressed before starting v0.5.0

## Overview

This document tracks tasks that were identified during v0.4.0 and v0.4.5 development but were deferred, skipped, or left incomplete. These items should be evaluated and addressed (or explicitly deferred again) before beginning work on v0.5.0.

---

## v0.4.0 Deferred Tasks

### 1. Telegram Setup Wizard (Deferred)

**Context:** v0.4.0 introduced Telegram integration with manual setup via `appsettings.json` and Windows Credential Manager.

**Gap:** No interactive setup wizard to guide users through bot creation, token storage, and configuration.

**Current Workaround:** Users follow the manual steps in `docs/guides/TELEGRAM-SETUP.md`.

**Recommendation:** 
- Add `/setup` command in Console mode that interactively:
  - Prompts for bot token
  - Stores token in Windows Credential Manager
  - Gets user's Telegram ID from `@userinfobot`
  - Writes `AllowedUsers` array to `appsettings.json`
  - Validates configuration
- **Effort:** ~1-2 days
- **Priority:** Medium (improves onboarding but not blocking)

---

### 2. Interactive Working Directory Prompt (Deferred)

**Context:** v0.4.0 uses `DefaultWorkingDirectory` from `appsettings.json` (defaults to `.` if not specified).

**Gap:** No interactive prompt at startup to select/confirm working directory. Users must edit config file before first run.

**Current Workaround:** Edit `appsettings.json` before running, or use `.` (current directory).

**Recommendation:**
- Add startup prompt in Console mode (before session manager initialization):
  ```
  Working directory not configured. Please specify:
  1. Use current directory: /home/user/projects/krutaka
  2. Enter custom path
  ```
- Store selection in `appsettings.json` for future runs
- **Effort:** ~1 day (requires `Program.cs` startup restructuring)
- **Priority:** Low (v0.4.5 directory awareness reduces need)

---

### 3. Vector Search / Memory v2 (Explicitly Deferred per ADR-009)

**Context:** Current memory system uses SQLite FTS5 (full-text keyword search).

**Gap:** No semantic/vector search for finding conceptually similar memories.

**Current State:** ADR-009 documents decision to defer vector search to v0.5.0+ to avoid dependency bloat in v0.1.0.

**Recommendation:**
- Re-evaluate in v0.5.0 planning:
  - User feedback on FTS5 limitations (if any)
  - Available .NET vector DB options (Milvus, Qdrant, Weaviate clients)
  - Model for generating embeddings (local via ONNX or remote API)
  - Token budget impact of embedding generation
- **Effort:** ~1-2 weeks (new `IVectorMemory` interface, embedding generation, vector DB integration)
- **Priority:** Low (no user complaints about FTS5 yet)

---

## v0.4.5 Deferred Tasks

### 1. `retry-after` Header Parsing (Deferred)

**Context:** v0.4.5 added exponential backoff for rate limit retries but does NOT parse `retry-after` header from Anthropic responses.

**Gap:** Anthropic SDK v12.4.0 does not expose `retry-after` header in `AnthropicRateLimitException`. Code structure is ready but header parsing is blocked by SDK limitation.

**Current Workaround:** Uses calculated exponential backoff (1s → 2s → 4s → 8s, max 30s) instead of server-provided delay.

**Recommendation:**
- Monitor Anthropic SDK releases for header exposure
- Update `ClaudeClientWrapper.ExecuteWithRetryAsync()` when available:
  ```csharp
  catch (AnthropicRateLimitException ex) when (attempt < _retryMaxAttempts - 1)
  {
      var retryAfter = ex.RetryAfter; // Not yet exposed
      var delayMs = retryAfter.HasValue 
          ? (int)retryAfter.Value.TotalMilliseconds 
          : CalculateBackoffWithJitter(attempt);
      // ...
  }
  ```
- **Effort:** ~1 hour (when SDK exposes header)
- **Priority:** Low (exponential backoff is working well)

---

### 2. Mid-Stream Rate Limit Handling (Deferred)

**Context:** v0.4.5 retries rate limits during `CreateStreaming()` call but NOT mid-stream (after streaming starts).

**Gap:** If Anthropic rate-limits mid-stream, exception propagates without retry.

**Current State:** Considered unlikely per v0.4.5 spec — rate limits typically occur at request initiation, not during streaming.

**Recommendation:**
- Monitor for user reports of mid-stream rate limits
- If observed, add retry wrapper around `await foreach (var evt in stream)`:
  ```csharp
  try
  {
      await foreach (var evt in stream.WithCancellation(cancellationToken))
      {
          // Process events
      }
  }
  catch (AnthropicRateLimitException)
  {
      // Retry from last checkpoint?
      // Or propagate and let user retry?
  }
  ```
- **Challenge:** Mid-stream retry requires conversation state checkpoint (sent messages + partial response)
- **Effort:** ~2-3 days (complex retry semantics)
- **Priority:** Very Low (no observed mid-stream rate limits)

---

### 3. Compaction Mid-Stream Failure Recovery (Deferred)

**Context:** v0.4.5 wrapped `CompactIfNeededAsync()` in try-catch to prevent crashes, but compaction mid-stream failures (e.g., during summarization API call) are not retried.

**Gap:** If compaction fails (e.g., due to summarization API error), compaction is skipped entirely for that loop iteration. Next iteration will retry from scratch.

**Current Workaround:** Agentic loop continues without compaction. Next iteration (when token count still exceeds threshold) will retry compaction from scratch.

**Recommendation:**
- Acceptable as-is — compaction is optimization, not correctness requirement
- If frequent compaction failures observed:
  - Add retry logic inside `ContextCompactor.CompactAsync()` (separate from main loop)
  - Add fallback strategy: skip summarization, just keep last N messages
- **Effort:** ~1 day (if needed)
- **Priority:** Very Low (compaction failures are rare)

---

### 4. Tool Result Pruning Configuration via UI (Deferred)

**Context:** v0.4.5 added `PruneToolResultsAfterTurns` (default: 6) and `PruneToolResultMinChars` (default: 1000) configuration in `appsettings.json`.

**Gap:** No runtime UI to adjust pruning thresholds. Users must edit config file and restart application.

**Current Workaround:** Edit `appsettings.json` before startup.

**Recommendation:**
- Add `/config` command to view/edit configuration at runtime:
  ```
  /config prune-turns 10
  /config prune-min-chars 2000
  ```
- **Effort:** ~1 day (command parsing + config persistence)
- **Priority:** Very Low (default values work well)

---

### 5. Bootstrap File Caps User Feedback ✅ **Resolved (v0.4.6)**

**Context:** v0.4.5 added per-file (20K chars) and total (150K chars) caps for bootstrap files.

**Resolution:** Added INFO-level logging when AGENTS.md or MEMORY.md is truncated, and WARNING-level logging when the total bootstrap content exceeds the total cap. Implemented via `[LoggerMessage]` source generators on `SystemPromptBuilder`. Also added a `Debug.Assert` guard ensuring Layer 2 security instructions are never truncated. 8 new tests verify the logging behavior.

---

## Issues with Skipped Tests

### 1. `RunCommandToolTests.Should_TimeoutLongRunningCommand` (Skipped)

**Test Project:** `Krutaka.Tools.Tests`  
**Reason:** Long-running test (60+ seconds) skipped for CI performance

**Gap:** Timeout behavior not regularly tested.

**Recommendation:**
- Keep skipped in default test runs
- Enable in weekly scheduled CI run or manual release verification
- **Effort:** 0 (already implemented, just skipped)
- **Priority:** Low (timeout logic is straightforward)

---

### 2. `PollingLockFileTests.TryAcquire_Should_WritePidToLockFile` (Skipped)

**Test Project:** `Krutaka.Telegram.Tests`  
**Reason:** Lock file persistence test skipped on CI (file system timing issues)

**Gap:** Lock file behavior not tested on Linux CI runners.

**Recommendation:**
- Re-enable on Windows CI runners only (add platform filter)
- Or add retry logic to handle file system timing on Linux
- **Effort:** ~1 hour
- **Priority:** Low (lock file works in practice)

---

## Documentation Gaps

### 1. Production Deployment Guide (Missing)

**Gap:** No documentation on deploying Krutaka to production (Windows Service, systemd, Docker, etc.).

**Current State:** Users run via `dotnet run` or published executable in interactive mode.

**Recommendation:**
- Add `docs/guides/PRODUCTION-DEPLOYMENT.md` covering:
  - Windows Service installation (using `sc.exe` or NSSM)
  - Linux systemd service file for `dotnet` runtime
  - Docker containerization (if cross-platform support added)
  - Environment variable management for secrets
  - Log rotation and monitoring
- **Effort:** ~1 day
- **Priority:** Medium (production users need this)

---

### 2. Troubleshooting Guide (Missing)

**Gap:** No centralized troubleshooting documentation. Users must search through architecture docs or ask maintainer.

**Current State:** Common issues (API key errors, Telegram auth failures, session corruption) are mentioned in respective guides but not consolidated.

**Recommendation:**
- Add `docs/guides/TROUBLESHOOTING.md` covering:
  - "API key not found" → check Credential Manager
  - "Telegram user not authorized" → check `AllowedUsers` array
  - "Session resume crash" → v0.4.5 fixes this, upgrade if on v0.4.0
  - "Rate limit exceeded" → v0.4.5 adds retries, check retry config
  - "Compaction fails" → v0.4.5 makes this non-fatal, logs error
- **Effort:** ~2 hours
- **Priority:** Medium (improves self-service support)

---

### 3. Architecture Decision Record for Tool Result Pruning ✅ **Resolved (v0.4.6)**

**Gap:** No ADR documenting why tool result pruning prunes in-memory only (not JSONL).

**Resolution:** ADR-014 added to `docs/architecture/DECISIONS.md` documenting the in-memory pruning decision, rationale (audit trail integrity), and alternatives considered (prune JSONL — rejected; no pruning — rejected).

---

## Summary

### High Priority (Before v0.5.0)

- ✅ All v0.4.0 and v0.4.5 issues complete — no blocking gaps

### Medium Priority (Evaluate for v0.5.0)

1. Telegram setup wizard (improves onboarding)
2. Production deployment guide (needed by production users)
3. Troubleshooting guide (reduces support burden)

### Resolved (v0.4.6)

1. ✅ Bootstrap file truncation feedback — INFO/WARNING logging in `SystemPromptBuilder`
2. ✅ ADR-014 — Tool result pruning strategy documented in `docs/architecture/DECISIONS.md`

### Low Priority (Monitor and defer if not critical)

1. Interactive working directory prompt (v0.4.5 directory awareness reduces need)
2. `retry-after` header parsing (blocked by SDK, working well without)
3. Vector search / Memory v2 (deferred per ADR-009, re-evaluate if FTS5 insufficient)
4. Mid-stream rate limit handling (not observed in practice)
5. Compaction mid-stream failure recovery (acceptable as-is)
6. Tool result pruning config UI (default values work well)
7. Skipped tests (low impact, already implemented)

---

## Recommendation for v0.5.0 Planning

Before starting v0.5.0 planning:

1. **Address Medium Priority items** (2-3 days total effort):
   - Telegram setup wizard
   - Bootstrap truncation feedback
   - Production deployment guide
   - Troubleshooting guide

2. **Re-evaluate Low Priority items** based on:
   - User feedback from v0.4.5 usage
   - Support requests (if troubleshooting patterns emerge)
   - Anthropic SDK updates (retry-after header exposure)

3. **Defer Low Priority items** if:
   - No user complaints or support requests
   - Workarounds are acceptable
   - Effort outweighs benefit

4. **New v0.5.0 Features** should be prioritized higher than deferred v0.4.x tasks unless user demand dictates otherwise.

---

**Next Review Date:** Before v0.5.0 planning kickoff
