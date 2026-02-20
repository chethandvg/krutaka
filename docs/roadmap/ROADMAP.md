# Krutaka Roadmap — From Security-Hardened Platform to Full Autonomous Agent

> **Created:** 2026-02-19
> **Last Updated:** 2026-02-19
> **Current Version:** v0.4.5 ✅ Complete (1,917 tests, 2 skipped)
> **Current State:** Multi-session agent platform with Telegram integration, session resilience, API hardening, and context intelligence

---

## Table of Contents

- [Version History](#version-history)
- [Roadmap Overview](#roadmap-overview)
- [Security Relaxation Principle](#security-relaxation-principle)
- [v0.4.6 — Project Structure, Code Quality & v0.5.0 Prerequisites](#v046--project-structure-code-quality--v050-prerequisites)
- [v0.5.0 — Autonomous Agent Mode](#v050--autonomous-agent-mode)
- [v0.6.0 — Vector Search & RAG Memory v2](#v060--vector-search--rag-memory-v2)
- [v0.7.0 — Web Browsing Tool](#v070--web-browsing-tool)
- [v0.8.0 — Server-Side Prompt Caching & Model Flexibility](#v080--server-side-prompt-caching--model-flexibility)
- [v0.9.0 — Multi-Agent Coordination](#v090--multi-agent-coordination)
- [v1.0.0 — Production-Ready Release](#v100--production-ready-release)
- [v1.1.0+ — Agent Pool & Manager Architecture](#v110--agent-pool--manager-architecture)
- [v1.2.0+ — Cross-Drive Access, Admin Elevation & OS Intelligence](#v120--cross-drive-access-admin-elevation--os-intelligence)
- [v1.3.0+ — Triggers, User Learning & Adaptive Personality](#v130--triggers-user-learning--adaptive-personality)
- [Deferred / Parked Items](#deferred--parked-items)
- [Dependency Map (Version → Version)](#dependency-map-version--version)
- [Related Documents](#related-documents)

---

## Version History

| Version | Title | Status | Completion Date | Test Count |
|---------|-------|--------|-----------------|------------|
| v0.1.0 | Core Agent & Security Foundation | ✅ Complete | 2026-02-11 | 576 |
| v0.1.1 | Smart Session Management | ✅ Complete | 2026-02-12 | 587 |
| v0.2.0 | Dynamic Directory Scoping | ✅ Complete | 2026-02-13 | 903 |
| v0.3.0 | Graduated Command Execution | ✅ Complete | 2026-02-14 | 1,289 (1 skipped) |
| v0.4.0 | Telegram Integration & Multi-Session | ✅ Complete | 2026-02-17 | 1,765 (2 skipped) |
| v0.4.5 | Session Resilience & Context Intelligence | ✅ Complete | 2026-02-19 | 1,917 (2 skipped) |
| v0.4.6 | Project Structure & v0.5.0 Prerequisites | 📋 Planning | — | Target: ~2,050+ |
| v0.5.0 | Autonomous Agent Mode | 🔮 Planned | — | Target: ~2,400+ |
| v0.6.0 | Vector Search & RAG Memory v2 | 🔮 Planned | — | — |
| v0.7.0 | Web Browsing Tool | 🔮 Planned | — | — |
| v0.8.0 | Prompt Caching & Model Flexibility | 🔮 Planned | — | — |
| v0.9.0 | Multi-Agent Coordination | 🔮 Planned | — | — |
| v1.0.0 | Production-Ready Release | 🔮 Target | — | — |

---

## Roadmap Overview

```text
 Phase     Version   Focus
 ─────     ───────   ─────
 FOUNDATION
           v0.1.0    Core agent, security, tools, memory          ✅
           v0.1.1    Session discovery and auto-resume             ✅
           v0.2.0    Dynamic directory scoping (4-layer policy)    ✅
           v0.3.0    Graduated command execution (4-tier risk)     ✅

 PLATFORM
           v0.4.0    Telegram + multi-session architecture         ✅
           v0.4.5    Session resilience + context intelligence     ✅
           v0.4.6    Project structure + v0.5.0 prerequisites      📋 ← NEXT

 AUTONOMY
           v0.5.0    Autonomous agent mode + git checkpoints       🔮

 INTELLIGENCE
           v0.6.0    Vector search + RAG memory v2                 🔮
           v0.7.0    Web browsing tool                             🔮
           v0.8.0    Prompt caching + model flexibility            🔮

 SCALE
           v0.9.0    Multi-agent coordination                      🔮
           v1.0.0    Production-ready release                      🔮

 FUTURE
           v1.1.0+   Agent pool + manager architecture             🔮
           v1.2.0+   Cross-drive access + admin elevation          🔮
           v1.3.0+   Triggers, user learning, adaptive personality 🔮
```

---

## Security Relaxation Principle

The project follows a **ratchet principle**: each version relaxes restrictions proportionally, with new security controls gating every new capability. The security boundary bar NEVER drops — it only gets more granular.

```text
 v0.1.0 ████████████████████████  Maximum restriction (local console, single dir)
 v0.2.0 ██████████████████████    Dynamic dirs, but hard deny-list immutable
 v0.3.0 ████████████████████      Graduated commands, safe auto-approved
 v0.4.0 ██████████████████        Remote access (Telegram), but auth-gated
 v0.4.5 █████████████████         Resilience improvements, no new surface
 v0.5.0 ████████████████          Semi-autonomous, but budgeted + checkpointed
 v0.6.0 ███████████████           Semantic search, but local embeddings only
 v0.7.0 ██████████████            Web access, but domain-allowlisted
 v0.8.0 █████████████             Caching optimization, no new surface
 v0.9.0 ████████████              Multi-agent, but hierarchical permissions
 v1.0.0 ███████████               Full autonomy within policy — NEVER unrestricted

 ████ = Immutable security boundaries (NEVER relaxed):
        - Path traversal protection
        - System directory deny-list (Layer 1)
        - Secret redaction in logs
        - Untrusted content tagging (<untrusted_content>)
        - Command injection prevention (CliWrap arrays)
        - CancellationToken on everything
        - Fail-closed for unknown commands
        - HMAC-signed callbacks
```

---

## v0.4.6 — Project Structure, Code Quality & v0.5.0 Prerequisites

> **Status:** 📋 Planning
> **Goal:** Housekeeping release — restructure all projects into proper directory hierarchies, add per-project README files, add missing test coverage, resolve medium-priority pending tasks, and define v0.5.0 prerequisite interfaces/models. No new user-facing features.
> **Estimated Effort:** ~10–13 days
> **Target Tests:** ~2,050+

### Why v0.4.6 Before v0.5.0

v0.5.0 (Autonomous Agent Mode) is the most significant behavioral change since v0.1.0. Before starting it:

1. **Code organization** — All 7 projects have flat `.cs` files with no subdirectories. Finding files is difficult and onboarding new contributors is painful. Must restructure before adding more code.
2. **Missing tests** — SessionManager, SessionFactory, and DI registrations lack dedicated test coverage. Must verify before building autonomy on top.
3. **Pending tasks** — Medium-priority deferred items from v0.4.0/v0.4.5 should be addressed (bootstrap truncation feedback, deployment guide, troubleshooting guide).
4. **Type system preparation** — v0.5.0 needs `AutonomyLevel`, `TaskBudget`, `IGitCheckpointService`, `IBehaviorAnomalyDetector` — define interfaces now so v0.5.0 can focus on implementation.

### Phase Summary

| Phase | Focus | Est. Issues | Est. New Tests |
|-------|-------|-------------|----------------|
| A | Documentation & Instructions | 1 | 0 |
| B | Project Restructuring (all 7 projects) | 8 | 0 |
| C | Missing Test Coverage | 3 | ~80 |
| D | Pending Task Quick Wins | 4 | ~15 |
| E | v0.5.0 Prerequisite Interfaces | 4 | ~30 |
| F | Testing & Release | 3 | ~10 |
| **Total** | | **~23** | **~135** |

### Phase B: Project Restructuring (Detail)

Currently all `.cs` files sit flat in each project root. Proposed directory structures:

**Krutaka.Core:**
```
src/Krutaka.Core/
├── Abstractions/          # ITool, IClaudeClient, IAuditLogger, IAccessPolicyEngine, etc.
├── Models/                # AgentEvent, AccessDecision, CommandExecutionRequest, DTOs
├── Orchestration/         # AgentOrchestrator, ContextCompactor, ConversationPruner
├── Prompt/                # SystemPromptBuilder
├── Session/               # ManagedSession, SessionState, SessionSummary
├── Security/              # SecurityPolicy, TelegramConfigValidator
├── Correlation/           # CorrelationContext, CorrelationContextAccessor
└── README.md
```

**Krutaka.Tools:**
```
src/Krutaka.Tools/
├── FileTools/             # ReadFileTool, WriteFileTool, EditFileTool, ListFilesTool, SearchFilesTool
├── CommandTools/          # RunCommandTool
├── Policies/              # CommandPolicy, CommandRiskClassifier, CommandPolicyOptions
├── Access/                # AccessPolicyEngine, SessionAccessStore, GlobPatternValidator, PathResolver
├── Security/              # SafeFileOperations, SecurityPolicy
├── Configuration/         # ToolOptions, CommandPolicyOptions
├── DI/                    # ServiceExtensions
├── Session/               # SessionFactory
└── README.md
```

**Krutaka.Telegram:**
```
src/Krutaka.Telegram/
├── Auth/                  # TelegramAuthGuard, AuthResult, LockoutState, SlidingWindowCounter
├── Commands/              # TelegramCommandRouter, CommandRouteResult, TelegramCommand
├── Streaming/             # TelegramResponseStreamer
├── Approval/              # TelegramApprovalHandler, CallbackDataSigner, CallbackPayload
├── Session/               # TelegramSessionBridge
├── Files/                 # TelegramFileHandler
├── Health/                # TelegramHealthMonitor
├── Infrastructure/        # PollingLockFile, TelegramBotService, ServiceExtensions
├── Configuration/         # TelegramSecurityConfig, TelegramConfigValidator
└── README.md
```

**Krutaka.Console:**
```
src/Krutaka.Console/
├── UI/                    # ConsoleUI, MarkdownRenderer, ApprovalHandler
├── Setup/                 # SetupWizard, SecretsProvider, WindowsSecretsProvider
├── Configuration/         # HostModeConfigurator
├── Program.cs             # Entry point (stays at root — .NET convention)
└── README.md
```

**Krutaka.Memory:**
```
src/Krutaka.Memory/
├── Storage/               # SqliteMemoryStore, MemoryFileService
├── Tools/                 # MemoryStoreTool, MemorySearchTool
├── Session/               # SessionStore
├── Logging/               # DailyLogService
├── Chunking/              # TextChunker
├── Configuration/         # MemoryOptions
├── DI/                    # ServiceExtensions
└── README.md
```

**Krutaka.Skills:**
```
src/Krutaka.Skills/
├── Loading/               # SkillLoader, SkillFrontmatter
├── Registry/              # SkillRegistry, ISkillRegistry
├── Configuration/         # SkillOptions
├── DI/                    # ServiceExtensions
└── README.md
```

**Krutaka.AI:**
```
src/Krutaka.AI/
├── Client/                # ClaudeClientWrapper
├── DI/                    # ServiceExtensions
└── README.md
```

**Important:** File moves only — no namespace changes, no logic changes, no behavioral changes. C# does not enforce namespace-to-directory mapping. All 1,917 existing tests MUST pass after restructuring with zero changes.

### Phase D: Pending Task Quick Wins

| Task | Source | Effort |
|------|--------|--------|
| Bootstrap file truncation logging (INFO-level + Console indicator) | PENDING-TASKS.md §5 | ~2 hours |
| Production deployment guide (`docs/guides/PRODUCTION-DEPLOYMENT.md`) | PENDING-TASKS.md, Documentation Gaps §1 | ~1 day |
| Troubleshooting guide (`docs/guides/TROUBLESHOOTING.md`) | PENDING-TASKS.md, Documentation Gaps §2 | ~2 hours |
| ADR-014: Tool result pruning (in-memory only, not JSONL) | PENDING-TASKS.md, Documentation Gaps §3 | ~1 hour |

### Phase E: v0.5.0 Prerequisite Interfaces

These are **interface and model definitions only** — no implementations, no behavioral changes. They prepare the type system so v0.5.0 can focus purely on behavior.

```csharp
// E1: Autonomy levels
public enum AutonomyLevel
{
    Supervised = 0,     // Every action requires approval (v0.1.0–v0.4.x default)
    Guided = 1,         // Safe auto-approved, moderate prompted
    SemiAutonomous = 2, // Safe+Moderate auto, elevated prompted
    Autonomous = 3      // All within policy, only dangerous blocked
}

// E2: Task budget model
public record TaskBudget(
    int MaxClaudeTokens,         // Default: 200,000
    int MaxToolCalls,            // Default: 100
    int MaxFilesModified,        // Default: 20
    int MaxProcessesSpawned);    // Default: 10

public interface ITaskBudgetTracker
{
    bool TryConsume(BudgetDimension dimension, int amount);
    TaskBudgetSnapshot GetSnapshot();
    bool IsExhausted { get; }
}

// E3: Git checkpoint service
public interface IGitCheckpointService
{
    Task<string> CreateCheckpointAsync(string message, CancellationToken ct);
    Task RollbackToCheckpointAsync(string checkpointId, CancellationToken ct);
    Task<IReadOnlyList<CheckpointInfo>> ListCheckpointsAsync(CancellationToken ct);
}

// E4: Behavior anomaly detection
public interface IBehaviorAnomalyDetector
{
    Task<AnomalyAssessment> AssessAsync(AgentBehaviorSnapshot snapshot, CancellationToken ct);
}
```

---

## v0.5.0 — Autonomous Agent Mode

> **Status:** 🔮 Planned
> **Predecessor:** v0.4.6 (Project Structure & v0.5.0 Prerequisites)
> **Goal:** Allow the agent to work on longer tasks with graduated autonomy, budgeted resource consumption, git-based rollback, and anomaly detection. First version where the agent can operate without constant human approval.

### Problem Statement

In v0.4.x, every Moderate/Elevated tool invocation requires human approval. For a 30-minute coding task, this can mean 50+ approval prompts. Users rubber-stamp approvals, defeating the security purpose. The agent also cannot work unattended — closing the console or Telegram stops all progress.

### Autonomy Levels

| Level | Name | What's Auto-Approved | What's Prompted | What's Blocked |
|-------|------|---------------------|-----------------|----------------|
| 0 | Supervised | Nothing | Safe, Moderate, Elevated | Dangerous |
| 1 | Guided | Safe | Moderate, Elevated | Dangerous |
| 2 | Semi-Autonomous | Safe, Moderate | Elevated | Dangerous |
| 3 | Autonomous | Safe, Moderate, Elevated | Nothing (within budget) | Dangerous |

**Default:** Level 1 (Guided) — same behavior as v0.3.0+ for backward compatibility.
**Level 3** requires explicit opt-in via config AND per-session confirmation.

### Key Components

#### 1. Task Budget Enforcement

```text
Session starts with budget:
  MaxClaudeTokens:      200,000  (configurable)
  MaxToolCalls:         100      (configurable)
  MaxFilesModified:     20       (configurable)
  MaxProcessesSpawned:  10       (configurable)

Every tool call → ITaskBudgetTracker.TryConsume()
  If exhausted → stop agent, notify user, request budget extension or /abort
  At 80% → warning notification (Console + Telegram)
  At 100% → hard stop
```

#### 2. Git Checkpoint & Rollback

```text
Before any file modification (write_file, edit_file):
  IGitCheckpointService.CreateCheckpointAsync("pre-modify: {file}")
  → Creates lightweight git stash or commit on temp branch

On task failure or user /rollback:
  IGitCheckpointService.RollbackToCheckpointAsync(checkpointId)
  → Restores files to pre-modification state

On task success:
  Checkpoints cleaned up (squash or remove temp branch)
```

**Security:** Checkpoints are local git operations only. No `git push` without Elevated approval. Checkpoint creation itself is Safe tier.

#### 3. Deadman's Switch

```text
Configuration:
  MaxUnattendedDuration: 30 minutes (configurable)
  HeartbeatInterval: 5 minutes

Agent operates autonomously:
  If no human interaction for MaxUnattendedDuration:
    → Pause agent
    → Send notification (Telegram push / Console bell)
    → Wait for heartbeat (/continue or any input)
    → If no response in 2× MaxUnattendedDuration → auto-abort + rollback
```

#### 4. Behavior Anomaly Detection

```text
IBehaviorAnomalyDetector monitors per-session:
  - Tool call frequency (>10 calls/minute = unusual)
  - Repeated failures on same tool (>3 = agent stuck)
  - Escalating access requests (ReadOnly → ReadWrite → Execute in rapid succession)
  - File modification velocity (>5 files/minute = bulk operation)
  - Directory scope expansion (accessing 5+ new directories in one session)

On anomaly detection:
  Level 0-1: Log warning, continue
  Level 2-3: Pause agent, notify user, require /continue to proceed
```

#### 5. Session Steering

```text
While agent is working on a task:
  User can send /steer "change direction to X"
  → Injects steering message into conversation
  → Agent acknowledges and adjusts approach
  → Original task context preserved

  User can send /pause → agent completes current tool call, then waits
  User can send /abort → agent stops immediately, rollback offered
  User can send /budget → shows current budget consumption
  User can send /checkpoint → creates manual checkpoint
```

### Architecture Changes

```text
AgentOrchestrator
  │
  ├── AutonomyLevel (from config + per-session)
  ├── ITaskBudgetTracker (per-session)
  ├── IGitCheckpointService (per-session)
  ├── IBehaviorAnomalyDetector (per-session)
  └── DeadmanSwitch timer (per-session)

Before each tool call:
  1. Check budget → reject if exhausted
  2. Check autonomy level → auto-approve or prompt based on tier vs level
  3. Check anomaly detector → pause if anomalous
  4. Create checkpoint (if file-modifying tool)
  5. Execute tool
  6. Update budget tracker
  7. Reset deadman switch timer
```

### Security Analysis

| Threat | Severity | Mitigation |
|--------|----------|------------|
| Autonomy level escalation | High | Level stored in config + confirmed per-session. No runtime escalation API. |
| Budget exhaustion by malicious prompt | Medium | Hard budget cap. Per-session, not global. Cannot be increased by agent. |
| Checkpoint manipulation | Low | Checkpoints are git operations in local repo. Agent cannot push. |
| Anomaly detector bypass | Medium | Detector runs outside agent control. Agent cannot disable it. |
| Deadman switch disarmed | Low | Timer runs in SessionManager, not in orchestrator. Agent cannot reset it. |
| Autonomous + Telegram = remote unattended | High | Level 3 requires both config opt-in AND session-start confirmation. Budget hard-capped. |

### Estimated Effort

| Phase | Focus | Est. Issues | Est. New Tests |
|-------|-------|-------------|----------------|
| A | Copilot instructions + AGENTS.md | 1 | 0 |
| B | Autonomy level implementation | 3 | ~60 |
| C | Task budget tracker | 2 | ~40 |
| D | Git checkpoint service | 3 | ~50 |
| E | Deadman's switch | 2 | ~30 |
| F | Behavior anomaly detector | 3 | ~40 |
| G | Session steering commands | 2 | ~20 |
| H | Console + Telegram integration | 2 | ~30 |
| I | Adversarial tests + release | 3 | ~80 |
| **Total** | | **~21** | **~350** |

### New Commands

| Command | Description | Availability |
|---------|-------------|--------------|
| `/steer <message>` | Redirect agent mid-task | Console + Telegram |
| `/pause` | Pause agent after current tool call | Console + Telegram |
| `/continue` | Resume paused agent / heartbeat | Console + Telegram |
| `/rollback [id]` | Rollback to checkpoint | Console + Telegram |
| `/checkpoint` | Create manual checkpoint | Console + Telegram |
| `/autonomy [level]` | View/set autonomy level for session | Console + Telegram |

---

## v0.6.0 — Vector Search & RAG Memory v2

> **Status:** 🔮 Planned
> **Predecessor:** v0.5.0
> **Goal:** Upgrade memory system from keyword-only (FTS5) to hybrid keyword + semantic vector search, enabling conceptual recall across sessions.

### Problem Statement

FTS5 keyword search fails for conceptual queries. "What was the approach we discussed for authentication?" won't find memories stored as "decided to use JWT tokens with refresh rotation." Vector search bridges this semantic gap.

### Key Components

1. **Local ONNX Embeddings**
   - Model: `bge-micro-v2` or similar lightweight model (~25MB) (Note: Add a couple more models like nomic-embed-text-v1.5, Snowflake-Arctic-Embed-XS, all-MiniLM-L6-v2 or any other if required which can be picked on the go)
   - Runs locally via `Microsoft.ML.OnnxRuntime` — no external API calls
   - Embedding dimension: 384 (configurable)
   - Generation: on memory store, cached for deduplication
   - research if we can use tags/labels (by creating new if required or identify and using the once that are more related. May be we can get some when we make the LLM call) to help this process. Use it if it makes the application efficient

2. **sqlite-vec Integration**
   - SQLite virtual table for vector similarity search
   - Uses existing `embedding BLOB` column (prepared in v0.1.0 schema per ADR-009)
   - KNN search with configurable top-K (default: 10)

3. **Hybrid Search with Weighted Scoring**
   ```text
   Query: "authentication approach"

   FTS5 (BM25):     [result1: score 0.8, result2: score 0.5]
   Vector (cosine):  [result3: score 0.9, result1: score 0.7]

   Merge (vector=0.7, text=0.3):
     result3: 0.9×0.7 = 0.63
     result1: 0.8×0.3 + 0.7×0.7 = 0.73
     result2: 0.5×0.3 = 0.15

   Final: [result1, result3, result2]
   ```

4. **Embedding Cache**
   - Deduplicate embedding generation for identical content
   - SQLite table: `embedding_cache(content_hash TEXT PRIMARY KEY, embedding BLOB, model TEXT)`
   - Cache invalidation: content hash mismatch

5. **Document Chunking Enhancement**
   - Split large memories into chunks (max 512 tokens per chunk)
   - Store embeddings per chunk, not per full document
   - Search returns chunk + parent document reference

### Security Considerations

- ONNX model is local-only — no external API calls (privacy preserved per ADR-004 spirit)
- Embedding cache is informational — corruption doesn't affect core functionality
- Vector search results are advisory — same `<untrusted_content>` tagging applies
- Model file integrity: SHA-256 hash verification on first load

### ADR-009 Re-evaluation

ADR-009 deferred vector search to v2. v0.6.0 IS the v2 implementation. The ADR's conditions are met:
- FTS5 has been the sole search mechanism for 5+ versions
- Schema already has `embedding BLOB` column
- ONNX runtime is mature and lightweight
- User feedback (if any) on FTS5 limitations will inform priority

---

## v0.7.0 — Web Browsing Tool

> **Status:** 🔮 Planned
> **Predecessor:** v0.6.0
> **Goal:** Give the agent controlled web access for documentation lookup, API reference checking, and research — with strict domain allowlisting and content sanitization.

### Problem Statement

The agent frequently needs to check documentation, API references, or search for error messages. Currently it can only use `memory_search` or ask the user. Web access would dramatically improve the agent's ability to self-serve information.

### Architecture

```text
┌─────────────┐     ┌──────────────────────┐     ┌─────────────┐
│  Agent       │────▶│  WebBrowsingTool      │────▶│  Internet    │
│  (Claude)    │◀────│  (new tool)           │◀────│  (HTTPS)     │
└─────────────┘     └──────────────────────┘     └─────────────┘
                           │
                    ┌──────┴──────────────┐
                    │ Security Pipeline:  │
                    │  1. Domain allowlist │  ← only approved domains
                    │  2. URL validation   │  ← no file://, no internal IPs
                    │  3. TLS enforcement  │  ← HTTPS only
                    │  4. Content sanitize │  ← strip scripts, limit size
                    │  5. Rate limiting    │  ← max N requests/minute
                    │  6. Content tagging  │  ← <untrusted_content source="web:domain">
                    │  7. Size capping     │  ← max 50KB extracted text
                    │  8. Audit logging    │  ← every request logged
                    └─────────────────────┘
```

### Domain Allowlist (Default)

```json
{
  "WebBrowsing": {
    "AllowedDomains": [
      "docs.microsoft.com",
      "learn.microsoft.com",
      "developer.mozilla.org",
      "stackoverflow.com",
      "github.com",
      "docs.anthropic.com",
      "nuget.org"
    ],
    "MaxRequestsPerMinute": 5,
    "MaxContentSizeBytes": 51200,
    "TimeoutSeconds": 15,
    "UserAgent": "Krutaka/{version} (AI Agent; +https://github.com/chethandvg/krutaka)"
  }
}
```

### Security Model

| Threat | Mitigation |
|--------|------------|
| SSRF (Server-Side Request Forgery) | Domain allowlist + private IP range blocking (10.x, 172.16.x, 192.168.x, 127.x) |
| Content injection | All web content wrapped in `<untrusted_content source="web:{domain}">` tags |
| Credential leakage in URLs | URL validation strips credentials, query params logged but values masked |
| Resource exhaustion | Rate limit (5 req/min), timeout (15s), content cap (50KB) |
| Tracking/fingerprinting | Minimal User-Agent, no cookies persisted, no JavaScript execution |
| Domain allowlist bypass | Strict exact-match + subdomain matching, no wildcard patterns |

### User Configuration

Option for Anthropic-provided web search tool if user has API key:
- If `WebSearch.UseAnthropicWebSearch: true` AND API key available → use Anthropic's web search
- Otherwise → use built-in HTTP client with domain allowlist
- Both modes use same security pipeline (sanitization, tagging, audit logging)

---

## v0.8.0 — Server-Side Prompt Caching & Model Flexibility

> **Status:** 🔮 Planned
> **Predecessor:** v0.7.0
> **Goal:** Optimize token usage via Anthropic prompt caching, support multiple LLM providers, and allow configurable model selection.

### Problem Statement

Every API call re-sends the full system prompt (AGENTS.md, security instructions, tool descriptions, skills, memory). This wastes tokens and increases latency. Anthropic's prompt caching feature can cache the first ~4000 tokens of the system prompt, reducing cost by up to 90% for cached portions.

### Key Components

#### 1. Server-Side Prompt Caching

```text
System prompt structure (cacheable layers):
  ┌─────────────────────────────────────┐
  │ Layer 1: Core Identity (AGENTS.md)  │ ← CACHE THIS (changes rarely)
  │ Layer 2: Security Instructions      │ ← CACHE THIS (never changes)
  │ Layer 3a: Tool Descriptions         │ ← CACHE THIS (changes per-version)
  │ Layer 3b: Command Tier Info         │ ← CACHE THIS (changes per-version)
  ├─────────────────────────────────────┤
  │ Layer 3c: Environment Context       │ ← DO NOT CACHE (per-session)
  │ Layer 4: Skill Metadata             │ ← CACHE THIS (changes rarely)
  │ Layer 5: MEMORY.md                  │ ← DO NOT CACHE (changes frequently)
  └─────────────────────────────────────┘

Strategy:
  - Cache Layers 1, 2, 3a, 3b, 4 as a single cache block
  - Layers 3c and 5 always sent fresh
  - Cache TTL: 5 minutes (Anthropic default)
  - Cache invalidation: version change, config change, skill file change
```

**Bottleneck Analysis:**
- Anthropic caching requires `cache_control` parameter on content blocks
- Cache is per-API-key, per-model — shared across sessions (beneficial)
- First request is slightly slower (cache write), subsequent requests faster (cache hit)
- MEMORY.md changes frequently → cannot cache → must be last in prompt order
- Estimated savings: 30-50% token reduction on system prompt for subsequent calls

#### 2. Model Flexibility

```text
Configuration:
{
  "Agent": {
    "DefaultModel": "claude-sonnet-4-20250514",
    "AvailableModels": [
      { "Id": "claude-sonnet-4-20250514", "MaxTokens": 200000, "Label": "Claude Sonnet 4" },
      { "Id": "claude-haiku-3-5-20241022", "MaxTokens": 200000, "Label": "Claude Haiku 3.5" },
      { "Id": "local:ollama:deepseek-r1", "MaxTokens": 32000, "Label": "DeepSeek R1 (Local)" }
    ],
    "ModelSwitchRequiresConfirmation": true
  }
}
```

- Users can add local LLM models (Ollama, LM Studio) via configuration
- Each model has its own `MaxTokens` setting — compaction thresholds auto-adjust
- New `/model` command to switch models mid-session
- Local models use OpenAI-compatible API interface (Ollama standard)
- Token counting adjusts per model (Anthropic tokenizer vs tiktoken vs local estimate)

### Security Considerations

- Prompt cache is server-side at Anthropic — no local cache to secure
- Local models bypass Anthropic's content filtering — add local content filter option
- Model switch during session preserves all security boundaries (same tool policies, same access policies)
- Local model API keys stored in Credential Manager (same as Anthropic key)

---

## v0.9.0 — Multi-Agent Coordination

> **Status:** 🔮 Planned
> **Predecessor:** v0.8.0
> **Goal:** Enable spawning sub-agents for parallel task execution with inter-agent communication and hierarchical permission model.

### Problem Statement

Complex tasks (e.g., "refactor this module, update tests, and update documentation") benefit from parallel execution. Currently the agent processes everything sequentially. Sub-agents could work on independent subtasks concurrently.

### Architecture

```text
┌─────────────────────────────────────────────────┐
│                  Session Manager                 │
│                                                  │
│  ┌───────────────────────────────────────┐      │
│  │ Parent Agent (primary session)         │      │
│  │ AgentId: guid-A                        │      │
│  │ Role: "coordinator"                    │      │
│  │                                        │      │
│  │ Spawns:                                │      │
│  │  ├── Sub-Agent B (Role: "coder")       │      │
│  │  │   AgentId: guid-B                   │      │
│  │  │   ParentAgentId: guid-A             │      │
│  │  │   Budget: subset of A's budget      │      │
│  │  │   Access: inherited from A           │      │
│  │  │                                      │      │
│  │  └── Sub-Agent C (Role: "tester")       │      │
│  │      AgentId: guid-C                    │      │
│  │      ParentAgentId: guid-A              │      │
│  │      Budget: subset of A's budget       │      │
│  │      Access: inherited from A            │      │
│  └───────────────────────────────────────┘       │
└─────────────────────────────────────────────────┘
```

### Inter-Agent Communication

```text
Communication channels:
  1. Parent → Child:  Direct message injection into child's conversation
  2. Child → Parent:  Structured status updates (progress, questions, errors)
  3. Sibling → Sibling: NOT ALLOWED directly — must go through parent

Message types:
  - TaskAssignment(description, budget, constraints)
  - ProgressUpdate(percentComplete, currentStep, issues)
  - QuestionToParent(question, context, urgency)
  - ErrorReport(error, affectedFiles, recoveryOptions)
  - CompletionReport(summary, filesModified, testsRun)
  - ThankYou(targetAgentId, reason)        ← agent acknowledges helpful sibling work
  - InterferenceAlert(sourceAgentId, file)  ← agent reports unexpected file changes
```

### Permission Hierarchy

```text
Parent Agent:
  ✅ Can steer/pause/abort any child
  ✅ Can read any child's conversation
  ✅ Can inject messages into any child
  ✅ Can reallocate budget between children
  ❌ Cannot exceed own budget (children share parent's budget)

Sibling Agents:
  ✅ Can request information from parent (who may relay from another sibling)
  ✅ Can report interference (file conflicts between siblings)
  ❌ Cannot directly communicate with siblings
  ❌ Cannot access sibling's conversation history
  ❌ Cannot modify sibling's files without parent coordination

Human User:
  ✅ Can interact with any agent directly
  ✅ Can override any agent's decisions
  ✅ Can kill-switch all agents at once
```

### Human Intervention Queue

When multiple agents need human input simultaneously:
```text
Queue Priority:
  1. Security approvals (Elevated commands) — highest
  2. Error recovery — high
  3. Access requests — medium
  4. Questions / clarifications — low

Queue Display (Console):
  ┌─────────────────────────────────────────┐
  │ 🔔 3 agents need your attention:        │
  │                                          │
  │ 1. [🔴 SECURITY] Agent B: git push      │
  │ 2. [🟡 ERROR] Agent C: test failure     │
  │ 3. [🟢 QUESTION] Agent B: API choice?   │
  │                                          │
  │ Select (1-3) or /queue to view all:      │
  └─────────────────────────────────────────┘

Queue Display (Telegram):
  Inline keyboard per approval, queued and labeled by priority
```

### CorrelationContext Usage

v0.4.0 added `AgentId`, `ParentAgentId`, `AgentRole` to `CorrelationContext` (currently null). v0.9.0 activates these:
- Every audit event tagged with `AgentId` — trace which agent did what
- Parent-child relationship visible in logs
- Cross-agent interactions logged with both agent IDs

---

## v1.0.0 — Production-Ready Release

> **Status:** 🔮 Target
> **Predecessor:** v0.9.0
> **Goal:** Full stability, documentation, packaging, and deployment story. First version recommended for general use.

### Criteria for v1.0.0

| Requirement | Description |
|-------------|-------------|
| **Feature completeness** | All v0.5.0–v0.9.0 features stable and tested |
| **Test coverage** | >90% line coverage on Core, Tools, Security. 3,000+ total tests minimum |
| **Documentation** | Complete user guide, API reference, troubleshooting, deployment guide |
| **Packaging** | Self-contained EXE, MSI installer (Windows), optional Docker image |
| **Installation wizard** | First-run setup: API key, working directory, Telegram config |
| **Performance benchmarks** | Documented: cold start time, avg response latency, memory footprint |
| **Security audit** | Complete threat model review, all ADRs current, adversarial test suite comprehensive |
| **Backward compatibility** | v0.4.x → v1.0.0 migration path documented |
| **Error handling** | Every known error has a user-friendly message and recovery path |
| **Logging** | Production-grade structured logging with rotation, retention, and monitoring hooks |

### Deletion Handling Policy (Finalized for v1.0.0)

```text
Deletion classification:
  Agent-created temp files (last 5 minutes):
    → Auto-approved if within session temp directory
    → Prompted if in project directory (even if agent created it)

  Bulk deletion (>3 files or entire directory):
    → ALWAYS prompted, regardless of who created them
    → Shows full file list before confirmation
    → Git checkpoint created before execution

  System/config file deletion:
    → ALWAYS blocked (Layer 1 deny-list)

  User-initiated deletion (/delete command):
    → Single confirmation prompt
    → Git checkpoint before execution
```

---

## v1.1.0+ — Agent Pool & Manager Architecture

> **Status:** 🔮 Future
> **Predecessor:** v1.0.0
> **Goal:** Introduce role-based agent hierarchy where a main agent delegates to specialized managers who coordinate workers.

### Architecture

```text
Human User
  │
  ▼
Main Agent (receives tasks from human)
  │
  ├── Software Manager
  │     ├── Solution Architect
  │     ├─��� Milestone Planner
  │     ├── Phase Planner
  │     ├── Issues Planner
  │     ├── Tasks Planner
  │     ├── Coding Agent (can spawn multiple)
  │     ├── Code Reviewer
  │     ├── Security Reviewer
  │     ├── Test Writer
  │     └── Documentation Writer
  │
  ├── Personal Manager
  │     ├── Calendar Agent
  │     ├── Email Draft Agent
  │     └── Research Agent
  │
  └── Research Manager
        ├── Web Research Agent
        ├── Code Analysis Agent
        └── Summary Agent
```

### Escalation Chain

```text
Coding Agent has a doubt about architecture:
  1. Coding Agent → asks Issues Planner
  2. Issues Planner doesn't know → asks Phase Planner
  3. Phase Planner doesn't know → asks Milestone Planner
  4. Milestone Planner doesn't know → asks Solution Architect
  5. Solution Architect doesn't know → asks Software Manager
  6. Software Manager doesn't know → asks Main Agent
  7. Main Agent doesn't know → asks Human User

Cross-manager communication:
  Worker A (under Software Manager) needs info from Research Manager:
  1. Worker A → Software Manager (request)
  2. Software Manager → Research Manager (peer request)
  3. Research Manager → Research Agent (task)
  4. Research Agent → Research Manager (result)
  5. Research Manager → Software Manager (response)
  6. Software Manager → Worker A (answer)
```

### Manager Lifecycle

- If a manager is busy with one task and a new task arrives → spawn another instance of that manager type
- Each manager has its own budget (subset of main agent budget)
- User can set per-task budgets: "spend max $2 on this task"
- Managers can negotiate budget reallocation through main agent

### Additional Scenarios for Software Manager

1. **Conflict resolution**: Two coding agents modify the same file → manager detects via git status, pauses both, resolves conflict
2. **Quality gate**: All coding agent output goes through reviewer before merge
3. **Regression detection**: Test writer runs tests after each coding agent commit — failures cascade to coding agent
4. **Architecture drift**: Security reviewer checks every PR against architecture docs
5. **Dependency update**: Milestone planner tracks dependency versions, triggers upgrade tasks
6. **Documentation sync**: Documentation writer monitors code changes, triggers doc updates

---

## v1.2.0+ — Cross-Drive Access, Admin Elevation & OS Intelligence

> **Status:** 🔮 Future
> **Predecessor:** v1.1.0+
> **Goal:** Enable multi-drive access, OS-aware directory policies, and admin privilege management.

### Cross-Drive Access

```text
Current (v0.4.x):
  CeilingDirectory: C:\Users\username  ← only C: drive accessible

Proposed (v1.2.0):
  Per-drive policies:
  {
    "DriveAccess": {
      "C": {
        "CeilingDirectory": "C:\\Users\\username",
        "DepthRestriction": true,       // Enforce OS directory structure
        "RequireFullPath": true          // Must use C:\abc\abc format
      },
      "E": {
        "CeilingDirectory": "E:\\",
        "DepthRestriction": false,       // No depth enforcement
        "RequireFullPath": false          // Can use E:\* freely
      },
      "D": {
        "CeilingDirectory": "D:\\Projects",
        "DepthRestriction": false,
        "AutoGrant": true                // Auto-approve all under D:\Projects
      }
    }
  }
```

### OS-Aware Directory Intelligence

```text
On startup, detect OS directory structure:
  - Identify system directories (Windows, Program Files, System32)
  - Identify user profile directory
  - Identify common project directories (Projects, repos, src)
  - Identify temp directories
  - Identify OneDrive/cloud sync directories

Apply rules:
  System directories → Layer 1 deny (existing)
  User profile → ceiling (existing)
  Project directories → auto-grant patterns
  Temp directories → ReadWrite auto-grant, cleanup on session end
  Cloud sync → warn about sync conflicts
```

### Admin Elevation

```text
On application startup:
  Check if running as administrator:
    If YES → log warning, suggest running as normal user
    If NO → some operations will fail (e.g., symlink creation, service management)

  When agent needs admin permission:
    1. Agent detects operation requires elevation
    2. Prompt user: "This operation requires administrator privileges"
    3. Options:
       a. "Restart as administrator" → re-launch with runas
       b. "Skip this operation"
       c. "Never ask again for this session"
    4. On restart: preserve session state via temp file
```

---

## v1.3.0+ — Triggers, User Learning & Adaptive Personality

> **Status:** 🔮 Future
> **Predecessor:** v1.2.0+
> **Goal:** Time-based triggers for agent activation, cross-session user preference extraction, and adaptive agent behavior.

### Trigger System

```text
Trigger types:
  1. Time trigger:    "Run tests every day at 9:00 AM"
  2. File trigger:    "When package.json changes, run npm install"
  3. Git trigger:     "When main branch is updated, run build"
  4. Schedule trigger: "Every Friday at 5 PM, generate weekly summary"
  5. Event trigger:   "When build fails, notify via Telegram"

Implementation:
  Trigger → ISessionManager.CreateSessionAsync(triggerContext)
  → Agent runs with AutonomyLevel.SemiAutonomous
  → Budget capped per trigger
  → Results sent to configured notification channel
```

### Cross-Session User Preference Learning

```text
After each session (human-initiated only, not agent-initiated):
  Extract preferences:
    - Coding style (indentation, naming conventions, patterns used)
    - Approval patterns (what does user always approve? always deny?)
    - Tool usage patterns (which tools used most? which avoided?)
    - Communication style (brief responses preferred? detailed explanations?)
    - Time patterns (when does user typically interact?)

  Storage:
    user_preferences/
      coding_style.md        ← "User prefers 4-space indentation, PascalCase methods"
      approval_patterns.md   ← "User always approves git commit, often denies npm install"
      interaction_style.md   ← "User prefers brief responses with code examples"

  Session tagging:
    Each session tagged with:
      - Primary activity (coding, debugging, research, configuration)
      - Languages used
      - Duration and engagement level
      - Satisfaction signals (user said "thanks", "perfect", "wrong")

  Learning rules:
    - Only learn from human-user sessions (not agent-automated sessions)
    - Preferences are advisory (included in system prompt layer), not policy
    - User can /reset-preferences to clear learned behavior
    - Preferences never override security boundaries
```

### Adaptive Personality

```text
Based on accumulated preferences:
  - Adjust verbosity (concise vs detailed based on user history)
  - Adjust proactivity (suggest next steps vs wait for instructions)
  - Adjust explanation depth (expert user vs learning user)
  - Remember user's project context across sessions
  - Anticipate common follow-up questions

Security boundary:
  Adaptation is cosmetic (communication style) — NEVER affects:
  - Tool execution policies
  - Security boundaries
  - Approval requirements
  - Budget limits
```

---

## Deferred / Parked Items

Items explicitly evaluated and deferred. Re-evaluate at the noted version.

| Item | Deferred From | Re-evaluate At | Reason |
|------|--------------|----------------|--------|
| `retry-after` header parsing | v0.4.5 | When Anthropic SDK exposes header | SDK limitation (blocked) |
| Mid-stream rate limit retry | v0.4.5 | v0.6.0 | Not observed in practice |
| Compaction mid-stream failure retry | v0.4.5 | v0.6.0 | Acceptable as-is |
| Tool result pruning config UI | v0.4.5 | v0.5.0 | Low priority, defaults work well |
| Dynamic trust progression | v0.3.0 (ADR-013) | Never | Rejected — creates trust-building attack vector |
| Self-modification capabilities | v0.4.0 | v0.8.0+ | Requires mature approval framework |
| Remote skill marketplace | v0.1.0 (ADR-008) | Never (current) | Supply-chain attack risk too high |
| Batch API usage | v0.1.0 (ADR-004) | Re-evaluate when ZDR batch available | Privacy posture requirement |

---

## Dependency Map (Version → Version)

```text
v0.4.6 depends on: v0.4.5 ✅
  └── Project restructuring, test coverage, v0.5.0 interfaces

v0.5.0 depends on: v0.4.6
  └── Autonomy levels, task budgets, git checkpoints, anomaly detection

v0.6.0 depends on: v0.5.0
  └── Vector search builds on session/memory infrastructure from v0.5.0
  └── Embedding generation uses budget tracking from v0.5.0

v0.7.0 depends on: v0.6.0
  └── Web content stored in vector memory
  └── Search results use hybrid retrieval

v0.8.0 depends on: v0.7.0
  └── Prompt caching optimizes all content from v0.1.0-v0.7.0
  └── Model flexibility affects all tool/security interactions

v0.9.0 depends on: v0.8.0
  └── Multi-agent uses CorrelationContext.AgentId (v0.4.0)
  └── Sub-agent budgets use ITaskBudgetTracker (v0.5.0)
  └── Parent-child communication uses session infrastructure

v1.0.0 depends on: v0.9.0
  └── Integration testing of all features together
  └── Packaging and deployment story

v1.1.0+ depends on: v1.0.0
  └── Agent pool extends multi-agent (v0.9.0)

v1.2.0+ depends on: v1.1.0+
  └── Cross-drive policies extend access policy engine (v0.2.0)

v1.3.0+ depends on: v1.2.0+
  └── Learning uses vector memory (v0.6.0) for preference storage
  └── Triggers use session manager (v0.4.0)
```

---

## Related Documents

| Document | Path | Description |
|----------|------|-------------|
| v0.1.0 Spec | `docs/versions/v0.1.0.md` | Core agent and security foundation |
| v0.2.0 Spec | `docs/versions/v0.2.0.md` | Dynamic directory scoping |
| v0.3.0 Spec | `docs/versions/v0.3.0.md` | Graduated command execution |
| v0.4.0 Spec | `docs/versions/v0.4.0.md` | Telegram integration & multi-session |
| v0.4.5 Spec | `docs/versions/v0.4.5.md` | Session resilience & context intelligence |
| Architecture Decisions | `docs/architecture/DECISIONS.md` | ADR-001 through ADR-013 |
| Architecture Overview | `docs/architecture/OVERVIEW.md` | Component architecture |
| Security Model | `docs/architecture/SECURITY.md` | Security boundaries and threat model |
| Pending Tasks | `docs/status/PENDING-TASKS.md` | Deferred items from v0.4.0/v0.4.5 |
| Progress Tracker | `docs/status/PROGRESS.md` | Issue-by-issue completion tracking |
| Changelog | `CHANGELOG.md` | Keep a Changelog format, all versions |
| Agent Instructions | `AGENTS.md` | Copilot coding agent instructions |
| Release Lifecycle | `release-lifecycle.txt` | PLAN → DEVELOP → STABILIZE → RELEASE → MAINTAIN |

---

> **Next Action:** Begin v0.4.6 planning — create issues for project restructuring and v0.5.0 prerequisite interfaces.
>
> **Review Schedule:** This roadmap should be reviewed and updated:
> - Before each version's planning kickoff
> - After each version's release (update status, test counts, dates)
> - When significant user feedback or external changes (SDK updates, security advisories) require reprioritization
