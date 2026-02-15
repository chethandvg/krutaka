# Krutaka — Multi-Session Architecture

> **Last updated:** 2026-02-14 (v0.4.0 initial architecture)
>
> This document describes the multi-session isolation model introduced in v0.4.0.
> It is **mandatory reading** before implementing any code that creates, manages, or interacts with sessions.
>
> **Version spec:** See `docs/versions/v0.4.0.md` for the complete v0.4.0 design.

---

## 1. Problem Statement

### Why Singleton DI Breaks

In v0.3.0, every mutable, session-specific component is registered as `AddSingleton` in `Program.cs`:

```csharp
// Current v0.3.0 — everything is singleton
builder.Services.AddSingleton(sp => new CorrelationContext(sessionId));
builder.Services.AddSingleton<AgentOrchestrator>(...);
builder.Services.AddSingleton(sp => new SessionStore(workingDirectory, sessionId));
```

If two concurrent operations (e.g., two Telegram chats) share these singletons:

| Shared State | Corruption |
|---|---|
| `AgentOrchestrator._conversationHistory` | Messages from Chat A appear in Chat B's context |
| `AgentOrchestrator._approvalCache` | Tool "always approve" from User A applies to User B |
| `CorrelationContext.SessionId` / `TurnId` | Audit log entries attributed to wrong session |
| `ISessionAccessStore` grants | Directory grant from User A allows User B to access that directory |
| `ICommandApprovalCache` | Command approval from User A auto-approves same command for User B |
| `SessionStore` JSONL | Events from both sessions written to the same file |

**Result:** Security violation, audit corruption, and unpredictable behavior.

### Why This Matters Now

v0.4.0 introduces Telegram Bot API as a remote interface. Multiple Telegram users send messages concurrently. Each chat must be an isolated session with its own state.

---

## 2. Session Isolation Model

### Shared vs Per-Session Components

| Component | Scope | Instance Count | Rationale |
|---|---|---|---|
| `IClaudeClient` | **Shared** (Singleton) | 1 | Stateless HTTP client, thread-safe. Wraps Anthropic SDK. |
| `ISecurityPolicy` | **Shared** (Singleton) | 1 | Stateless validation rules (allowlist, blocklist, metacharacters). Immutable after startup. |
| `IAuditLogger` | **Shared** (Singleton) | 1 | Thread-safe Serilog logger. Events tagged with per-session CorrelationContext. |
| `IAccessPolicyEngine` | **Shared** (Singleton) | 1 | Stateless policy evaluation (Layer 1 deny-list, Layer 2 glob patterns, Layer 4 heuristics). Layer 3 session grants are per-session via `ISessionAccessStore`. |
| `ICommandRiskClassifier` | **Shared** (Singleton) | 1 | Stateless tier classification rules. Reads from immutable config. |
| `ToolOptions` | **Shared** (Singleton) | 1 | Immutable configuration loaded at startup. |
| `AgentOrchestrator` | **Per-Session** | N | `_conversationHistory`, `_turnLock`, `_approvalCache`, `_pendingApproval` — all mutable per-session state. |
| `CorrelationContext` | **Per-Session** | N | Mutable `SessionId`, `TurnId`, `RequestId`, `AgentId`. |
| `SessionStore` | **Per-Session** | N | Writes to session-specific JSONL file. |
| `ISessionAccessStore` | **Per-Session** | N | Directory grants scoped to session. Created by factory as `InMemorySessionAccessStore`. |
| `ICommandApprovalCache` | **Per-Session** | N | Command-signature-level approvals from v0.3.0. |
| `ContextCompactor` | **Per-Session** | N | References per-session `CorrelationContext` for audit logging during compaction. |
| `IToolRegistry` | **Per-Session** | N | Tools scoped to session's working directory (`ProjectPath`). |

### Two Approval Caches

The orchestrator contains TWO separate approval caches. Both must be per-session:

1. **`_approvalCache`** — internal `ConcurrentDictionary<string, bool>` inside `AgentOrchestrator`. Tracks per-tool "always approve" decisions (e.g., "always approve `write_file`"). **Automatically per-session** because it's created in the orchestrator constructor.

2. **`_commandApprovalCache`** — DI-injected `ICommandApprovalCache`. Tracks command-signature-level approvals for the v0.3.0 graduated command execution (e.g., "approve `dotnet build`"). **Must be explicitly created per-session** by `ISessionFactory`.

---

## 3. Component Relationships

```text
ISessionFactory                     ISessionManager
     │                                   │
     │ Create(SessionRequest)            │ CreateSessionAsync()
     ▼                                   │ GetOrCreateByKeyAsync()
┌──────────────┐                        │ ResumeSessionAsync()
│ ManagedSession│◄───────────────────────│ TerminateSessionAsync()
│              │                        │ ListActiveSessions()
│ SessionId    │                        │ TerminateAllAsync()
│ ProjectPath  │                        ▼
│ ExternalKey  │               ┌──────────────────┐
│ State        │               │  SessionManager  │
│ Budget       │               │                  │
│ Orchestrator │               │ ConcurrentDict   │
│ CorrelationCtx│              │ <Guid, Session>  │
│ LastActivity │               │                  │
└──────────────┘               │ ConcurrentDict   │
                               │ <string, Guid>   │
                               │ (external keys)  │
                               │                  │
                               │ IdleTimer        │
                               │ EvictionLogic    │
                               │ BudgetTracker    │
                               └──────────────────┘
```

### Key Types

| Type | Kind | Location | Purpose |
|---|---|---|---|
| `ISessionFactory` | Interface | `Krutaka.Core` | Creates fully isolated `ManagedSession` instances |
| `ISessionManager` | Interface | `Krutaka.Core` | Lifecycle management: create, idle, suspend, resume, terminate |
| `ManagedSession` | Sealed Class | `Krutaka.Core` | Holds per-session components, implements `IAsyncDisposable` |
| `SessionRequest` | Record | `Krutaka.Core` | Describes how to create a session (ProjectPath, ExternalKey, budgets) |
| `SessionState` | Enum | `Krutaka.Core` | Active, Idle, Suspended, Terminated |
| `SessionBudget` | Class | `Krutaka.Core` | Thread-safe token/tool-call/turn tracking with exhaustion check |
| `SessionManagerOptions` | Record | `Krutaka.Core` | MaxActiveSessions, IdleTimeout, SuspendedTtl, per-user limits, eviction |
| `SessionSummary` | Record | `Krutaka.Core` | Lightweight view of a session for listing |
| `EvictionStrategy` | Enum | `Krutaka.Core` | SuspendOldestIdle, RejectNew, TerminateOldest |
| `SessionFactory` | Class | Implementation project | Creates per-session instances, wires shared + per-session services |
| `SessionManager` | Class | Implementation project | Lifecycle management with concurrent dictionaries, idle timer, eviction |

---

## 4. Session Lifecycle State Machine

```text
  Created ──► Active ──► Idle (no messages for IdleTimeout)
                │              │
                │              ▼
                │        Suspended
                │        (orchestrator disposed, JSONL on disk)
                │              │
                │              ├── Resume (new message arrives)
                │              │   → SessionStore.ReconstructMessagesAsync()
                │              │   → orchestrator.RestoreConversationHistory()
                │              │
                │              └── Expired (SuspendedTtl reached)
                │                  → Fully removed from tracking
                │
                └── Terminated (user /killswitch, admin, or explicit)
                    → ManagedSession.DisposeAsync() called
                    → Orchestrator.Dispose() called (synchronous)
                    → Resources released
```

### State Transitions

| From | To | Trigger | Actions |
|---|---|---|---|
| — | Active | `CreateSessionAsync` | Factory creates all per-session instances |
| Active | Idle | No messages for `IdleTimeout` | Background timer transitions state |
| Active | Terminated | Explicit terminate, /killswitch, or budget exhaustion | `ManagedSession.DisposeAsync()` |
| Idle | Suspended | Idle timer fires | Dispose orchestrator (free memory), keep JSONL on disk |
| Idle | Active | New message arrives | `UpdateLastActivity()` resets timer |
| Suspended | Active | Resume request | Create new orchestrator, restore from JSONL via `ReconstructMessagesAsync` |
| Suspended | Terminated | `SuspendedTtl` expired, or explicit terminate | Remove from tracking, optionally delete JSONL |
| Terminated | — | Final state | All resources released, removed from all dictionaries |

---

## 5. Resource Governance

| Resource | Limit | Default | Enforcement |
|---|---|---|---|
| Active sessions | `MaxActiveSessions` | 10 | SessionManager rejects or evicts per `EvictionStrategy` |
| Sessions per user | `MaxSessionsPerUser` | 3 | SessionManager counts by `SessionRequest.UserId` |
| Tokens per session | `SessionBudget.MaxTokens` | 200,000 | `SessionBudget.IsExhausted` check before each prompt |
| Tool calls per session | `SessionBudget.MaxToolCalls` | 100 | `SessionBudget.IsExhausted` check before each tool call |
| Tokens globally per hour | `GlobalMaxTokensPerHour` | 1,000,000 | SessionManager cumulative tracking across all sessions |
| Idle timeout | `IdleTimeout` | 15 min | Background timer transitions idle sessions |
| Suspended session TTL | `SuspendedTtl` | 24 hours | Background timer removes expired suspended sessions |

### Eviction Strategies

| Strategy | Behavior | When |
|---|---|---|
| `SuspendOldestIdle` | Suspend the session with the oldest `LastActivity` | Default — graceful, preserves data |
| `RejectNew` | Throw exception, refuse to create session | Strict capacity enforcement |
| `TerminateOldest` | Terminate the oldest session entirely | Aggressive — frees maximum resources |

---

## 6. Console Migration Path

✅ **Status:** Complete (2026-02-15, Issue #160)

`Program.cs` has been successfully migrated from singleton orchestrator to `ISessionManager` as a "single-session client":

### Before (v0.3.0)

```text
Program.cs:
  Register singleton AgentOrchestrator
  Register singleton CorrelationContext
  Register singleton SessionStore
  Main loop: orchestrator.RunAsync(input)
```

### After (v0.4.0) — Implemented

```text
Program.cs:
  Register ISessionFactory (singleton) — via ServiceExtensions.AddAgentTools()
  Register ISessionManager (singleton) — via ServiceExtensions.AddAgentTools()
  Register SessionManagerOptions (singleton) — MaxActiveSessions: 1, IdleTimeout: Zero
  
  On startup:
    session = sessionManager.ResumeSessionAsync() + SessionStore.ReconstructMessagesAsync() + RestoreConversationHistory()
    OR session = sessionManager.CreateSessionAsync(request)
  
  Main loop:
    session.Orchestrator.RunAsync(input)
    Access correlation context via session.CorrelationContext (not global DI)
    Create SystemPromptBuilder using session's tool registry (via reflection)
  
  /new command:
    sessionManager.TerminateSessionAsync(session.SessionId)
    session = sessionManager.CreateSessionAsync(request)
  
  /sessions command:
    sessionManager.ListActiveSessions() + SessionStore.ListSessions()
  
  /resume command:
    SessionStore.ReconstructMessagesAsync() + session.Orchestrator.RestoreConversationHistory()
  
  On shutdown:
    sessionManager.DisposeAsync()
```

### Implementation Details

**DI Cleanup (ServiceExtensions.cs):**
- ❌ Removed `ICommandApprovalCache` singleton (now per-session)
- ❌ Removed `ISessionAccessStore` singleton (now per-session)
- ❌ Removed `IToolRegistry` and all `ITool` singleton registrations (now per-session)
- ✅ Global `IAccessPolicyEngine` uses `sessionStore: null` (Layer 1 & 2 only)

**DI Cleanup (Program.cs):**
- ❌ Removed `CorrelationContext` singleton (accessed via `session.CorrelationContext`)
- ❌ Removed `ICorrelationContextAccessor` singleton (per-session instance)
- ❌ Removed `SessionStore` singleton (created per-session in main loop)
- ❌ Removed `ContextCompactor` singleton (created per-session by SessionFactory)
- ❌ Removed `AgentOrchestrator` singleton (created per-session by SessionFactory)
- ❌ Removed `SystemPromptBuilder` singleton (created per-session using session's tool registry)
- ✅ Added `SessionManagerOptions` configuration

**Three-Step Resume Pattern:**
```csharp
// Step 1: Resume session (creates new orchestrator, no history)
var session = await sessionManager.ResumeSessionAsync(sessionId, projectPath, ct);

// Step 2: Load conversation history from JSONL on disk
var sessionStore = new SessionStore(projectPath, session.SessionId);
var messages = await sessionStore.ReconstructMessagesAsync(ct);

// Step 3: Restore history into the orchestrator
if (messages.Count > 0)
{
    session.Orchestrator.RestoreConversationHistory(messages);
}
```

### Key Invariant

Console mode behavior is **identical to v0.3.0** from a user perspective. The SessionManager simply wraps the singleton pattern into a single-session management model. All existing commands, streaming, approvals, and auto-resume work exactly as before.

### Verification

- ✅ All 1,424 tests passing (845 Tools, 305 Core, 131 Memory, 116 Console, 17 Skills, 10 AI, 1 skipped)
- ✅ Build succeeds with zero warnings/errors
- ✅ No singleton registrations for mutable per-session state
- ✅ Behavioral parity with v0.3.0 verified

---

## 7. Dispose Pattern

### AgentOrchestrator — IDisposable (Synchronous)

`AgentOrchestrator` implements `IDisposable`, **NOT** `IAsyncDisposable`. Its `Dispose()` method only releases the `SemaphoreSlim` (`_turnLock`). This is a synchronous operation.

**Do NOT change `AgentOrchestrator` to `IAsyncDisposable`.** It has no async resources to dispose.

### ManagedSession — IAsyncDisposable

`ManagedSession` implements `IAsyncDisposable`. Its `DisposeAsync()` method:

1. Transitions state to `Terminated`
2. Calls `Orchestrator.Dispose()` **synchronously** (since it's `IDisposable`)
3. Performs any other async cleanup (e.g., flushing session store)

```csharp
public async ValueTask DisposeAsync()
{
    if (State == SessionState.Terminated)
        return; // Already disposed
    
    State = SessionState.Terminated;
    
    // Synchronous dispose — AgentOrchestrator.Dispose() releases SemaphoreSlim
    Orchestrator.Dispose();
    
    // Any async cleanup here (e.g., session store flush)
    await Task.CompletedTask; // Placeholder if no async cleanup needed
}
```

### SessionManager — IAsyncDisposable

`SessionManager` implements `IAsyncDisposable`. Its `DisposeAsync()` calls `TerminateAllAsync()` which disposes all active `ManagedSession` instances.

---

## 8. Future Multi-Agent Hook (v0.9.0)

`ManagedSession` is designed so that in v0.9.0, an `IAgentPool` can be hosted within a session:

```text
v0.4.0:
  ManagedSession
    └── Orchestrator (single agent per session)

v0.9.0 (future):
  ManagedSession
    └── IAgentPool
          ├── Agent A (primary orchestrator)
          ├── Agent B (sub-agent for code review)
          └── Agent C (sub-agent for testing)
```

`CorrelationContext` is extended in v0.4.0 with `AgentId` (Guid?), `ParentAgentId` (Guid?), and `AgentRole` (string?) fields. These are `null` in v0.4.0 but prevent an audit log schema break when multi-agent coordination is introduced. Each agent within a session would have its own `CorrelationContext` with a unique `AgentId`, sharing the session's `SessionId`.

---

## Related Documents

- `docs/versions/v0.4.0.md` — Complete v0.4.0 version specification
- `docs/architecture/TELEGRAM.md` — Telegram security architecture
- `docs/architecture/OVERVIEW.md` — Component architecture
- `docs/architecture/SECURITY.md` — Security model
- `src/Krutaka.Core/AgentOrchestrator.cs` — Per-session orchestrator (implements `IDisposable`)
- `src/Krutaka.Core/CorrelationContext.cs` — Per-session correlation tracking
- `src/Krutaka.Memory/SessionStore.cs` — JSONL session persistence
- `src/Krutaka.Console/Program.cs` — Current singleton pattern (to be refactored)
