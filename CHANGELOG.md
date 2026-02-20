# Changelog

All notable changes to Krutaka will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.6] - 2026-02-20

### Changed
- **Project restructuring — all 7 source projects organized into logical subdirectories** (#205–#211): All `.cs` files moved from flat project roots into category subdirectories (`Abstractions/`, `Models/`, `Orchestration/`, `Session/`, `FileTools/`, `Access/`, `Policies/`, `Auth/`, `Streaming/`, `Approval/`, etc.). No namespace changes, no behavioral changes. SDK-style `.csproj` wildcard includes mean zero build configuration changes required.
- **Test projects restructured to mirror source project layouts** (#212): Test files moved into subdirectories matching their corresponding source project structure (e.g., `tests/Krutaka.Memory.Tests/Storage/SessionStoreTests.cs` mirrors `src/Krutaka.Memory/Storage/SessionStore.cs`).

### Added
- **Per-project README.md files** (#205–#211): All 7 source projects (`Krutaka.Core`, `Krutaka.Tools`, `Krutaka.Memory`, `Krutaka.Skills`, `Krutaka.AI`, `Krutaka.Telegram`, `Krutaka.Console`) have a standardized `README.md` documenting purpose, responsibilities, directory layout, dependencies, and used-by relationships.
- **Dedicated SessionManager and SessionFactory tests** (#213, #214): ~80 new tests covering session lifecycle (create, suspend, resume, terminate, idle, eviction), budget tracking, per-session isolation guarantees, and DI registration verification.
- **Bootstrap file truncation INFO-level logging** (#215): `SystemPromptBuilder` logs at INFO level when individual bootstrap files (AGENTS.md, MEMORY.md) are truncated at the per-file cap (20K chars), and at WARNING level when the total bootstrap content exceeds the total cap (150K chars). Added `Debug.Assert` guard ensuring Layer 2 security instructions are never subject to truncation.
- **ADR-014: In-Memory Tool Result Pruning** (#215): Documents the decision to prune tool results in-memory only (not in JSONL session files), rationale (audit trail integrity), and alternatives considered.
- **`docs/guides/PRODUCTION-DEPLOYMENT.md`** (#216): Production deployment guide covering Windows Service installation, secrets management under service accounts, headless Telegram-only mode, log rotation, health monitoring, backup strategy, and update/rollback procedures.
- **`docs/guides/TROUBLESHOOTING.md`** (#216): Centralized troubleshooting guide covering all common issues: API key not found, Telegram user not authorized, session resume crash, rate limit exceeded, compaction failures, bot not responding, and tests failing after file moves.
- **`docs/roadmap/ROADMAP.md`** (#204): Forward-looking roadmap covering v0.5.0 (Autonomous Agent Mode) through v1.3.0+, including Autonomous Agent Mode, Multi-Agent Orchestration, Plugin Ecosystem, and Enterprise Features.
- **v0.5.0 prerequisite type stubs** (#217, #218): Defined in `Krutaka.Core` as definitions only (no implementations):
  - `AutonomyLevel` enum — `Supervised`, `Guided`, `SemiAutonomous`, `Autonomous`
  - `TaskBudget` record — Max Claude tokens, tool calls, files modified, processes spawned
  - `BudgetDimension` enum — `Tokens`, `ToolCalls`, `FilesModified`, `ProcessesSpawned`
  - `TaskBudgetSnapshot` record — Raw counters and percentage values
  - `ITaskBudgetTracker` interface — `TryConsume`, `GetSnapshot`, `IsExhausted`
  - `CheckpointInfo` record — Checkpoint ID, message, creation time, files modified
  - `AnomalySeverity` enum — `None`, `Low`, `Medium`, `High`
  - `AnomalyAssessment` record — `IsAnomalous`, optional `Reason`, `Severity`
  - `AgentBehaviorSnapshot` record — Behavioral metrics (tool call frequency, repeated failures, etc.)
  - `IGitCheckpointService` interface — `CreateCheckpointAsync`, `RollbackToCheckpointAsync`, `ListCheckpointsAsync`
  - `IBehaviorAnomalyDetector` interface — `AssessAsync`

## [0.4.5] - 2026-02-19

### Fixed
- **Orphaned `tool_use` blocks causing `AnthropicBadRequestException` crash on session resume** (#181): Session resume with orphaned `tool_use` blocks (tool calls without matching `tool_result`) caused unhandled API error and crashed main loop. Fixed by:
  - Normalizing `tool_use` input serialization in `CreateAssistantMessage()` — parse string to `JsonElement` to prevent double-serialization during JSONL round-trip
  - Hardening `RepairOrphanedToolUseBlocks()` with graceful handling of unknown content block types (forward compatibility)
  - Adding post-repair validation in `ReconstructMessagesAsync()` — drops orphaned assistant messages if invariant still doesn't hold after repair
- **`CompactIfNeededAsync` failure propagating as unhandled exception** (#181): Compaction failure (e.g., during token counting with malformed history) crashed the agentic loop. Fixed by wrapping compaction call in try-catch — compaction is optimization, not correctness requirement. Loop continues on failure.
- **`tool_use` input stored as string instead of `JsonElement`** (#181): `CreateAssistantMessage()` stored `toolCall.Input` (string) as-is, causing JSON round-trip corruption. Fixed by parsing to `JsonElement` before storing (fall back to `{}` if parsing fails).
- **Rate limit (HTTP 429) from Anthropic API crashing agentic loop** (#182): Single rate limit response crashed loop with no retry. Fixed by implementing exponential backoff with jitter (max 3 retries, 1s–30s delay) in `ClaudeClientWrapper.SendMessageAsync()` and `CountTokensAsync()`.
- **`AnthropicBadRequestException` in main loop leaving session corrupted with no recovery** (#183): API errors left session in corrupted state with no user-facing recovery options. Fixed by adding error recovery in Console main loop — offers "Reload session" and "Start new session" options on API errors.

### Added
- **Post-repair validation for session message history** (#181): After `RepairOrphanedToolUseBlocks()` runs, `ValidateAndRemoveOrphanedAssistantMessages()` re-scans all messages to verify invariant (every `tool_use` has matching `tool_result`). Drops orphaned assistant messages entirely if repair fails.
- **Exponential backoff with jitter for Anthropic API rate limits** (#182): Configurable retry logic with max 3 attempts, 1s–30s delay cap, ±25% jitter using cryptographically secure RNG. Prevents thundering herd and API exhaustion.
- **`retry-after` header parsing readiness** (#182): Code structure supports parsing `retry-after` header from Anthropic rate limit responses (deferred until SDK exposes header in `AnthropicRateLimitException`).
- **Error recovery in Console main loop** (#183): Specific `AnthropicBadRequestException` handler offers "Reload session" (re-read JSONL + run repair) and "Start new session" (clear history) options. Prevents session loss on API errors.
- **Directory awareness in system prompt** (#184): Claude knows `DefaultWorkingDirectory`, `CeilingDirectory`, and `AutoGrantPatterns` via Layer 3c (Environment Context) in `SystemPromptBuilder`. Eliminates working directory confusion.
- **Bootstrap file size caps** (#185): Per-file limit (20K chars) and total limit (150K chars) with truncation markers `[... truncated at 20,000 chars. Use read_file for full content ...]`. Layer 2 (security instructions) always full-length, never truncated.
- **Pre-compaction memory flush to MEMORY.md** (#186): Before compaction triggers, `ContextCompactor` extracts key decisions, file paths, and progress from conversation and writes to MEMORY.md via `MemoryFileService`. Preserves context that would be lost during summarization.
- **Tool result pruning for older conversation turns** (#187): Trims large tool results (>1K chars) older than 6 turns in API calls only. Replaces with `[Previous tool result truncated — {X} chars. Use read_file to re-read if needed.]`. Reduces token waste without modifying JSONL.
- **Compaction events recorded in JSONL session files** (#188): `SessionStore` writes compaction metadata (summary, tokensBefore, tokensAfter, messagesRemoved, timestamp) to JSONL after `CompactAsync()`. Skipped during message reconstruction — informational only for debugging.
- **Adversarial test suites for session resilience, rate limiting, and tool result pruning** (#189):
  - `SessionResumeAdversarialTests.cs` — Mass orphan scenario, worst-case double-serialization, empty conversation edge cases (7 tests)
  - `RateLimitAdversarialTests.cs` — Configuration validation, boundary conditions, jitter variance, cancellation handling (27 tests)
  - `ConversationPrunerTests.cs` — Boundary pruning, mixed content, error flag preservation, immutability verification (13 adversarial tests)
- **~152 new tests across Memory, Core, AI, and Console test projects** — Brings total to **1,917 tests passing (2 skipped)**. Key test additions include:
  - 7 in `SessionResumeRepairTests.cs`
  - 30 in `ClaudeClientRetryTests.cs` (includes 10 validation tests)
  - 10 in `ErrorRecoveryTests.cs`
  - 8 in `DirectoryAwarenessTests.cs`
  - 7 in `BootstrapFileCapsTests.cs`
  - 13 in `PreCompactionFlushTests.cs`
  - 10 in `ConversationPrunerTests.cs`
  - 10 in `CompactionEventTests.cs`
  - 7 in `SessionResumeAdversarialTests.cs`
  - 27 in `RateLimitAdversarialTests.cs` (includes 4 ExecuteWithRetryAsync validation tests)
  - 13 adversarial additions to `ConversationPrunerTests.cs`
  - Plus additional test modifications and enhancements across existing test suites

### Changed
- **`ClaudeClientWrapper.SendMessageAsync()` and `CountTokensAsync()` now retry on rate limits**: Both methods wrapped with `ExecuteWithRetryAsync()` helper. Retries only `AnthropicRateLimitException`, not other API errors (e.g., `AnthropicBadRequestException`). Mid-stream rate limits (unlikely) propagate without retry.
- **`AgentOrchestrator.CompactIfNeededAsync()` wrapped in try-catch**: Compaction failure logs error and skips compaction. Agentic loop continues without crashing. Suppressed CA1031 analyzer warning with pragma (intentional catch-all).
- **`AgentOrchestrator.CreateAssistantMessage()` stores `tool_use` input as `JsonElement` instead of string**: Parse `toolCall.Input` (string) to `JsonElement` using `JsonDocument.Parse()`. Fall back to `{}` if parsing fails. Prevents double-serialization during JSONL round-trip.
- **`SystemPromptBuilder.BuildAsync()` includes Layer 3c (Environment Context) and enforces bootstrap file caps**: Layer 3c injected after Layer 3b (Command Tier Information), includes working directory paths and auto-grant patterns. Bootstrap caps applied to Layer 1 (core identity) and Layer 5 (MEMORY.md), never Layer 2 (security).
- **`ContextCompactor.CompactAsync()` performs pre-compaction memory flush before summarization**: If `_memoryWriter` delegate provided, extracts critical context from conversation and writes to MEMORY.md. Then proceeds with normal compaction. Console shows brief "📝 Saving context..." indicator; Telegram silent.
- **`SessionStore` writes compaction events to JSONL and skips them during message reconstruction**: New event type `"compaction"` written after `CompactAsync()` completes. `ReconstructMessagesAsync()` skips compaction events (lines 142–146) — informational only, not part of conversation sent to Claude.
- **Console main loop has specific `AnthropicBadRequestException` handler with recovery options**: Catches `AnthropicBadRequestException` separately from generic exceptions. Displays error message and interactive menu: "Reload session" (1) or "Start new session" (2). Prevents session loss on API errors.

### Security
- **Synthetic `tool_result` blocks always have `is_error = true`** (T1 mitigation): `RepairOrphanedToolUseBlocks` injects synthetic results marked as errors — cannot fabricate successful results that influence Claude behavior (verified line 354 in `SessionStore.cs`).
- **Tool result pruning modifies only in-memory snapshots** (T3 mitigation): `PruneOldToolResults()` returns new list (line 1305 in `AgentOrchestrator.cs`), original JSONL files never modified. Permanent history intact for audit trail.
- **Pre-compaction memory flush wraps conversation content in `<untrusted_content>` tags** (T2 mitigation): Conversation content wrapped in `<untrusted_content>` tags (lines 347, 439 in `ContextCompactor.cs`) before sending to Claude for extraction. Prevents prompt injection via conversation history.
- **Bootstrap file caps never truncate Layer 2 hardcoded security instructions** (T4 mitigation): `GetSecurityInstructions()` returns hardcoded string (lines 207–211 in `SystemPromptBuilder.cs`), never loaded from files. Cap enforcement logic explicitly skips Layer 2 (line 585).
- **Max 3 retries with exponential backoff prevents retry amplification** (T5 mitigation): Retry loop capped at 3 attempts (line 471 in `ClaudeClientWrapper.cs`), SDK retries disabled (`MaxRetries = 0` line 53 in `ServiceExtensions.cs`). Prevents DoS via forced retries.
- **Compaction events are informational only** (T6 mitigation): `ReconstructMessagesAsync()` skips compaction events (lines 142–146 in `SessionStore.cs`). Tampered events cannot affect message reconstruction.

## [0.4.0] - 2026-02-17

### Added
- **Multi-session architecture**: Transform from single-session console app to multi-session, multi-interface platform
  - `ISessionFactory` and `SessionFactory` — Creates isolated per-session agent instances with independent state
  - `ISessionManager` — Manages session lifecycle (create, idle, suspend, resume, terminate) with resource governance
  - `ManagedSession` — Per-session container with budget tracking, state machine, and disposal pattern
  - `SessionRequest`, `SessionState` enum, `SessionBudget` — Core session abstractions in `Krutaka.Core`
  - `SessionManagerOptions` — Configure max active sessions (default: 10), idle timeout (30 min), suspended session TTL (24 hours)
  - Session eviction strategies — Idle timeout auto-suspend, TTL-based cleanup, LRU eviction when max sessions reached
  - Per-session isolation for all mutable state — `AgentOrchestrator`, `CorrelationContext`, `SessionStore`, `ISessionAccessStore`, `ICommandApprovalCache`, `IToolRegistry` are scoped per session, not singleton
  - Shared stateless services remain singleton — `IClaudeClient`, `ISecurityPolicy`, `IAuditLogger`, `IAccessPolicyEngine`, `ICommandRiskClassifier`, `ToolOptions`
- **CorrelationContext agent identity fields**: Added `AgentId`, `ParentAgentId`, `AgentRole` properties for multi-agent context propagation
  - `SetAgentContext(Guid, Guid?, string)` method with role validation
  - Conditional audit log field inclusion when `AgentId` is non-null (backward compatible)
- **Krutaka.Telegram project** — New composition root for Telegram Bot API integration (7+7 projects total)
  - `TelegramBotService` — Background service implementing long polling and webhook support
  - Dual-mode polling service supports both long polling (default) and webhook (production)
  - `ITelegramAuthGuard` and `TelegramAuthGuard` — User allowlist, rate limiting (10 cmd/min default), lockout (3 attempts → 1 hour), anti-replay tracking
  - `ITelegramCommandRouter` and `TelegramCommandRouter` — 12 supported commands (`/start`, `/help`, `/status`, `/pause`, `/resume`, `/restart`, `/cancel`, `/info`, `/debug`, `/killswitch`, `/sessions`, `/newsession`)
  - `ITelegramResponseStreamer` and `TelegramResponseStreamer` — MarkdownV2 formatting, 4,096-byte chunking, rate limit compliance (20 msg/min user, 30 msg/sec global)
  - `ITelegramApprovalHandler` and `TelegramApprovalHandler` — Inline keyboard approval flow with tier-specific panels (Safe/Moderate/Elevated), HMAC-SHA256 signed callbacks, nonce-based replay prevention
  - `CallbackDataSigner` — HMAC-SHA256 signature generation and validation for callback tampering prevention (32-byte secret, base64url encoding)
  - `ITelegramSessionBridge` and `TelegramSessionBridge` — Session routing (DM → user-scoped, group → chat-scoped), multi-session coordination
  - `ITelegramFileHandler` and `TelegramFileHandler` — File upload/download with security validation (10 MB limit, access policy checks, path hardening)
  - `ITelegramHealthMonitor` and `TelegramHealthMonitor` — Health checks, budget threshold alerts (80% token, 90% tool call, 95% turn warnings), admin-only push notifications
  - `TelegramInputSanitizer` — Wrap all Telegram text in `<untrusted_content source="telegram:user:{userId}">` tags, Unicode NFC normalization, Telegram entity stripping
  - `TelegramMarkdownV2Formatter` — Escape MarkdownV2 special characters for safe output formatting
  - `PollingLockFile` — Single-instance lock to prevent polling conflicts
  - `TelegramSecurityConfig`, `TelegramUserConfig`, `TelegramUserRole` — Configuration models in `Krutaka.Core` for DI and validation
  - `TelegramConfigValidator` — Startup validation (AllowedUsers non-empty, duplicate UserId check, webhook URL validation)
- **Telegram security configuration and startup validation**:
  - `TelegramSecurityConfig.AllowedUsers` — Array of authorized users with UserId (numeric), Role (User/Admin), optional ProjectPath
  - Empty AllowedUsers array = bot refuses to start (fail-fast validation)
  - Bot token NEVER in config files — loaded via `ISecretsProvider` (Windows Credential Manager) or `KRUTAKA_TELEGRAM_BOT_TOKEN` env var
  - Startup validation ensures AllowedUsers is populated, no duplicate UserIds, webhook URL present for Webhook mode
- **Telegram-specific audit events**: 6 new event types added via default interface methods in `IAuditLogger`
  - `LogTelegramMessageReceived` — Log inbound Telegram message with user ID, chat ID, message length
  - `LogTelegramResponseSent` — Log outbound response with chunk count, total bytes sent
  - `LogTelegramAuthFailure` — Log authentication failures (unknown user, rate limit, lockout)
  - `LogTelegramCallbackReceived` — Log inline keyboard callback with payload signature status
  - `LogTelegramFileUpload` — Log file upload events with file size, MIME type, security validation result
  - `LogTelegramFileDownload` — Log file download events with file path, size, access policy result
- **Dual-mode host architecture**: Support three operating modes via `appsettings.json` `"Mode"` setting or `--mode` CLI argument
  - `HostMode.Console` (0, default) — Single-session local console UI, no Telegram services loaded, backward compatible with v0.1.0–v0.3.0
  - `HostMode.Telegram` (1) — Headless bot service with multi-session support, no Console UI, requires Telegram configuration
  - `HostMode.Both` (2) — Concurrent Console + Telegram with shared session manager, requires Telegram configuration
  - Mode resolution: Config + CLI override, validated at startup
  - Conditional DI registration — Console mode does NOT load Telegram services, Telegram/Both modes require valid Telegram configuration
  - `Program.cs` refactored — Mode-aware execution paths, mode-specific logging
- **~476 new tests** across all test projects, bringing total to **1,765 tests passing (2 skipped)**:
  - 43 core abstraction tests (ISessionFactory, ISessionManager, ManagedSession, SessionBudget, SessionRequest, SessionState validation)
  - 16 CorrelationContext tests (agent identity fields, SetAgentContext, ResetSession, audit log integration)
  - 19 SessionFactory tests (isolation, ProjectPath validation, disposal, budget application)
  - 11 SessionManager tests (lifecycle, eviction, resource limits, thread-safety)
  - 20 dual-mode host tests (mode parsing, config override, conditional DI, validation)
  - 244 Telegram integration tests (auth guard, command router, response streamer, approval handler, session bridge, file handler, health monitor, input sanitizer, callback signing)
  - 123 adversarial tests (session isolation, Telegram security, callback tampering, rate limit bypass, lockout evasion, unknown user handling)

### Changed
- **`Program.cs` refactored from singleton orchestrator to multi-session architecture**:
  - Replaced singleton `AgentOrchestrator`, `CorrelationContext`, `SessionStore` with `ISessionManager` registration
  - Added mode-aware DI registration via `HostModeConfigurator`
  - Console mode continues single-session behavior for backward compatibility
  - Telegram/Both modes enable multi-session with configurable `MaxActiveSessions`
- **`IAuditLogger` extended with Telegram methods via default interface implementations**:
  - Added 6 new Telegram-specific log methods with default no-op implementations
  - Backward compatible — existing implementations continue to work without modification
  - `AuditLogger` (Serilog implementation) provides full Telegram audit trail
- **Solution expanded to 7+7 projects**:
  - Added `src/Krutaka.Telegram` (new composition root)
  - Added `tests/Krutaka.Telegram.Tests` (244 tests passing, 1 skipped)
  - Updated `Krutaka.slnx` to include new projects
- **`AGENTS.md` updated with `Krutaka.Telegram` in project dependency rules**:
  - `Krutaka.Telegram` listed as composition root (like `Krutaka.Console`)
  - Dependency rule: Telegram references Core, Tools, Memory, AI (no circular dependencies)

### Security
- **Bot token security** (S1):
  - NEVER in `appsettings.json` — loaded via `ISecretsProvider` (Windows Credential Manager with DPAPI encryption) or `KRUTAKA_TELEGRAM_BOT_TOKEN` environment variable
  - Log redaction filter prevents token leakage in audit logs
- **Empty AllowedUsers enforcement** (S2):
  - `TelegramConfigValidator` fails startup if `AllowedUsers` is null or empty
  - No default "allow all users" — explicit opt-in required
  - Duplicate UserId validation prevents configuration errors
- **Unknown user handling** (S3):
  - Telegram updates from unknown users are silently dropped (no response, no audit log entry for user)
  - Prevents enumeration attacks and spam
- **Input sanitization** (S4):
  - All Telegram text wrapped in `<untrusted_content source="telegram:user:{userId}">` XML tags before sending to Claude
  - Prevents prompt injection via Telegram messages
  - Unicode NFC normalization prevents homograph attacks
  - Telegram entity stripping removes markdown/HTML formatting from untrusted input
- **Callback signature validation** (S5):
  - HMAC-SHA256 signed inline keyboard callbacks prevent tampering
  - 32-byte random secret generated once per application lifetime
  - Base64url encoding prevents URL-unsafe characters
  - Nonce-based replay prevention (callbacks expire after use)
  - Adversarial tests verify signature bypass attempts are blocked
- **Per-session isolation** (S6):
  - Each Telegram user/chat gets independent `AgentOrchestrator`, `CorrelationContext`, `SessionStore`, `ISessionAccessStore`, `ICommandApprovalCache`, `IToolRegistry`
  - Directory grants approved by User A do NOT apply to User B
  - Command approvals from Session 1 do NOT leak to Session 2
  - Conversation history is isolated per session
  - Adversarial tests verify no state leakage between sessions
- **Global token budget** (S7):
  - `SessionManager` tracks total tokens across all sessions
  - Default global budget: 200,000 tokens per application lifetime (overridable via config)
  - Prevents API exhaustion from concurrent users
  - New session creation fails when global budget exhausted
- **Kill switch priority** (S8):
  - `/killswitch` command processed first in polling loop (before rate limiting)
  - Ensures emergency shutdown works even under attack conditions
  - Admin-only command (verified by role check)
  - Gracefully terminates all active sessions and stops polling

## [0.3.0] - 2026-02-14

### Added
- **Graduated command execution**: Commands are now classified into four risk tiers instead of requiring blanket approval for all `run_command` invocations
  - **Safe tier** (auto-approved): Read-only commands like `git status`, `git log`, `dotnet --version`, `cat`, `grep`, `find`, `dir`, `echo`
  - **Moderate tier** (context-dependent): Build/local commands like `git add`, `git commit`, `dotnet build`, `dotnet test`, `npm run`, `python` — auto-approved in trusted directories, prompted elsewhere
  - **Elevated tier** (always prompted): Potentially destructive commands like `git push`, `git pull`, `npm install`, `dotnet publish`, `pip install`
  - **Dangerous tier** (always blocked): Blocklisted executables (`powershell`, `cmd`, `curl`, `wget`, etc.) and unknown commands
- **`ICommandRiskClassifier` interface** (`Krutaka.Core`): Classifies commands by executable name and arguments into risk tiers
- **`ICommandPolicy` interface** (`Krutaka.Core`): Evaluates command execution requests and returns tier-based approval decisions
- **`CommandRiskClassifier`** (`Krutaka.Tools`): Default classifier with hardcoded rules for Safe/Moderate/Elevated/Dangerous tiers, fail-closed for unknown commands
- **`GraduatedCommandPolicy`** (`Krutaka.Tools`): Three-stage evaluation — security pre-check → risk classification → tier-based decision with directory trust integration
- **`CommandApprovalRequiredException`**: New exception type for graduated command approval flow (follows `DirectoryAccessRequiredException` pattern)
- **`CommandApprovalRequested` event**: New agent event yielded when command requires interactive approval
- **Configurable command tier overrides** via `appsettings.json`: Users can customize tier assignments for custom executables (e.g., `cargo`, `make`) with startup validation preventing security downgrades
- **`CommandTierConfigValidator`**: Startup validation for tier overrides — blocks promotion of blocklisted commands, prevents Dangerous tier assignment via config, validates executable names and argument patterns
- **Tier-aware approval UI**: `ApprovalHandler` displays tier-specific labels and emoji (🟢 Safe, 🟡 Moderate, 🔴 Elevated), "Always" option for Moderate tier commands
- **Session-level command approval caching**: "Always" option caches approval for specific command signatures within a session
- **System prompt command tier information**: `SystemPromptBuilder` includes tier listings so Claude knows which commands require approval
- **Command classification audit logging**: Every command logged with tier, approval status, and directory trust context; tier-based log levels (Safe→Debug, Moderate→Info, Elevated→Warning)
- **New model types**: `CommandRiskTier` enum, `CommandOutcome` enum, `CommandRiskRule` record, `CommandExecutionRequest` record (with defensive argument copy), `CommandDecision` record (with factory methods), `CommandPolicyOptions`, `CommandClassificationEvent`
- **~370 new tests** across all test projects for graduated command execution, bringing total to 1,273 (1 skipped)

### Changed
- **`RunCommandTool` refactored**: Now uses `ICommandPolicy.EvaluateAsync()` instead of direct `ISecurityPolicy.ValidateCommand()` for tier-based approval decisions
- **`run_command` removed from static approval list**: Approval is now determined dynamically by `ICommandPolicy` tier evaluation instead of `CommandPolicy.ToolsRequiringApproval`
- **`AgentOrchestrator` enhanced**: Added command approval flow with `ApproveCommand()`/`DenyCommand()` methods and session-level approval caching
- **`ApprovalHandler` enhanced**: New `HandleCommandApproval()` method with tier-specific UI formatting
- **`SystemPromptBuilder` enhanced**: Optional `ICommandRiskClassifier` dependency for including tier information in system prompt
- **`IAuditLogger` enhanced**: New `LogCommandClassification()` method with tier-based log levels
- **`GraduatedCommandPolicy` updated**: Optional `IAuditLogger` for command classification audit trail

### Security
- **Fail-closed classification**: Unknown executables and executables with path separators are classified as Dangerous (always blocked)
- **Immutable security pre-check**: Shell metacharacter and blocklist validation always runs before tier classification
- **Elevated commands never auto-approved**: Directory trust does NOT override Elevated tier — `git push` always requires approval
- **Hard denial enforcement**: `AccessOutcome.Denied` from access policy engine returns `CommandDecision.Deny`, preventing security downgrade where non-overridable denials could become approvable
- **Configuration tampering prevention**: Startup validation prevents promoting blocklisted commands via config, prevents `.exe` suffix bypass (e.g., `powershell.exe`)
- **Defensive argument copy**: `CommandExecutionRequest` creates immutable copy of arguments to prevent post-classification mutation
- **Adversarial test coverage**: New tests for tier bypass attempts, argument pattern evasion, configuration manipulation, and unknown command handling

## [0.2.0] - 2026-02-13

### Added
- **Dynamic directory scoping**: Agent can now request access to multiple directories at runtime instead of being locked to a single `WorkingDirectory` at startup
- **Layered access policy engine** (`IAccessPolicyEngine`, `LayeredAccessPolicyEngine`): Four-layer evaluation for directory access requests
  - Layer 1: Hard deny-list (system directories, UNC paths, paths above ceiling)
  - Layer 2: Configurable auto-grant patterns (glob patterns in `appsettings.json`)
  - Layer 3: Session-scoped grants (previously approved by user)
  - Layer 4: Heuristic checks with interactive user prompts
- **Session-scoped access grants** (`ISessionAccessStore`, `InMemorySessionAccessStore`): Time-to-live (TTL) based directory access grants with automatic pruning
- **Glob auto-grant patterns** (`GlobPatternValidator`): Configure trusted directory patterns in `appsettings.json` for auto-approval (e.g., `C:\Users\name\Projects\**`)
- **Symlink and junction resolution** (`PathResolver`): Segment-by-segment symlink resolution to prevent symlink escape attacks
- **Alternate Data Streams (ADS) blocking**: Paths containing `:` after drive letter are rejected to prevent ADS-based attacks
- **Device name blocking**: Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`) blocked in all path segments
- **Device path prefix blocking**: `\\.\` and `\\?\` prefixes are blocked
- **Interactive directory approval UI**: `DirectoryAccessRequested` event with user prompts for directory access decisions
- **Ceiling directory enforcement**: `ToolOptions.CeilingDirectory` configuration to set maximum ancestor directory (default: `%USERPROFILE%`)
- **87 new adversarial security tests** across 3 test suites:
  - `AccessPolicyEngineAdversarialTests` (21 test methods): System directory bypass, ceiling enforcement, path manipulation, session scope accumulation, cross-volume detection
  - `PathResolverAdversarialTests` (18 test methods): ADS attacks, device name blocking, device path prefixes, deeply nested paths
  - `GlobPatternAdversarialTests` (21 test methods): Overly broad patterns, relative traversal, blocked directories

### Changed
- **All 6 file/command tools refactored**: `ReadFileTool`, `WriteFileTool`, `EditFileTool`, `ListFilesTool`, `SearchFilesTool`, `RunCommandTool` now use `IAccessPolicyEngine` for directory access validation instead of static `_projectRoot` field
- **Configuration property renamed**: `ToolOptions.WorkingDirectory` → `ToolOptions.DefaultWorkingDirectory` (still defaults to `.` if not specified)
- **New configuration properties**: `CeilingDirectory`, `AutoGrantPatterns`, `MaxConcurrentGrants`, `DefaultGrantTtlMinutes`
- **Enhanced path validation**: `SafeFileOperations.ValidatePath()` now calls `PathResolver.ResolveToFinalTarget()` before containment checks to resolve all symlinks, junctions, and reparse points

### Security
- **Path hardening**: Segment-by-segment symlink resolution closes v0.1.0 gap where symlinks could escape project root
- **TOCTOU mitigation**: Path resolution happens both at policy evaluation and at file access time
- **Circular symlink detection**: Prevents infinite loops and DoS from symlink cycles
- **Glob pattern abuse prevention**: Patterns must have ≥ 3 path segments, cannot contain blocked directories, must be under ceiling directory
- **Session scope accumulation defense**: Max concurrent grants (default 10), automatic TTL expiry, ceiling enforcement, strict access level checks
- **Comprehensive adversarial test coverage**: 87 new tests simulating attack scenarios (symlink escapes, ADS manipulation, device name exploits, pattern abuse, ceiling violations)

### Fixed
- Symlink escape vulnerability: Symlinks within project directory pointing to blocked locations (e.g., `C:\Windows\System32`) are now correctly blocked after resolution

## [0.1.1] - 2026-02-12

### Added
- **Smart session management**: Auto-resume most recent session on startup
- **Session discovery**: `SessionStore.FindMostRecentSession()` and `SessionStore.ListSessions()` for finding and listing past sessions
- **New commands**: 
  - `/sessions` — List recent sessions for the current project (last 10)
  - `/new` — Start a fresh session with cleared conversation history
- **11 new tests** for session discovery (10) and conversation clearing (1)

### Changed
- **Startup behavior**: Application automatically resumes the most recent session instead of requiring manual `/resume` command
- **Session store API**: Added static methods `FindMostRecentSession` and `ListSessions` to `SessionStore` for discovery

### Fixed
- Data loss between app restarts: Sessions are now automatically resumed on startup
- Broken `/resume` command: Fixed and integrated with auto-resume behavior

## [0.1.0] - 2026-02-11

### Added
- **Initial release**: Complete core features with 576 tests passing
- **Console application**: No network listener (eliminates CVE-2026-25253 attack class)
- **Claude API integration**: Streaming support with official `Anthropic` NuGet package v12.4.0
- **Tool system**: 6 tools (read_file, write_file, edit_file, list_files, search_files, run_command, memory_store, memory_search)
- **Security controls**:
  - Windows Credential Manager integration for API key storage (DPAPI encryption)
  - Command allowlist/blocklist with metacharacter detection
  - Path validation with project root sandboxing
  - Process sandboxing with Windows Job Objects (256MB memory, 30s CPU limits)
  - Human-in-the-loop approval for write/execute operations
  - Environment variable scrubbing (removes API keys from child processes)
  - Log redaction filter for API keys and secrets
  - Prompt injection defense (untrusted content wrapped in XML tags)
- **Memory system**:
  - SQLite FTS5 keyword search
  - JSONL session persistence
  - Token counting and context compaction
  - MEMORY.md management
- **UI**: Spectre.Console streaming interface with rich panels, spinners, and prompts
- **Skills system**: Markdown skill loader with YAML frontmatter
- **Audit logging**: Structured JSON logs with correlation IDs (Serilog)
- **125 security policy tests**: Command validation (40), path validation (40), environment scrubbing (20), attack simulations (25+)
- **CI/CD**: GitHub Actions pipeline with build and security test workflows
- **Self-contained publishing**: Single-file executable with `dotnet publish`

### Security
- **Threat model**: Addresses OpenClaw CVEs (CVE-2026-25253, CVE-2026-25157, CVE-2026-24763)
- **Defense-in-depth**: 9 security controls with comprehensive test coverage

---

[Unreleased]: https://github.com/chethandvg/krutaka/compare/v0.4.6...HEAD
[0.4.6]: https://github.com/chethandvg/krutaka/compare/v0.4.5...v0.4.6
[0.4.5]: https://github.com/chethandvg/krutaka/compare/v0.4.0...v0.4.5
[0.4.0]: https://github.com/chethandvg/krutaka/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/chethandvg/krutaka/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/chethandvg/krutaka/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/chethandvg/krutaka/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/chethandvg/krutaka/releases/tag/v0.1.0
