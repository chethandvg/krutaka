# Copilot Repository Instructions for Krutaka

## Project Context

Krutaka is a C#/.NET 10 console application targeting Windows (x64). It is an OpenClaw-inspired AI agent that uses the Claude API for agentic task execution with security-hardened tool use.

**Implementation Status:** 🚧 **v0.5.0 Autonomous Agent Mode In Progress** — v0.4.6 complete with 2,051 tests passing (2 skipped). v0.5.0 is now in active development: autonomy levels, task budgets, git checkpoints, deadman's switch, and behavior anomaly detection. See `docs/status/PROGRESS.md` for detailed status.

**Host Modes:** The application supports three operating modes via `appsettings.json` `"Mode"` setting or `--mode` CLI argument:
- **Console** (default): Single-session local console UI, no Telegram services loaded
- **Telegram**: Headless bot service with multi-session support
- **Both**: Concurrent Console + Telegram with shared session manager

## Coding Conventions

### C# Style
- Target: .NET 10, C# 13, `LangVersion latest`
- Nullable reference types are enabled globally
- Warnings are treated as errors — all code must compile with zero warnings
- Use `PascalCase` for all public members (methods, properties, classes, interfaces)
- Use `_camelCase` for private fields
- Use `camelCase` for local variables and parameters
- Prefix interfaces with `I` (e.g., `ITool`, `IClaudeClient`)
- Use `Async` suffix for all async methods
- All async methods must accept `CancellationToken` as the last parameter
- Use collection expressions (`[]`) and target-typed `new()` where appropriate
- Prefer `switch` expressions and pattern matching over `if/else` chains
- Use `record` types for immutable data carriers
- Use `readonly record struct` for small value types
- Use `partial class` if a `.cs` file exceeds 300 lines of code. Up to 330 lines is acceptable before splitting is required.
- Name partial files descriptively: `MyClass.cs` + `MyClass.Validation.cs` or `MyClass.EventHandlers.cs`

### Project Structure
- Solution uses central package management (`Directory.Packages.props`)
- Each project has a `ServiceExtensions.cs` for DI registration
- Interfaces live in `Krutaka.Core` — implementations in their respective projects
- Tests use xUnit with FluentAssertions
- Test classes mirror source classes: `MyClass.cs` → `MyClassTests.cs`
- `Krutaka.Telegram` is a composition root (like `Krutaka.Console`) that provides Telegram bot interface
- `ISessionFactory`/`ISessionManager` replace the singleton orchestrator pattern for multi-session support
- All source projects use logical subdirectories (Abstractions/, Models/, etc.) — see each project's README.md for layout
- File moves MUST NOT change namespaces — C# does not enforce namespace-to-directory mapping
- `.csproj`, `AssemblyInfo.cs`, `packages.lock.json`, and `Program.cs` (for executables) stay at project root

### Security (Critical)
- NEVER hardcode secrets, API keys, or credentials
- NEVER use `string.Format` or interpolation to build shell commands — use CliWrap argument arrays
- ALWAYS validate directory access through `IAccessPolicyEngine.EvaluateAsync()` before any file I/O
- ALWAYS validate file paths through `PathResolver.ResolveToFinalTarget()` to resolve symlinks, junctions, and reparse points
- ALWAYS validate commands through `ICommandPolicy.EvaluateAsync()` for tier-based approval
- ALWAYS wrap untrusted content in `<untrusted_content>` tags when sending to Claude
- ALWAYS wrap Telegram user input in `<untrusted_content source="telegram:user:{userId}">` tags before sending to Claude
- ALWAYS use `CancellationToken` for cancellable operations
- ALWAYS ensure per-session state (orchestrator, correlation context, session store, access store, approval cache, tool registry, context compactor, `ITaskBudgetTracker`, `IGitCheckpointService`, `IBehaviorAnomalyDetector`, `DeadmanSwitch`) is instantiated per-session via `ISessionFactory`, NEVER as a singleton
- ALWAYS validate Telegram inline keyboard callbacks with HMAC-SHA256 before processing
- NEVER log sensitive data — use the log redaction filter
- NEVER store Telegram bot tokens in `appsettings.json` — use `ISecretsProvider` (Windows Credential Manager) or environment variables
- Synthetic `tool_result` blocks injected by `RepairOrphanedToolUseBlocks` MUST always have `is_error = true` — never fabricate successful results
- Tool result pruning MUST NOT modify JSONL session files — only modify in-memory snapshots before API calls
- Pre-compaction memory flush MUST wrap conversation content in `<untrusted_content>` tags
- Bootstrap file caps MUST NOT truncate Layer 2 security instructions (hardcoded in `GetSecurityInstructions()`)
- **S9: Autonomy level MUST NOT escalate at runtime** — set once at session start from config, immutable thereafter
- **S10: Budget MUST NOT increase without explicit user action** — agent cannot extend its own budget
- **S11: Checkpoints are local-only** — no `git push` without Elevated approval
- **S12: Deadman's switch timer runs in `SessionManager`** — agent cannot access or reset it
- **S13: Anomaly detector runs independently** — agent cannot disable or modify thresholds
- **S14: Dangerous tier commands are ALWAYS blocked** — regardless of autonomy level
- **S15: All steering input (`/steer`) MUST be wrapped in `<untrusted_content>` tags** — no exception

### Dependencies
- Use only packages declared in `Directory.Packages.props`
- If a new package is needed, add it to `Directory.Packages.props` first
- Prefer Microsoft/official packages over community alternatives when quality is comparable

## Key Documentation

Before making changes, read:
- `AGENTS.md` — Agent-level instructions and project rules
- `docs/status/PROGRESS.md` — Current implementation status
- `docs/architecture/OVERVIEW.md` — Component architecture
- `docs/architecture/SECURITY.md` — Security model (for security-sensitive code)
- `docs/versions/v0.2.0.md` — v0.2.0 dynamic directory scoping architecture design
- `docs/versions/v0.3.0.md` — v0.3.0 graduated command execution architecture design
- `docs/versions/v0.4.0.md` — v0.4.0 Telegram integration and multi-session architecture design
- `docs/versions/v0.4.5.md` — v0.4.5 Session Resilience, API Hardening & Context Intelligence design
- `docs/versions/v0.4.6.md` — v0.4.6 Project Structure, Code Quality & v0.5.0 Prerequisites design
- `docs/versions/v0.5.0.md` — v0.5.0 Autonomous Agent Mode architecture, security invariants, and implementation roadmap
- `docs/roadmap/ROADMAP.md` — Forward-looking roadmap (v0.5.0 through v1.3.0+)
- `docs/architecture/MULTI-SESSION.md` — Multi-session isolation architecture
- `docs/architecture/TELEGRAM.md` — Telegram security architecture
- `docs/architecture/DECISIONS.md` — Architecture Decision Records (ADR-013 for graduated command execution)