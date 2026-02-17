# Krutaka — Agent Instructions

This file provides instructions for AI coding agents (GitHub Copilot, etc.) working on this repository.

## Project Overview

Krutaka is an OpenClaw-inspired AI agent built in C#/.NET 10 for Windows. It is a console application that uses the Claude API to perform agentic tasks (read/write files, execute commands, search code) with human-in-the-loop approval for destructive operations.

**Implementation Status:** ✅ **v0.4.0 Telegram Integration & Multi-Session Architecture Complete** — v0.4.0 is complete with 1,765 tests passing (2 skipped). Adds Telegram bot interface, multi-session architecture, dual-mode host support (Console, Telegram, or Both), and comprehensive security controls. The project is ready for production use with both local console and remote Telegram access. See `docs/status/PROGRESS.md` for details.

**Important:** We use the official `Anthropic` NuGet package (v12.4.0), NOT the community `Anthropic.SDK` package. Always refer to it as the "official Anthropic package" or "Anthropic NuGet package" to avoid confusion. See ADR-003 in `docs/architecture/DECISIONS.md` for details.

## Before Starting Any Task

1. **Read the progress tracker** at `docs/status/PROGRESS.md` to understand what has been implemented and what is pending.
2. **Read the architecture overview** at `docs/architecture/OVERVIEW.md` to understand the component structure and dependencies.
3. **Read the security model** at `docs/architecture/SECURITY.md` before implementing anything that touches tools, file I/O, process execution, secrets, or prompt construction.
4. **Read the architecture decisions** at `docs/architecture/DECISIONS.md` to understand why specific choices were made — do not contradict them without explicit instruction.

## After Completing Any Task

After every task, update the following files **only with necessary changes**:

1. **`docs/status/PROGRESS.md`** — Mark the completed issue as "Complete" with the date.
2. **Relevant architecture docs** — If the task changes the component structure, dependencies, or security controls, update the corresponding docs:
   - `docs/architecture/OVERVIEW.md` for structural changes
   - `docs/architecture/SECURITY.md` for security-related changes
   - `docs/status/DEPENDENCY-MAP.md` for package version changes
3. **Do NOT create new documentation files** unless the issue explicitly says to.
4. **Do NOT update `README.md`** unless the issue explicitly says to.
5. **For v0.4.0 issues**, new documentation files ARE permitted when the issue explicitly requests their creation.

## Build and Test Commands

```bash
# Build entire solution
dotnet build

# Build specific project
dotnet build src/Krutaka.Console

# Clean build artifacts
dotnet clean

# Run all tests
dotnet test

# Run tests for specific project
dotnet test tests/Krutaka.Tools.Tests

# Run tests with detailed output
dotnet test --logger "console;verbosity=detailed"

# Run specific test by filter
dotnet test --filter "FullyQualifiedName~SecurityPolicy"

# Format code to match .editorconfig
dotnet format

# Restore NuGet packages
dotnet restore
```

## Coding Standards

- **Language:** C# 13 (.NET 10, LangVersion `latest`)
- **Nullable reference types:** Enabled globally (`<Nullable>enable</Nullable>`)
- **Implicit usings:** Enabled
- **Warnings as errors:** Enabled (`<TreatWarningsAsErrors>true</TreatWarningsAsErrors>`)
- **Naming:** PascalCase for public members, `_camelCase` for private fields, `camelCase` for local variables and parameters
- **Async:** All I/O-bound methods must be async with `Async` suffix and accept `CancellationToken`
- **Dependency injection:** Use constructor injection, register via `ServiceExtensions.cs` per project
- **No `var` abuse:** Use explicit types when the type is not obvious from the right-hand side
- **String interpolation:** Preferred over `string.Format` or concatenation
- **Collections:** Use collection expressions (`[]`) where supported
- **Pattern matching:** Use `is`, `switch` expressions, and property patterns where they improve clarity
- **Error handling:** Never swallow exceptions silently. Log and rethrow, or handle explicitly.

## Project Dependency Rules

```
Krutaka.Core          → (no dependencies — interfaces and models only)
Krutaka.AI            → Krutaka.Core
Krutaka.Tools         → Krutaka.Core
Krutaka.Memory        → Krutaka.Core
Krutaka.Skills        → Krutaka.Core
Krutaka.Console       → All above projects
Krutaka.Telegram      → Krutaka.Core, Krutaka.Tools, Krutaka.Memory, Krutaka.AI (composition root, like Console)
```

- `Krutaka.Core` must NEVER reference any other Krutaka project.
- `Krutaka.AI`, `Krutaka.Tools`, `Krutaka.Memory`, `Krutaka.Skills` must NEVER reference each other directly.
- Only `Krutaka.Console` and `Krutaka.Telegram` (composition roots) may reference all projects.

## Security Rules (Non-Negotiable)

These rules apply to ALL code changes. Violating them is a blocking issue.

1. **API keys must NEVER appear in source code, config files, environment variables, or log output.**
2. **All directory access requests must be validated through `IAccessPolicyEngine.EvaluateAsync()` before any file operations.**
3. **All file paths must be resolved through `PathResolver.ResolveToFinalTarget()` to detect and block symlink escapes, ADS attacks, and device names.**
4. **All shell commands must be validated through `ICommandPolicy.EvaluateAsync()` for tier-based approval before execution.**
5. **Shell commands must use CliWrap with explicit argument arrays — never string interpolation.**
6. **Child processes must have sensitive environment variables scrubbed before execution.**
7. **Untrusted content (file contents, command output, web pages, Telegram messages) sent to Claude must be wrapped in `<untrusted_content>` XML tags.**
8. **Telegram user input must be wrapped in `<untrusted_content source="telegram:user:{userId}">` tags before sending to Claude.**
9. **Write, execute, and directory access operations must require human approval (enforced by `ISecurityPolicy.IsApprovalRequired` and `IAccessPolicyEngine`).**

## Key Files Reference

| File | Purpose |
|---|---|
| `Rough_outline.md` | Original architecture blueprint with detailed code patterns |
| `Outline_gaps.md` | Gap analysis and risk assessment |
| `docs/architecture/OVERVIEW.md` | Living architecture document — component structure |
| `docs/architecture/SECURITY.md` | Security threat model and policy rules |
| `docs/architecture/DECISIONS.md` | Architecture Decision Records (ADR-001 through ADR-013) |
| `docs/architecture/MULTI-SESSION.md` | Multi-session isolation architecture |
| `docs/architecture/TELEGRAM.md` | Telegram security architecture |
| `docs/status/PROGRESS.md` | Issue/phase completion tracker |
| `docs/status/DEPENDENCY-MAP.md` | NuGet package versions |
| `docs/guides/LOCAL-SETUP.md` | Build and run instructions |
| `docs/guides/TELEGRAM-SETUP.md` | Telegram bot setup and configuration |
| `docs/guides/TESTING.md` | Test strategy and procedures |
| `docs/versions/v0.2.0.md` | v0.2.0 dynamic directory scoping architecture design |
| `docs/versions/v0.3.0.md` | v0.3.0 graduated command execution architecture design |
| `docs/versions/v0.4.0.md` | v0.4.0 Telegram integration and multi-session architecture design |
| `CHANGELOG.md` | Release notes following Keep a Changelog format |