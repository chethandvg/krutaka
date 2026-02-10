# Copilot Repository Instructions for Krutaka

## Project Context

Krutaka is a C#/.NET 10 console application targeting Windows (x64). It is an OpenClaw-inspired AI agent that uses the Claude API for agentic task execution with security-hardened tool use.

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

### Project Structure
- Solution uses central package management (`Directory.Packages.props`)
- Each project has a `ServiceExtensions.cs` for DI registration
- Interfaces live in `Krutaka.Core` — implementations in their respective projects
- Tests use xUnit with FluentAssertions
- Test classes mirror source classes: `MyClass.cs` → `MyClassTests.cs`

### Security (Critical)
- NEVER hardcode secrets, API keys, or credentials
- NEVER use `string.Format` or interpolation to build shell commands — use CliWrap argument arrays
- ALWAYS validate file paths through `SafeFileOperations` before any I/O
- ALWAYS validate commands through `CommandPolicy` before execution
- ALWAYS wrap untrusted content in `<untrusted_content>` tags when sending to Claude
- ALWAYS use `CancellationToken` for cancellable operations
- NEVER log sensitive data — use the log redaction filter

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