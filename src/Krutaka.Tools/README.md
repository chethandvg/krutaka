# Krutaka.Tools

## Purpose

Implements all agent tools (file I/O, command execution), directory access policy enforcement, command risk classification, session lifecycle management, and security validation.

## Dependencies

### NuGet Packages
- `CliWrap` — structured child process execution with argument arrays
- `Meziantou.Framework.Win32.Jobs` — Windows Job Objects for child process isolation
- `Microsoft.Extensions.DependencyInjection` — DI container integration
- `Microsoft.Extensions.FileSystemGlobbing` — glob pattern matching for file search
- `Microsoft.Extensions.Logging.Abstractions` — structured logging interfaces

### Project References
- `Krutaka.Core` — interfaces, models, and orchestration contracts

## Responsibilities

- Providing file I/O tools: read, write, edit, list, and search files
- Executing shell commands via CliWrap with argument arrays (no string interpolation)
- Enforcing graduated command risk tiers (Safe / Moderate / Elevated / Dangerous)
- Validating directory access requests via `LayeredAccessPolicyEngine`
- Resolving file paths through `PathResolver` to detect symlink escapes and device names
- Scrubbing sensitive environment variables before spawning child processes
- Managing per-session access scopes via `InMemorySessionAccessStore`
- Registering and resolving agent tools via `ToolRegistry`
- Creating and managing agent sessions via `SessionFactory` and `SessionManager`
- Configuring tool behavior and command tier thresholds via options classes

## Directory Layout

| Directory | Description | Key Files |
|-----------|-------------|-----------|
| `Access/` | File path validation, access policy enforcement, glob matching | `LayeredAccessPolicyEngine.cs`, `PathResolver.cs`, `SafeFileOperations.cs`, `GlobPatternValidator.cs`, `InMemorySessionAccessStore.cs` |
| `CommandTools/` | Shell command execution and environment hardening | `RunCommandTool.cs`, `EnvironmentScrubber.cs` |
| `Configuration/` | Tool and command policy configuration options | `ToolOptions.cs`, `CommandPolicyOptions.cs`, `CommandTierConfigValidator.cs` |
| `FileTools/` | File read, write, edit, list, and search tools | `ReadFileTool.cs`, `WriteFileTool.cs`, `EditFileTool.cs`, `ListFilesTool.cs`, `SearchFilesTool.cs`, `BackupHelper.cs` |
| `Policies/` | Command risk classification and graduated execution policy | `GraduatedCommandPolicy.cs`, `CommandPolicy.cs`, `CommandRiskClassifier.cs` |
| `Session/` | Session lifecycle creation and management | `SessionFactory.cs`, `SessionManager.cs` |
| *(root)* | Cross-cutting registrations | `ToolRegistry.cs`, `ServiceExtensions.cs` |

## Used By

- `Krutaka.Console` — loads all tools and policies for the local console agent
- `Krutaka.Telegram` — loads all tools and policies for the Telegram bot agent
- `Krutaka.Memory` — depends on `ISessionAccessStore` indirectly via `Krutaka.Core` interfaces

## Notes

> **Security-critical:** This project contains security-critical implementations (`LayeredAccessPolicyEngine`, `GraduatedCommandPolicy`, `PathResolver`, `SafeFileOperations`). Changes require careful review against `docs/architecture/SECURITY.md`.
