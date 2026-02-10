# Krutaka — NuGet Dependency Map

> **Last updated:** 2026-02-10 (Issue #5 — Scaffolding complete)

## Package Registry

All packages are managed centrally via `Directory.Packages.props`.

| Package | Version | Project(s) | Purpose |
|---|---|---|---|
| `Anthropic.SDK` | 1.0.0 | Krutaka.AI | Official Anthropic Claude API client (GA) |
| `Microsoft.Extensions.AI` | 10.0.0 | Krutaka.AI | Provider-agnostic AI abstraction layer |
| `System.Net.ServerSentEvents` | 10.0.0 | Krutaka.AI | SSE streaming support |
| `Microsoft.Extensions.Http.Resilience` | 10.0.0 | Krutaka.AI | Retry, timeout, circuit breaker for HTTP |
| `Microsoft.Extensions.Hosting` | 10.0.2 | Krutaka.Console | DI container, configuration, logging host |
| `Microsoft.Extensions.DependencyInjection` | 10.0.2 | All projects | Dependency injection abstractions |
| `Microsoft.Extensions.Configuration` | 10.0.2 | Krutaka.Console | Configuration abstractions |
| `Microsoft.Extensions.Configuration.UserSecrets` | 10.0.2 | Krutaka.Console | User secrets configuration provider |
| `Spectre.Console` | 0.49.1 | Krutaka.Console | Rich console UI (markup, panels, prompts) |
| `Markdig` | 0.40.0 | Krutaka.Console | Markdown parsing for console rendering |
| `Microsoft.Data.Sqlite` | 10.0.1 | Krutaka.Memory | SQLite database with built-in FTS5 |
| `YamlDotNet` | 16.2.1 | Krutaka.Skills | YAML frontmatter parsing for skill files |
| `CliWrap` | 3.6.7 | Krutaka.Tools | Safe async process execution |
| `Meziantou.Framework.Win32.CredentialManager` | 1.7.17 | Krutaka.Console | DPAPI-backed Windows Credential Manager |
| `Meziantou.Framework.Win32.Jobs` | 3.4.10 | Krutaka.Tools | Windows Job Object process sandboxing |
| `Serilog` | 4.2.0 | Krutaka.Console | Structured logging framework |
| `Serilog.Sinks.File` | 6.0.0 | Krutaka.Console | File-based log sink |
| `Serilog.Sinks.Console` | 6.0.0 | Krutaka.Console | Console log sink |
| `Serilog.Extensions.Hosting` | 8.0.0 | Krutaka.Console | Serilog integration with .NET Host |

## Test Dependencies

| Package | Version | Project(s) | Purpose |
|---|---|---|---|
| `xunit` | 2.9.3 | All test projects | Test framework |
| `xunit.runner.visualstudio` | 3.0.0 | All test projects | VS test runner integration |
| `FluentAssertions` | 7.0.0 | All test projects | Assertion library |
| `Microsoft.NET.Test.Sdk` | 17.12.0 | All test projects | Test SDK |
| `NSubstitute` | 5.3.0 | All test projects | Mocking framework |
| `coverlet.collector` | 6.0.2 | All test projects | Code coverage collector |

## Version Changes from Initial Plan

| Package | Original Version | Actual Version | Reason |
|---|---|---|---|
| Anthropic | 12.4.0 | Anthropic.SDK 1.0.0 | Using official SDK package name |
| Microsoft.Extensions.AI | 10.0.0-preview | 10.0.0 | GA release available |
| Meziantou.Framework.Win32.CredentialManager | 1.7.11 | 1.7.17 | Latest stable version |

## Future Dependencies (v2 — Vector Search)

| Package | Version | Project(s) | Purpose |
|---|---|---|---|
| `Microsoft.SemanticKernel.Connectors.Onnx` | 1.45.0+ | Krutaka.Memory | Local ONNX embeddings (bge-micro-v2) |
| `Microsoft.Extensions.VectorData.Abstractions` | 9.7.0 | Krutaka.Memory | Vector store abstraction |

## Version Pinning Rules

- All versions are pinned in `Directory.Packages.props` (central package management)
- `global.json` pins the .NET SDK version (10.0.102)
- `packages.lock.json` will be committed for deterministic CI restores
- Dependabot or Renovate should be configured for automated update PRs