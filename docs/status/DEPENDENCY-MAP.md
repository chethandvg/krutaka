# Krutaka — NuGet Dependency Map

> **Last updated:** 2026-02-10 (Pre-implementation — versions to be confirmed during Issue #3)

## Package Registry

All packages are managed centrally via `Directory.Packages.props`.

| Package | Version | Project(s) | Purpose |
|---|---|---|---|
| `Anthropic` | 12.4.0 | Krutaka.AI | Official Claude API SDK (GA) |
| `Microsoft.Extensions.Http.Resilience` | 9.4.0 | Krutaka.AI | Retry, timeout, circuit breaker for HTTP |
| `Microsoft.Extensions.Hosting` | 10.0.0 | Krutaka.Console | DI container, configuration, logging host |
| `Spectre.Console` | 0.54.0 | Krutaka.Console | Rich console UI (markup, panels, prompts) |
| `Markdig` | 0.44.0 | Krutaka.Console | Markdown parsing for console rendering |
| `Microsoft.Data.Sqlite` | 10.0.0 | Krutaka.Memory | SQLite database with built-in FTS5 |
| `YamlDotNet` | latest | Krutaka.Skills | YAML frontmatter parsing for skill files |
| `CliWrap` | 3.8.2 | Krutaka.Tools | Safe async process execution |
| `Meziantou.Framework.Win32.CredentialManager` | 1.7.11 | Krutaka.Console | DPAPI-backed Windows Credential Manager |
| `Meziantou.Framework.Win32.Jobs` | 3.4.10 | Krutaka.Tools | Windows Job Object process sandboxing |
| `Serilog` | latest | Krutaka.Console | Structured logging framework |
| `Serilog.Sinks.File` | latest | Krutaka.Console | File-based log sink |
| `Serilog.Extensions.Hosting` | latest | Krutaka.Console | Serilog integration with .NET Host |

## Test Dependencies

| Package | Version | Project(s) | Purpose |
|---|---|---|---|
| `xunit` | latest | All test projects | Test framework |
| `xunit.runner.visualstudio` | latest | All test projects | VS test runner integration |
| `FluentAssertions` | latest | All test projects | Assertion library |
| `Microsoft.NET.Test.Sdk` | latest | All test projects | Test SDK |
| `NSubstitute` | latest | All test projects | Mocking framework |
| `WireMock.Net` | latest | Krutaka.AI.Tests | Mock HTTP server for API tests |

## Future Dependencies (v2 — Vector Search)

| Package | Version | Project(s) | Purpose |
|---|---|---|---|
| `Microsoft.SemanticKernel.Connectors.Onnx` | 1.45.0+ | Krutaka.Memory | Local ONNX embeddings (bge-micro-v2) |
| `Microsoft.Extensions.VectorData.Abstractions` | 9.7.0 | Krutaka.Memory | Vector store abstraction |

## Version Pinning Rules

- All versions are pinned in `Directory.Packages.props` (central package management)
- `global.json` pins the .NET SDK version
- `packages.lock.json` is committed for deterministic CI restores
- Dependabot or Renovate should be configured for automated update PRs