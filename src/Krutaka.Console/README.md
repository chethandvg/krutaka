# Krutaka.Console

The console composition root and primary user interface. Provides the startup entry point (`Program.cs`), console UI with Spectre.Console rendering, Markdown rendering, human-in-the-loop approval handling, first-run setup wizard, structured audit logging, and host mode configuration.

> **This is a composition root** — it wires DI and orchestrates the application lifecycle. Business logic should NOT be added here.
>
> `Program.cs` uses top-level statements and must remain at the project root.

## NuGet Dependencies

| Package | Purpose |
|---|---|
| `Markdig` | Markdown parsing |
| `Meziantou.Framework.Win32.CredentialManager` | Windows Credential Manager access |
| `Microsoft.Extensions.Configuration` | Configuration abstractions |
| `Microsoft.Extensions.Configuration.UserSecrets` | User secrets support |
| `Microsoft.Extensions.Hosting` | Generic host / DI container |
| `Serilog` | Structured logging |
| `Serilog.Extensions.Hosting` | Serilog integration with Generic Host |
| `Serilog.Sinks.Console` | Console log sink |
| `Serilog.Sinks.File` | File log sink |
| `Spectre.Console` | Rich terminal UI rendering |

## Key Responsibilities

- Application startup and DI wiring (`Program.cs`, `HostModeConfigurator`)
- Interactive console UI and Markdown rendering (`ConsoleUI`, `MarkdownRenderer`)
- Human-in-the-loop approval prompts (`ApprovalHandler`)
- First-run setup wizard and secrets management (`SetupWizard`, `SecretsProvider`, `WindowsSecretsProvider`)
- Structured audit logging and log redaction (`AuditLogger`, `LogRedactionEnricher`)

## Directory Layout

| Directory | Description | Key Files |
|---|---|---|
| `UI/` | Console UI, rendering, and approval prompts | `ConsoleUI.cs`, `MarkdownRenderer.cs`, `ApprovalHandler.cs` |
| `Setup/` | First-run wizard and secrets providers | `SetupWizard.cs`, `SecretsProvider.cs`, `WindowsSecretsProvider.cs` |
| `Logging/` | Structured audit logging and redaction | `AuditLogger.cs`, `LogRedactionEnricher.cs` |
| _(root)_ | Entry point and host configuration | `Program.cs`, `HostModeConfigurator.cs`, `GlobalSuppressions.cs` |

## Project Dependencies

Depends on: `Krutaka.Core`, `Krutaka.AI`, `Krutaka.Tools`, `Krutaka.Memory`, `Krutaka.Skills`, `Krutaka.Telegram`
