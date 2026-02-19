# Krutaka.AI

Wraps the Anthropic Claude API client with streaming support, retry/backoff logic, token counting, and DI registration. This is the only project that directly references the Anthropic NuGet package.

## NuGet Dependencies

| Package | Purpose |
|---|---|
| `Anthropic` | Official Anthropic SDK for Claude API access |
| `Microsoft.Extensions.AI` | AI abstractions |
| `Microsoft.Extensions.Configuration.Abstractions` | Configuration abstractions |
| `Microsoft.Extensions.DependencyInjection` | DI container |
| `Microsoft.Extensions.Http.Resilience` | HTTP resilience pipelines (Polly integration) |
| `Microsoft.Extensions.Logging.Abstractions` | Logging abstractions |

## Key Responsibilities

- Implementing `IClaudeClient` from `Krutaka.Core` via `ClaudeClientWrapper`
- Streaming Claude API responses as `IAsyncEnumerable<AgentEvent>`
- Exponential backoff with jitter for rate-limit retries
- Token counting with caching via `TokenCounter`
- DI registration of all AI services via `ServiceExtensions`

## Directory Layout

| Directory / File | Description | Key Files |
|---|---|---|
| `Client/` | Claude API client implementation and token counting | `ClaudeClientWrapper.cs`, `TokenCounter.cs` |
| `ServiceExtensions.cs` | DI registration for AI services | — |

## Relationships

- **Depends on:** `Krutaka.Core` (for `IClaudeClient`, `AgentEvent`, and other core interfaces)
- **Depended on by:** `Krutaka.Console`, `Krutaka.Telegram`

> **Note:** `ClaudeClientWrapper` implements `IClaudeClient` from `Krutaka.Core`. All Claude API interaction must go through this wrapper.
