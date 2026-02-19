# Krutaka.Telegram

Provides the Telegram bot interface — authentication, command routing, response streaming, inline keyboard approval flow, file handling, health monitoring, and session management for multi-user Telegram access.

## NuGet Dependencies

| Package | Purpose |
|---|---|
| `Telegram.Bot` | Telegram Bot API client |
| `Microsoft.Extensions.Configuration.Abstractions` | Configuration abstractions |
| `Microsoft.Extensions.DependencyInjection` | DI registration |
| `Microsoft.Extensions.Logging.Abstractions` | Logging abstractions |

## Key Responsibilities

- Authenticate Telegram users against an allowlist and enforce lockout on repeated failures
- Route incoming Telegram commands to the appropriate agent session handler
- Stream Claude responses back to Telegram with rate-limiting and chunking
- Handle inline keyboard approval flows with HMAC-signed callback payloads
- Receive and forward files sent by Telegram users to the agent
- Monitor bot health and manage polling lock files to prevent duplicate instances
- Bridge Telegram sessions to the multi-session orchestration layer

## Directory Layout

| Directory | Description | Key Files |
|---|---|---|
| `Auth/` | Authentication and lockout | `TelegramAuthGuard`, `ITelegramAuthGuard`, `AuthResult`, `LockoutState`, `SlidingWindowCounter` |
| `Commands/` | Command routing and parsing | `TelegramCommandRouter`, `ITelegramCommandRouter`, `TelegramCommandParser`, `TelegramCommand`, `CommandRouteResult` |
| `Streaming/` | Response streaming and formatting | `TelegramResponseStreamer`, `ITelegramResponseStreamer`, `TelegramMarkdownV2Formatter` |
| `Approval/` | Inline keyboard approval flow | `TelegramApprovalHandler`, `ITelegramApprovalHandler`, `CallbackDataSigner`, `CallbackPayload`, `ApprovalContext` |
| `Session/` | Session bridging | `TelegramSessionBridge`, `ITelegramSessionBridge` |
| `Files/` | File receive and forwarding | `TelegramFileHandler`, `ITelegramFileHandler`, `FileReceiveResult` |
| `Health/` | Health monitoring | `TelegramHealthMonitor`, `ITelegramHealthMonitor` |
| `Infrastructure/` | Bot service, polling lock, input sanitization | `TelegramBotService`, `PollingLockFile`, `TelegramInputSanitizer` |
| `Configuration/` | DI registration | `ServiceExtensions` |

## Project Relationships

- **Depends on:** `Krutaka.Core` (interfaces and models), `Krutaka.Tools`, `Krutaka.Memory`, `Krutaka.AI`
- **Depended on by:** `Krutaka.Console` (when `HostMode` is `Telegram` or `Both`)

## Security Notes

- All Telegram user input MUST be sanitized through `TelegramInputSanitizer` before reaching Claude.
- Inline keyboard callbacks MUST be validated with HMAC-SHA256 via `CallbackDataSigner`.
- Bot token MUST NOT be stored in `appsettings.json` — use `ISecretsProvider` (Windows Credential Manager) or environment variables.
