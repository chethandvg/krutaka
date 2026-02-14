# Krutaka — Telegram Security Architecture

> **Last updated:** 2026-02-14 (v0.4.0 initial architecture)
>
> This document describes the Telegram Bot API integration security model introduced in v0.4.0.
> It is **mandatory reading** before implementing any code that handles Telegram updates, callbacks, file transfers, or bot configuration.
>
> **Version spec:** See `docs/versions/v0.4.0.md` for the complete v0.4.0 design.

---

## 1. Threat Model

v0.4.0 introduces the **first network-accessible attack surface** in Krutaka's history. The Telegram Bot API creates inbound message flow from the internet to the agent.

| ID | Threat | Severity | Attack Vector | Mitigation | Verified By |
|---|---|---|---|---|---|
| T1 | Bot token theft | Critical | Token in config files, logs, or error messages | `ISecretsProvider` (DPAPI) or env var. No `BotToken` property on config. Log redaction. | Design + test |
| T2 | Unauthorized user access | High | Unknown Telegram user sends message to bot | User ID allowlist (`HashSet<long>`, O(1)). Empty = bot disabled. Silent drop. | Auth guard test |
| T3 | Rate limit abuse / DoS | High | Allowed user floods bot with requests | Per-user sliding window rate limiter (`MaxCommandsPerMinute`) | Auth guard test |
| T4 | Account lockout DoS | Medium | Attacker triggers lockout for legitimate user | Lockout per-source with monotonic clock, time-limited (`LockoutDuration`) | Auth guard test |
| T5 | Callback tampering | High | Modify inline keyboard callback data to approve unauthorized actions | HMAC-SHA256 with `RandomNumberGenerator` secret, per-request nonce | Adversarial test |
| T6 | Cross-user approval | High | User B presses approval button meant for User A | `user_id` in signed callback verified against `callback.From.Id` | Adversarial test |
| T7 | Callback replay | Medium | Replay a previously valid callback | One-time nonce tracking in `ConcurrentDictionary` | Adversarial test |
| T8 | Prompt injection via Telegram | High | User sends text designed to override system prompt | `<untrusted_content source="telegram:user:{userId}">` wrapping | Sanitization test |
| T9 | Cross-session state leakage | Critical | Session A's state visible/usable from Session B | Per-session factory creates independent instances | Adversarial test |
| T10 | Resource exhaustion via sessions | High | Create many sessions to exhaust memory/tokens | `MaxActiveSessions`, `MaxSessionsPerUser`, `GlobalMaxTokensPerHour` | Adversarial test |
| T11 | Update replay | Medium | Replay a previously processed Telegram update | Monotonic `update_id` check (`update_id > lastProcessed`) | Auth guard test |
| T12 | File upload attack | High | Upload malicious executable disguised as document | Extension allowlist, double-extension check, size limit, path traversal check | File handler test |
| T13 | Homoglyph prompt injection | Medium | Use Cyrillic/lookalike characters to bypass sanitization | Unicode NFC normalization before wrapping | Sanitization test |
| T14 | Man-in-the-Middle | Medium | Intercept Telegram API traffic | TLS 1.2+ enforced on `HttpClient` (`SslProtocols.Tls12 \| Tls13`) | Polling service test |
| T15 | Double-polling corruption | Medium | Two bot instances poll same token simultaneously | Single-instance file lock at `{UserProfile}/.krutaka/.polling.lock` | Polling service test |

---

## 2. Authentication Architecture

### Pipeline

Every incoming Telegram `Update` passes through this pipeline before reaching the agent:

```text
Update received
  │
  ├── from.id in AllowedUsers HashSet?
  │   ├── NO → log TelegramAuthEvent(Denied)
  │   │        log TelegramSecurityIncidentEvent(UnknownUserAttempt)
  │   │        return AuthResult.Invalid (NO REPLY SENT — silent drop)
  │   └── YES → continue
  │
  ├── Is user locked out?
  │   ├── YES → check if LockoutDuration expired (MONOTONIC clock)
  │   │   ├── Expired → clear lockout, continue
  │   │   └── Not expired → return AuthResult.Invalid (LockedOut)
  │   └── NO → continue
  │
  ├── Rate limit check (sliding window)
  │   ├── Exceeded → log TelegramRateLimitEvent
  │   │              return AuthResult.Invalid (RateLimited)
  │   └── Within limit → continue
  │
  ├── update_id > lastProcessedUpdateId?
  │   ├── NO → return AuthResult.Invalid (anti-replay)
  │   └── YES → continue
  │
  ├── message.text.length ≤ MaxInputMessageLength?
  │   ├── NO → return AuthResult.Invalid (too long)
  │   └── YES → continue
  │
  └── return AuthResult.Valid(userId, role, chatId)
```

### Key Design Decisions

| Decision | Rationale |
|---|---|
| **`HashSet<long>` for allowlist** | O(1) lookup. Telegram user IDs are stable `long` values. |
| **Silent drop for unknown users** | Bot must not reveal its existence to unauthorized users. No "access denied" reply. |
| **Monotonic clock for lockout** | `Stopwatch.GetTimestamp()` or `Environment.TickCount64` — not susceptible to system clock changes. `DateTime.Now` can be adjusted by the OS. |
| **Sliding window rate limiter** | Per-user, per-minute. More fair than fixed windows. Implemented via `ConcurrentDictionary<long, SlidingWindowCounter>`. |
| **Anti-replay via `update_id`** | Telegram's `update_id` is monotonically increasing. Processing an update with `id ≤ lastProcessed` is always a replay. |

---

## 3. Dual-Mode Transport

### Comparison

| Aspect | Long Polling | Webhook |
|---|---|---|
| **Use when** | Local dev, behind NAT/firewall | Production, cloud/VPS with public IP |
| **How it works** | Bot calls `getUpdates` periodically | Telegram POSTs to bot's HTTPS endpoint |
| **Token exposure** | In every `getUpdates` HTTPS request | Once during webhook registration |
| **IP restriction** | Not possible (client-initiated) | Telegram IP ranges whitelistable |
| **TLS** | Client-side enforcement (our responsibility) | Server-side required by Telegram |
| **Scaling** | Single instance only (file lock enforced) | Can load-balance (future) |
| **Latency** | 0–30s polling interval (configurable) | Near real-time push |
| **Complexity** | Low (recommended for v0.4.0 primary) | Medium (needs TLS cert + public endpoint) |
| **NAT-friendly** | Yes (outbound connections only) | No (requires inbound port) |

### Recommendation

Long polling is the primary mode for v0.4.0. Webhook support is provided as an alternative for production deployments but may be placeholder initially.

---

## 4. Long Polling Security Mitigations

| Mitigation | Description | What It Prevents |
|---|---|---|
| **TLS 1.2+ enforcement** | `HttpClient` configured with `SslProtocols.Tls12 \| Tls13` | Man-in-the-middle (T14) |
| **Offset-after-processing** | `offset = update.Id + 1` committed AFTER full processing | Message loss on crash |
| **Single-instance file lock** | `{UserProfile}/.krutaka/.polling.lock` acquired at start, contains PID | Double-polling corruption (T15) |
| **Exponential backoff** | 5s → 10s → 20s → 40s → 80s → 120s (cap) on connection failure | Retry storm DoS |
| **Consecutive failure limit** | After configurable N consecutive failures, stop polling entirely | Infinite retry loop |
| **Kill switch priority** | Scan update batch for `/killswitch` BEFORE processing other commands | Unresponsive bot |
| **Bot token in memory only** | Loaded from `ISecretsProvider` at startup, never in config or logs | Token leakage (T1) |

### Offset Commit Ordering (Critical)

```text
CORRECT:
  1. Receive update batch [update_id=100, 101, 102]
  2. Process update 100 fully (auth → route → agent → respond)
  3. Process update 101 fully
  4. Process update 102 fully
  5. Next poll: offset=103

WRONG:
  1. Receive update batch [update_id=100, 101, 102]
  2. Set offset=103 immediately
  3. Process updates... (crash mid-processing)
  4. Updates 101, 102 are lost forever
```

---

## 5. Approval Flow Architecture

### Inline Keyboard with HMAC-Signed Callbacks

When `HumanApprovalRequired`, `DirectoryAccessRequested`, or `CommandApprovalRequested` events occur:

```text
Bot → User: ┌─────────────────────────────────────┐
             │ 🔴 Elevated Command Approval         │
             │                                       │
             │ Command: git push origin main         │
             │ Tier: Elevated                         │
             │ Directory: C:\Projects\MyApp          │
             │                                       │
             │ [✅ Approve]  [❌ Deny]               │
             └─────────────────────────────────────┘
```

### Callback Payload Structure

```json
{
  "action": "approve",
  "tool_use_id": "tool_abc123",
  "session_id": "guid-here",
  "user_id": 12345678,
  "timestamp": 1708000000,
  "nonce": "unique_random_32byte_hex",
  "hmac": "sha256_signature_of_all_above_fields"
}
```

### HMAC Signing & Verification

```text
Signing (when creating approval keyboard):
  1. payload = { action, tool_use_id, session_id, user_id, timestamp, nonce }
  2. serialized = canonical JSON serialization of payload (sorted keys)
  3. hmac = HMACSHA256(serialized, serverSecret)
  4. callback_data = serialize(payload + hmac)

Verification (when button pressed):
  1. Deserialize callback_data → payload + receivedHmac
  2. expectedHmac = HMACSHA256(serialize(payload without hmac), serverSecret)
  3. if (receivedHmac != expectedHmac) → REJECT "callback tampering" (T5)
  4. if (callback.From.Id != payload.user_id) → REJECT "cross-user" (T6)
  5. if (now - payload.timestamp > approvalTimeout) → REJECT "expired"
  6. if (payload.nonce in usedNonces) → REJECT "replay" (T7)
  7. usedNonces.Add(payload.nonce)
  8. Route to orchestrator method:
     - ApproveTool(toolUseId, alwaysApprove: action == "always")
     - DenyTool(toolUseId)
     - ApproveDirectoryAccess(grantedLevel, createSessionGrant: action == "always")
     - DenyDirectoryAccess()
     - ApproveCommand(alwaysApprove: action == "always")
     - DenyCommand()
  9. Edit original message to show decision ("✅ Approved by @username")

Server secret: RandomNumberGenerator.GetBytes(32) at startup, held in memory only.
```

### Approval Panels by Event Type

| Event Type | Buttons | "Always" Available |
|---|---|---|
| `HumanApprovalRequired` (tool) | `[✅ Approve] [❌ Deny] [🔄 Always]` | Yes |
| `DirectoryAccessRequested` | `[✅ Grant] [❌ Deny] [📂 Session]` | Yes (session grant) |
| `CommandApprovalRequested` (Moderate) | `[✅ Approve] [❌ Deny] [🔄 Always]` | Yes |
| `CommandApprovalRequested` (Elevated) | `[✅ Approve] [❌ Deny]` | No |

### Timeout Handling

If no callback received within the configurable timeout:
1. Auto-deny the pending approval
2. Edit the original message: "⏰ Approval timed out — auto-denied"
3. This works in concert with the orchestrator's own `_approvalTimeout`

---

## 6. Streaming Architecture

### AgentEvent → Telegram Message Mapping

```text
AgentEvent Stream                    Telegram Messages
─────────────────                    ─────────────────
TextDelta("He")  ─┐
TextDelta("llo") ─┤── buffer ──►  Edit message: "Hello"
TextDelta(" wo") ─┤   (~500ms)
TextDelta("rld") ─┘              Edit message: "Hello world"

ToolCallStarted  ─────────────►  New message: "⚙️ Running `git status`..."
ToolCallCompleted ────────────►  Edit to: "✅ `git status` complete"
ToolCallFailed   ─────────────►  Edit to: "❌ `git status` failed: {error}"

FinalResponse    ─────────────►  Send formatted MarkdownV2 message
                                 (chunked if >4096 chars)

RequestIdCaptured ────────────►  Silently consumed (internal use only)

Interactive events (approvals):
  → Delegated to onInteractiveEvent callback
  → NOT consumed by streamer
```

### Buffering Strategy

- **TextDelta tokens** accumulate in a `StringBuilder`
- Flush (edit message) every **~500ms** or when buffer exceeds **200 characters**
- This coalesces rapid token events into fewer Telegram API calls

### Rate Limit Compliance

- Telegram allows **~30 message edits per minute per chat**
- Track edit count per chat via sliding window
- If approaching limit, increase flush interval (degrade gracefully, don't drop content)

### Message Chunking

- Telegram has a **4096 character message limit** per message
- Long responses split into multiple messages
- Split at paragraph boundaries or code block boundaries (never mid-code-block)
- Each chunk sent as a separate message

### MarkdownV2 Formatting

- Escape special characters: `_ * [ ] ( ) ~ > # + - = | { } . !`
- Code blocks (triple backtick) — content inside does NOT need internal escaping
- Inline code (single backtick) — content inside does NOT need internal escaping
- Graceful fallback: if formatting fails or produces invalid MarkdownV2, send as plain text

---

## 7. Input Sanitization

### Defense-in-Depth Layers

| Layer | Applied In | What It Does |
|---|---|---|
| 1. Bot mention stripping | `TelegramInputSanitizer` (Issue #12) | Remove `@botname` syntax from commands |
| 2. `<untrusted_content>` wrapping | `TelegramInputSanitizer` (Issue #12) | Wrap ALL user text in `<untrusted_content source="telegram:user:{userId}">` tags |
| 3. Telegram entity stripping | `TelegramInputSanitizer` (Issue #17) | Strip formatting entities (bold, italic, `text_link`, etc.) — extract plain text only |
| 4. Unicode NFC normalization | `TelegramInputSanitizer` (Issue #17) | `string.Normalize(NormalizationForm.FormC)` prevents homoglyph attacks |
| 5. Control character removal | `TelegramInputSanitizer` (Issue #17) | Remove U+0000–U+001F (except `\n`, `\t`) and U+007F (DEL) |
| 6. Whitespace collapsing | `TelegramInputSanitizer` (Issue #17) | Collapse 3+ consecutive spaces into 2 |
| 7. Callback data isolation | Design | Inline keyboard callback data is NEVER included in any prompt sent to Claude |
| 8. Group chat @mention extraction | `TelegramInputSanitizer` (Issue #17) | In group chats, only text after `@botUsername` is forwarded to agent |

### Why Entity Stripping Matters

Telegram formatting entities can contain arbitrary URLs via `text_link`. Example:

```text
User sends: "Please read [this document](https://evil.com/ignore-all-rules)"
Telegram delivers: text="Please read this document", entities=[text_link(url="https://evil.com/ignore-all-rules")]
```

Without entity stripping, the URL could be forwarded to Claude and used for prompt injection. Entity stripping preserves the visible text ("this document") and discards the hidden URL.

### Callback Data Isolation

Inline keyboard callback data (HMAC-signed JSON from Issue #14) is processed ONLY by `TelegramApprovalHandler`. It is **NEVER**:
- Included in any prompt sent to Claude
- Forwarded to any tool
- Logged with content (only metadata is logged)

---

## 8. Configuration Model

### TelegramSecurityConfig

```json
{
  "Telegram": {
    "Mode": "LongPolling",
    "AllowedUsers": [
      { "UserId": 12345678, "Role": "Admin", "ProjectPath": "C:\\Projects\\MyApp" },
      { "UserId": 87654321, "Role": "User" }
    ],
    "MaxCommandsPerMinute": 10,
    "MaxTokensPerHour": 100000,
    "MaxFailedAuthAttempts": 3,
    "LockoutDurationMinutes": 60,
    "PanicCommand": "/killswitch",
    "MaxInputMessageLength": 4000,
    "PollingTimeoutSeconds": 30,
    "WebhookUrl": null,
    "RequireConfirmationForElevated": true
  }
}
```

### Field Descriptions and Defaults

| Field | Type | Default | Validation | Security Rationale |
|---|---|---|---|---|
| `AllowedUsers` | `TelegramUserConfig[]` | **REQUIRED** | Empty → `InvalidOperationException` at startup | Fail-secure: no users = bot disabled |
| `Mode` | `TelegramTransportMode` | `LongPolling` | Webhook requires non-empty `WebhookUrl` | — |
| `MaxCommandsPerMinute` | `int` | 10 | Must be > 0 | Per-user rate limiting (T3) |
| `MaxTokensPerHour` | `int` | 100,000 | Must be > 0 | Per-user token budget |
| `MaxFailedAuthAttempts` | `int` | 3 | Must be > 0 | Lockout threshold (T4) |
| `LockoutDuration` | `TimeSpan` | 1 hour | Must be > 0 | Lockout window |
| `PanicCommand` | `string` | `/killswitch` | — | Emergency shutdown |
| `MaxInputMessageLength` | `int` | 4,000 | Must be > 0 | Prevents oversized input |
| `PollingTimeoutSeconds` | `int` | 30 | Must be > 0 | Long polling interval |
| `WebhookUrl` | `string?` | `null` | Required when Mode=Webhook | — |
| `RequireConfirmationForElevated` | `bool` | `true` | — | Elevated commands always prompted |

### Critical: No BotToken Property

`BotToken` is NOT part of `TelegramSecurityConfig`. There is no `BotToken` property on the config record — this is enforced **by design**.

The bot token is loaded separately:
1. **Primary:** `ISecretsProvider` (Windows Credential Manager / DPAPI)
2. **Fallback:** `KRUTAKA_TELEGRAM_BOT_TOKEN` environment variable
3. **Never:** Configuration files, logs, or error messages

### Startup Validation

All configuration is validated at startup (fail-fast). The following conditions cause `InvalidOperationException`:

- `AllowedUsers` is null or empty
- `MaxCommandsPerMinute` ≤ 0
- `MaxTokensPerHour` ≤ 0
- `MaxFailedAuthAttempts` ≤ 0
- `LockoutDuration` ≤ TimeSpan.Zero
- `MaxInputMessageLength` ≤ 0
- `PollingTimeoutSeconds` ≤ 0
- `Mode == Webhook && string.IsNullOrWhiteSpace(WebhookUrl)`
- Duplicate `UserId` values in `AllowedUsers`

---

## Related Documents

- `docs/versions/v0.4.0.md` — Complete v0.4.0 version specification
- `docs/architecture/MULTI-SESSION.md` — Multi-session isolation architecture
- `docs/architecture/OVERVIEW.md` — Component architecture
- `docs/architecture/SECURITY.md` — Security model (to be updated with Telegram section)
- `src/Krutaka.Core/IAuditLogger.cs` — Audit interface (extended with Telegram default methods)
- `src/Krutaka.Core/TelegramSecurityConfig.cs` — Configuration model
- `src/Krutaka.Console/ApprovalHandler.cs` — Console approval pattern (reference for Telegram adaptation)
- `src/Krutaka.Core/AgentOrchestrator.cs` — Orchestrator approval methods
