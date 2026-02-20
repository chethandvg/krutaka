# Krutaka — Troubleshooting Guide

> **Last updated:** 2026-02-20 (v0.4.6)

This guide consolidates common errors and their solutions in one place. For setup instructions, see the [Local Setup Guide](LOCAL-SETUP.md), [Telegram Setup Guide](TELEGRAM-SETUP.md), or [Production Deployment Guide](PRODUCTION-DEPLOYMENT.md).

## Table of Contents

- [API & Secrets Issues](#api--secrets-issues)
  - [API key not found](#api-key-not-found)
  - [API key invalid format](#api-key-invalid-format)
  - [Rate limit exceeded](#rate-limit-exceeded)
- [Telegram Issues](#telegram-issues)
  - [Telegram user not authorized](#telegram-user-not-authorized)
  - [Bot not responding to messages](#bot-not-responding-to-messages)
  - [Polling lock file conflict](#polling-lock-file-conflict)
  - [Bot token not found](#bot-token-not-found)
  - [AllowedUsers cannot be null or empty](#allowedusers-cannot-be-null-or-empty)
- [Session Issues](#session-issues)
  - [Session resume crash](#session-resume-crash)
  - [Compaction fails](#compaction-fails)
- [Build & Test Issues](#build--test-issues)
  - [dotnet build fails](#dotnet-build-fails)
  - [Tests failing after file moves](#tests-failing-after-file-moves)
  - [Tests fail on non-Windows](#tests-fail-on-non-windows)
- [Runtime Issues](#runtime-issues)
  - [SQLite native library not found](#sqlite-native-library-not-found)
  - [Tool execution timeout](#tool-execution-timeout)
  - [Directory access denied](#directory-access-denied)
- [Common Error Messages Reference](#common-error-messages-reference)

---

## API & Secrets Issues

### API key not found

**Symptom:** The application fails to start with an error like:
```
Claude API key not found in secure credential store. Please run the setup wizard to configure your Anthropic API key.
```

**Cause:** Krutaka cannot locate the API key in Windows Credential Manager. The API key is read **only** from Windows Credential Manager via `ISecretsProvider` — environment variables are not used for the Anthropic API key.

**Solutions (try in order):**

1. **Re-run the setup wizard** — Start the application in Console mode; it will detect the missing key and prompt you:
   ```powershell
   dotnet run --project src/Krutaka.Console
   ```
   The wizard stores the key securely in Windows Credential Manager under `Krutaka_ApiKey`.

2. **Verify Credential Manager** — Open `Control Panel > User Accounts > Credential Manager > Windows Credentials > Generic Credentials` and look for `Krutaka_ApiKey`. If missing, run the wizard again.

3. **Check the running account** — For Windows Service deployments, the credential must be stored under the **same user account** the service runs as. If the service runs as `svc-krutaka`, log in as `svc-krutaka` and run the setup wizard once to store the credential in that account's Credential Manager.

4. **Delete and re-store** — If the credential is corrupted, delete `Krutaka_ApiKey` from Credential Manager and re-run the setup wizard.

---

### API key invalid format

**Symptom:**
```
[ERR] API key has invalid format. Expected key starting with 'sk-ant-'.
```

**Cause:** The key stored in Credential Manager was truncated, corrupted, or is from a different API provider.

**Fix:** Get a fresh API key from [console.anthropic.com/settings/keys](https://console.anthropic.com/settings/keys) (keys start with `sk-ant-api03-...`) and re-run the setup wizard.

---

### Rate limit exceeded

**Symptom:** The agent pauses mid-task with a message like:
```
[WRN] Rate limit hit (attempt 1/3). Retrying in 1.2s...
[WRN] Rate limit hit (attempt 2/3). Retrying in 2.4s...
```
Or after retries are exhausted:
```
[ERR] Rate limit exceeded after 3 attempts. Please try again later.
```

**Context:** v0.4.5+ automatically retries rate-limited requests with exponential backoff (1s → 2s → 4s, ±25% jitter, max 30s). This is expected behavior for heavy workloads.

**Solutions:**

1. **Wait and retry** — If retries are exhausted, wait 1 minute and send your request again. Anthropic rate limits reset per minute.

2. **Check your Anthropic plan** — Free/starter tier accounts have lower rate limits. Consider upgrading at [console.anthropic.com](https://console.anthropic.com/).

3. **Reduce token usage** — Shorten your prompts or reduce `MaxTokens` in `appsettings.json`:
   ```json
   "Claude": {
     "MaxTokens": 4096
   }
   ```

4. **Adjust retry configuration** — Retry settings live under the `Agent` section in `appsettings.json`. The keys use milliseconds:
   ```json
   "Agent": {
     "RetryMaxAttempts": 5,
     "RetryInitialDelayMs": 2000,
     "RetryMaxDelayMs": 60000
   }
   ```

> **Note:** The `retry-after` header from Anthropic is not yet parsed (blocked by Anthropic SDK v12.4.0 limitation). Krutaka uses calculated backoff, which is working well in practice. See `docs/status/PENDING-TASKS.md` (v0.4.5 Deferred §1) for status.

---

## Telegram Issues

### Telegram user not authorized

**Symptom:** The bot silently ignores your messages (no error reply). Or in logs:
```
[WRN] Unauthorized Telegram user {UserId} — message dropped
```

**Cause:** Your Telegram numeric User ID is not in the `AllowedUsers` array in `appsettings.json`. Unknown users are **silently dropped by design** (no error message is sent back to prevent information leakage).

**Fix:**

1. **Find your Telegram User ID** — Send any message to [@userinfobot](https://t.me/userinfobot). It replies with your numeric ID (e.g., `123456789`).

2. **Add your User ID to `appsettings.json`:**
   ```json
   "Telegram": {
     "AllowedUsers": [
       { "UserId": 123456789, "Role": "Admin" }
     ]
   }
   ```

3. **Restart the service/application** — Configuration changes require a restart.

> ⚠️ **Important:** Always use the numeric User ID, not your `@username`. Usernames can be changed and are not used for authentication.

---

### Bot not responding to messages

**Symptom:** The bot is running (logs show "Listening for updates") but does not reply to your messages.

**Possible causes and solutions:**

| Cause | Check | Fix |
|---|---|---|
| User ID not in `AllowedUsers` | Check logs for "Unauthorized Telegram user" | [See above](#telegram-user-not-authorized) |
| Invalid bot token | Check startup logs for token errors | Regenerate token with `/revoke` in @BotFather |
| Rate limit exceeded | Check logs for "Rate limit" warnings | Wait 1 minute, then retry |
| User is locked out | Check logs for "User locked out" | Wait for lockout to expire (default: 1 hour), or restart the service |
| Polling conflict | Check logs for "Cannot acquire polling lock" | [See Polling lock file conflict](#polling-lock-file-conflict) |
| Service not running | `sc.exe query "Krutaka"` or check Windows Services | Start the service |

---

### Polling lock file conflict

**Symptom:**
```
[ERR] Cannot acquire polling lock file. Another instance is already polling.
```

**Cause:** Two instances of Krutaka are trying to poll Telegram simultaneously. Only one process can poll at a time.

**Fix:**

1. **Find and stop the other instance:**
   ```powershell
   # Find all running Krutaka processes
   Get-Process -Name "Krutaka.Console" -ErrorAction SilentlyContinue

   # Stop a specific process by PID
   Stop-Process -Id <PID>
   ```

2. **Delete the stale lock file** (if the previous instance crashed without cleanup):
   ```powershell
   # Lock file is at {UserProfile}\.krutaka\.polling.lock
   Remove-Item "$env:USERPROFILE\.krutaka\.polling.lock" -ErrorAction SilentlyContinue
   ```

3. **Restart your instance** — After removing the stale lock, start Krutaka again.

---

### Bot token not found

**Symptom:**
```
[ERR] Telegram bot token not found. Set KRUTAKA_TELEGRAM_BOT_TOKEN environment variable.
```

**Fix:** Set the environment variable and restart:
```powershell
# User scope (interactive sessions, development)
[System.Environment]::SetEnvironmentVariable('KRUTAKA_TELEGRAM_BOT_TOKEN', 'YOUR-TOKEN', 'User')

# Machine scope (Windows Services, required for service accounts)
[System.Environment]::SetEnvironmentVariable('KRUTAKA_TELEGRAM_BOT_TOKEN', 'YOUR-TOKEN', 'Machine')
```

Restart your terminal or the Windows Service for the change to take effect.

---

### AllowedUsers cannot be null or empty

**Symptom:**
```
[ERR] Telegram configuration validation failed: AllowedUsers cannot be null or empty.
```

**Cause:** The `Telegram.AllowedUsers` array in `appsettings.json` is missing or empty. This is a deliberate security check — the bot refuses to start without an explicit allowlist.

**Fix:** Add at least one user to `AllowedUsers`:
```json
"Telegram": {
  "AllowedUsers": [
    { "UserId": 123456789, "Role": "Admin" }
  ]
}
```
Restart the application after saving the config.

---

## Session Issues

### Session resume crash

**Symptom** (v0.4.0 only):
```
[ERR] Failed to resume session: Object reference not set to an instance of an object.
```
Or the application crashes immediately after selecting "Resume last session".

**Cause:** This was a bug in v0.4.0 where session resume failed if the session file contained incomplete tool call records from a previous crash.

**Fix:** **Upgrade to v0.4.5 or later.** v0.4.5 introduced `RepairOrphanedToolUseBlocks` which automatically detects and repairs incomplete tool use/result pairs in session JSONL files before resuming. Resuming sessions that previously crashed is now safe.

If you cannot upgrade immediately:
1. Start a **new session** instead of resuming: use `/new` at the prompt
2. Manually delete the corrupted session file from `~/.krutaka/sessions/{project-hash}/`

---

### Compaction fails

**Symptom:**
```
[WRN] Context compaction failed (non-fatal): <error details>. Continuing without compaction.
```

**Cause:** Context compaction (summarizing old conversation history to free token budget) failed. This can happen due to:
- Transient Anthropic API error during summarization
- Rate limit hit during compaction
- Unusual conversation content that fails summarization

**Context:** As of v0.4.5, compaction failure is **non-fatal**. The agentic loop continues normally; compaction will be retried on the next iteration when the token budget threshold is exceeded again.

**What to do:**

1. **Nothing** — In most cases, compaction will succeed on the next attempt. Check logs to see if the failure is transient.

2. **Check for rate limit errors** — If compaction is failing repeatedly due to rate limits, see [Rate limit exceeded](#rate-limit-exceeded).

3. **Start a new session** — If the conversation is very long and compaction keeps failing, use `/new` to start fresh. Your memory summaries (in `memory.db` and `MEMORY.md`) are preserved.

4. **Check the logs** — The error message in `[WRN]` includes the root cause:
   ```powershell
   Select-String -Path "$env:USERPROFILE\.krutaka\logs\*.log" -Pattern "compaction failed"
   ```

---

## Build & Test Issues

### dotnet build fails

**Common errors and fixes:**

| Error | Cause | Fix |
|---|---|---|
| `error MSB1003: Specify a project` | Not in repo root | `cd` to the repo root before running `dotnet build` |
| `SDK '10.0.102' not found` | Wrong .NET version | Install .NET 10.0.102: [dotnet.microsoft.com](https://dotnet.microsoft.com/download/dotnet/10.0) |
| `NU1603: Package version mismatch` | Package version conflict | Check `Directory.Packages.props` for version mismatches |
| `CS8618: Non-nullable property` | Missing null initialization | Initialize the property or annotate with `= null!` |
| `CS0234: Type not found` | Missing `using` directive | Add the required `using` statement |
| `.slnx not supported` | Old IDE version | Use Visual Studio 2026+ or `dotnet` CLI |

Verify your .NET SDK version:
```powershell
dotnet --list-sdks
# Should include: 10.0.102 [C:\Program Files\dotnet\sdk]
```

---

### Tests failing after file moves

**Symptom:** Tests that were passing before now fail with errors like:
```
Error CS0234: The type or namespace name 'MyClass' does not exist in the namespace 'Krutaka.Core'
```
Or files appear to be missing from the build output.

**Cause:** A `.cs` file was moved to a subdirectory but the `.csproj` contains an explicit `<Compile Include="...">` reference to the old path. In SDK-style projects, files are included by default via glob patterns, but explicit references override this and create conflicts.

**Fix:**

1. **Check the `.csproj` for explicit file references:**
   ```xml
   <!-- Look for these — they break when files are moved -->
   <Compile Include="OldPath\MyClass.cs" />
   ```

2. **Remove the explicit reference** if it points to the old path. SDK-style projects automatically include all `.cs` files via `**\*.cs` glob, so explicit references are only needed for exclusions or non-default behavior.

3. **Verify the namespace was NOT changed** — Krutaka does not enforce namespace-to-directory mapping. Moving a file does **not** require changing its namespace. If you accidentally changed a namespace, revert it.

4. **Rebuild cleanly:**
   ```powershell
   dotnet clean
   dotnet build
   ```

> **Rule:** When moving `.cs` files, change ONLY the file's location. Never change namespaces, and check `.csproj` files for explicit `<Compile>` references that may need updating.

---

### Tests fail on non-Windows

**Symptom:** CI fails on Linux runners with errors like:
```
System.PlatformNotSupportedException: Windows Credential Manager is not supported on this platform.
```

**Cause:** Some tests exercise Windows-specific APIs (Windows Credential Manager, Windows Job Objects for sandboxing).

**Expected behavior:** These tests are expected to fail on non-Windows platforms. The CI pipeline uses Windows runners for the main test job. Tests requiring Windows APIs are marked with `[Trait("Platform", "Windows")]` or `[SkippableFact]`.

**Fix (for CI):** Ensure the CI workflow targets Windows runners:
```yaml
runs-on: windows-latest
```

**Fix (for local development on non-Windows):** Skip Windows-specific tests:
```powershell
dotnet test --filter "Platform!=Windows"
```

---

## Runtime Issues

### SQLite native library not found

**Symptom:**
```
[ERR] Unable to load shared library 'e_sqlite3': ...
```

**Cause:** The SQLite native library was not restored correctly.

**Fix:**
```powershell
dotnet restore
dotnet build
```

If the issue persists after restore, ensure you are running the correct platform binary (the published binary targets `win-x64`).

---

### Tool execution timeout

**Symptom:**
```
[WRN] Tool 'run_command' timed out after 30 seconds.
```

**Cause:** A shell command exceeded the configured timeout. Default is 30 seconds.

**Fix:** Increase `CommandTimeoutSeconds` in `appsettings.json`:
```json
"Agent": {
  "CommandTimeoutSeconds": 120
}
```

For long-running build commands (e.g., `dotnet build` on large solutions), 120–300 seconds is recommended.

---

### Directory access denied

**Symptom:**
```
[WRN] Access denied to directory 'C:\SensitiveFolder'. Policy: HardDeny.
```

**Cause:** The agent attempted to access a directory blocked by the security policy. System directories (`C:\Windows`, `C:\Program Files`, etc.) are always blocked regardless of configuration.

**Fix:**
- If this is a legitimate directory you want the agent to access, add it to the `AllowedDirectories` glob list in `appsettings.json`:
  ```json
  "AccessPolicy": {
    "AllowedDirectories": [
      "C:\\MyProjects\\**"
    ]
  }
  ```
- If this is unexpected, check whether the agent is attempting an unintended operation. Review the audit log for details.

---

## Common Error Messages Reference

| Error Message | Cause | Section |
|---|---|---|
| `Anthropic API key not found` | Missing credential or environment variable | [API key not found](#api-key-not-found) |
| `API key has invalid format` | Key truncated or wrong provider | [API key invalid format](#api-key-invalid-format) |
| `Rate limit hit (attempt N/M)` | Anthropic rate limit; retrying automatically | [Rate limit exceeded](#rate-limit-exceeded) |
| `Unauthorized Telegram user {UserId}` | User ID not in `AllowedUsers` | [Telegram user not authorized](#telegram-user-not-authorized) |
| `Cannot acquire polling lock file` | Two instances running simultaneously | [Polling lock file conflict](#polling-lock-file-conflict) |
| `Telegram bot token not found` | `KRUTAKA_TELEGRAM_BOT_TOKEN` not set | [Bot token not found](#bot-token-not-found) |
| `AllowedUsers cannot be null or empty` | Empty allowlist in config | [AllowedUsers cannot be null or empty](#allowedusers-cannot-be-null-or-empty) |
| `Failed to resume session` | Corrupted session file (pre-v0.4.5) | [Session resume crash](#session-resume-crash) |
| `Context compaction failed (non-fatal)` | Compaction error; loop continues | [Compaction fails](#compaction-fails) |
| `Tool 'run_command' timed out` | Command exceeded timeout | [Tool execution timeout](#tool-execution-timeout) |
| `Access denied to directory` | Policy blocked the path | [Directory access denied](#directory-access-denied) |
| `Unable to load shared library 'e_sqlite3'` | SQLite native library missing | [SQLite native library not found](#sqlite-native-library-not-found) |

---

## Getting Further Help

If your issue is not listed here:

1. **Check the logs** — `~/.krutaka/logs/krutaka-YYYYMMDD.log` contains detailed diagnostic information. Look for `[ERR]` and `[WRN]` entries.

2. **Check the audit log** — The structured audit log records all tool executions, approval decisions, and security events. Review it for unexpected patterns.

3. **Search existing issues** — [github.com/chethandvg/krutaka/issues](https://github.com/chethandvg/krutaka/issues)

4. **Open a new issue** — Include:
   - Version (`dotnet run --project src/Krutaka.Console -- --version`)
   - Operating mode (Console/Telegram/Both)
   - Relevant log lines (redact any API keys or bot tokens)
   - Steps to reproduce

---

## Related Documentation

- [Local Setup Guide](LOCAL-SETUP.md) — Development environment and first-run setup
- [Telegram Setup Guide](TELEGRAM-SETUP.md) — Bot creation and Telegram configuration
- [Production Deployment Guide](PRODUCTION-DEPLOYMENT.md) — Windows Service deployment
- [Architecture Overview](../architecture/OVERVIEW.md) — Component structure
- [Security Architecture](../architecture/SECURITY.md) — Threat model and security controls
