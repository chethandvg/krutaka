# Krutaka — Production Deployment Guide

> **Last updated:** 2026-02-20 (v0.4.6)

This guide covers deploying Krutaka to a Windows production environment as a long-running headless service, including secrets management, log rotation, health monitoring, and backup strategy.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1: Build a Release Binary](#step-1-build-a-release-binary)
- [Step 2: Configure Secrets](#step-2-configure-secrets)
- [Step 3: Configure Headless Telegram Mode](#step-3-configure-headless-telegram-mode)
- [Step 4: Install as a Windows Service](#step-4-install-as-a-windows-service)
  - [Option A: sc.exe (built-in)](#option-a-scexe-built-in)
  - [Option B: NSSM (Non-Sucking Service Manager)](#option-b-nssm-non-sucking-service-manager)
- [Step 5: Log Rotation and Retention](#step-5-log-rotation-and-retention)
- [Step 6: Health Monitoring](#step-6-health-monitoring)
- [Step 7: Backup Strategy](#step-7-backup-strategy)
- [Step 8: Updating the Application](#step-8-updating-the-application)
- [Security Checklist](#security-checklist)

---

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Windows | 10 22H2+ or Server 2022 (x64) | Service Account recommended |
| .NET SDK | 10.0.102+ | Only needed for building; not required at runtime |
| Telegram bot token | — | From [@BotFather](https://t.me/BotFather) |
| Anthropic API key | — | From [console.anthropic.com](https://console.anthropic.com/) |

> **Note:** The published binary is self-contained and does not require the .NET runtime to be installed on the production machine.

---

## Step 1: Build a Release Binary

Build a self-contained, single-file executable on your development machine:

```powershell
# From the repository root
dotnet publish src/Krutaka.Console -c Release

# Output:
# src/Krutaka.Console/bin/Release/net10.0-windows/win-x64/publish/Krutaka.Console.exe
```

Copy the published directory to the production machine. A recommended deployment path is:

```
C:\Services\Krutaka\
├── Krutaka.Console.exe   # ~82 MB self-contained binary
├── appsettings.json      # Configuration (no secrets here)
└── prompts\
    └── AGENTS.md         # Agent system prompt
```

---

## Step 2: Configure Secrets

Krutaka **never** stores secrets in `appsettings.json`. Each secret uses a different storage mechanism:

- **Anthropic API key** — stored in **Windows Credential Manager** (read via `ISecretsProvider`)
- **Telegram bot token** — supplied via **environment variable** (`KRUTAKA_TELEGRAM_BOT_TOKEN`)

### Anthropic API Key (Windows Credential Manager)

Krutaka reads the Anthropic API key **only** from Windows Credential Manager via `ISecretsProvider`. Environment variables are **not** used for the API key.

For an interactive console deployment, the built-in setup wizard handles this automatically. For a Windows Service running under a dedicated service account:

1. **Log on as (or impersonate) the service account** — open an interactive session under the account that will run the service.
2. **Run the setup wizard once** to store the API key under that account's Credential Manager:
   ```powershell
   C:\Services\Krutaka\Krutaka.Console.exe
   ```
   The wizard prompts for the key and stores it under `Krutaka_ApiKey` in Windows Credential Manager for the current user.
3. **Verify the credential** — open `Control Panel > User Accounts > Credential Manager > Windows Credentials > Generic Credentials` for the service account and confirm `Krutaka_ApiKey` is present.

> ⚠️ **Important:** The credential is stored per-user in Windows Credential Manager. It must be stored under the **same account** that the Windows Service runs as, not the administrator account used to install the service.

### Telegram Bot Token (`KRUTAKA_TELEGRAM_BOT_TOKEN`)

Set the environment variable scoped to the Windows Service account:

```powershell
# Machine scope — inherited by all services (use only if the machine is single-tenant)
# Run as Administrator:
[System.Environment]::SetEnvironmentVariable(
    'KRUTAKA_TELEGRAM_BOT_TOKEN',
    '1234567890:ABCdefGHIjklMNOpqrsTUVwxyz123456789',
    'Machine'
)
```

> ⚠️ **Security:** Machine-scoped environment variables are visible to all processes on the machine. For multi-tenant machines, use NSSM's `AppEnvironmentExtra` setting (see Option B below) to scope the variable to the Krutaka service only.

### Verify the Bot Token Is Set

```powershell
[System.Environment]::GetEnvironmentVariable('KRUTAKA_TELEGRAM_BOT_TOKEN', 'Machine')
```

---

## Step 3: Configure Headless Telegram Mode

Edit `C:\Services\Krutaka\appsettings.json` for headless Telegram-only production use:

```json
{
  "Mode": "Telegram",
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft": "Warning"
    }
  },
  "Claude": {
    "ModelId": "claude-4-sonnet-20250514",
    "MaxTokens": 8192,
    "Temperature": 0.7
  },
  "Agent": {
    "WorkingDirectory": "C:\\Services\\Krutaka\\workspace",
    "CommandTimeoutSeconds": 60,
    "ToolTimeoutSeconds": 60,
    "RequireApprovalForWrites": true,
    "MaxToolResultCharacters": 0,
    "RetryMaxAttempts": 3,
    "RetryInitialDelayMs": 1000,
    "RetryMaxDelayMs": 30000
  },
  "ContextCompaction": {
    "PruneToolResultsAfterTurns": 6,
    "PruneToolResultMinChars": 1000
  },
  "SessionManager": {
    "MaxActiveSessions": 10,
    "IdleTimeoutMinutes": 30,
    "SuspendedSessionTtlMinutes": 1440
  },
  "Telegram": {
    "AllowedUsers": [
      {
        "UserId": 123456789,
        "Role": "Admin",
        "ProjectPath": "C:\\Services\\Krutaka\\workspace"
      }
    ],
    "RequireConfirmationForElevated": true,
    "MaxCommandsPerMinute": 10,
    "MaxTokensPerHour": 100000,
    "MaxFailedAuthAttempts": 3,
    "LockoutDuration": "01:00:00",
    "PanicCommand": "/killswitch",
    "MaxInputMessageLength": 4000,
    "Mode": "LongPolling",
    "PollingTimeoutSeconds": 30
  }
}
```

### Key Production Settings

| Setting | Recommended Value | Reason |
|---|---|---|
| `Mode` | `"Telegram"` | No console UI in headless deployment |
| `Agent.WorkingDirectory` | Absolute path | Do not use `.` in production |
| `Telegram.RequireConfirmationForElevated` | `true` | Mandatory for security |
| `SessionManager.MaxActiveSessions` | 10 (default) | Tune based on expected load |
| `Agent.CommandTimeoutSeconds` | 60 | Increase for longer-running builds |

---

## Step 4: Install as a Windows Service

Choose **Option A** (built-in `sc.exe`) for simplicity, or **Option B** (NSSM) for more control over stdout/stderr logging, restart policies, and environment variables per-service.

### Option A: sc.exe (built-in)

`sc.exe` creates a native Windows Service with minimal configuration. Stdout/stderr are not automatically captured — use Serilog file logging (configured in Step 5).

**Create the service (run as Administrator):**

```powershell
sc.exe create "Krutaka" `
    binPath= "C:\Services\Krutaka\Krutaka.Console.exe" `
    DisplayName= "Krutaka AI Agent" `
    start= auto

sc.exe description "Krutaka" "OpenClaw-inspired AI agent with Telegram remote access"
```

**Start the service:**

```powershell
sc.exe start "Krutaka"
```

**Verify it is running:**

```powershell
sc.exe query "Krutaka"
# Should show: STATE: 4  RUNNING
```

**Stop the service:**

```powershell
sc.exe stop "Krutaka"
```

**Remove the service (when uninstalling):**

```powershell
sc.exe stop "Krutaka"
sc.exe delete "Krutaka"
```

> ⚠️ **Limitation:** `sc.exe` does not support per-service environment variables. Secrets set via `[System.Environment]::SetEnvironmentVariable(..., 'Machine')` are inherited by the service process.

---

### Option B: NSSM (Non-Sucking Service Manager)

[NSSM](https://nssm.cc/) provides richer service management including stdout/stderr redirection to log files, automatic restart on failure, and per-service environment variables.

**Install NSSM:**

```powershell
# Using winget
winget install nssm

# Or download from https://nssm.cc/download and add to PATH
```

**Install Krutaka as a service:**

```powershell
nssm install "Krutaka" "C:\Services\Krutaka\Krutaka.Console.exe"
```

**Configure via NSSM GUI** (opens automatically after install) or via CLI:

```powershell
# Application settings
nssm set "Krutaka" AppDirectory "C:\Services\Krutaka"
nssm set "Krutaka" DisplayName "Krutaka AI Agent"
nssm set "Krutaka" Description "OpenClaw-inspired AI agent with Telegram remote access"

# Stdout/stderr logging (in addition to Serilog file logging)
nssm set "Krutaka" AppStdout "C:\Services\Krutaka\logs\service-stdout.log"
nssm set "Krutaka" AppStderr "C:\Services\Krutaka\logs\service-stderr.log"
nssm set "Krutaka" AppRotateFiles 1
nssm set "Krutaka" AppRotateSeconds 86400
nssm set "Krutaka" AppRotateBytes 10485760

# Restart policy: restart after 5 seconds on failure
nssm set "Krutaka" AppExit Default Restart
nssm set "Krutaka" AppRestartDelay 5000

# Startup type: automatic
nssm set "Krutaka" Start SERVICE_AUTO_START

# Per-service environment variable for Telegram bot token
# (scopes it to this service only, instead of Machine-wide)
nssm set "Krutaka" AppEnvironmentExtra `
    "KRUTAKA_TELEGRAM_BOT_TOKEN=1234567890:YOUR-TOKEN-HERE"
```

**Start the service:**

```powershell
nssm start "Krutaka"
```

**Check service status:**

```powershell
nssm status "Krutaka"
# Should output: SERVICE_RUNNING
```

**Remove the service:**

```powershell
nssm stop "Krutaka"
nssm remove "Krutaka" confirm
```

---

## Step 5: Log Rotation and Retention

Krutaka configures Serilog directly in code (`Program.cs`) with a hardcoded base path of `%USERPROFILE%\.krutaka\logs\`. The rolling file settings (daily rotation, 30-day retention) are also set in code and **cannot be overridden via `appsettings.json`**.

For a Windows Service, `%USERPROFILE%` resolves to the service account's profile:

| Service Account | Resolved Log Path |
|---|---|
| `LocalSystem` | `C:\Windows\System32\config\systemprofile\.krutaka\logs\` |
| `LocalService` | `C:\Windows\ServiceProfiles\LocalService\.krutaka\logs\` |
| Custom user account | `C:\Users\{username}\.krutaka\logs\` |

> **Recommendation:** Run the service under a **dedicated named service account** (e.g., `svc-krutaka`) rather than `LocalSystem`. This gives you a predictable, accessible log path at `C:\Users\svc-krutaka\.krutaka\logs\` and limits the service's system privileges.

### Built-in Log Rotation Settings

The following settings are configured in `Program.cs` and apply to all deployments:

| Setting | Value | Effect |
|---|---|---|
| Rolling interval | Daily | New log file each day (`krutaka-YYYYMMDD.log`) |
| Retained file count | 30 | Keeps last 30 days of log files |
| Format | `{Timestamp} [{Level}] {Message}` | Structured text output |

### Monitoring Log Files

```powershell
# Replace {LogDir} with the resolved path for your service account, e.g.:
$logDir = "C:\Users\svc-krutaka\.krutaka\logs"

# View the current day's log (last 50 lines)
Get-Content "$logDir\krutaka-$(Get-Date -Format yyyyMMdd).log" -Tail 50

# Follow logs in real-time (PowerShell equivalent of `tail -f`)
Get-Content "$logDir\krutaka-$(Get-Date -Format yyyyMMdd).log" -Wait -Tail 20

# Search all log files for errors and warnings
Select-String -Path "$logDir\*.log" -Pattern "\[ERR\]|\[WRN\]"
```

### Log Redaction

All Anthropic API keys (`sk-ant-*` patterns) are automatically replaced with `***REDACTED***` by Krutaka's `LogRedactionEnricher` before writing to log files. Bot tokens are also redacted. **Never disable the log redaction filter in production.**

---

## Step 6: Health Monitoring

Krutaka sends health notifications to Telegram users with the `Admin` role. These notifications are sent automatically when the service starts, stops, or encounters a critical error.

### Admin User Configuration

Ensure at least one user in `AllowedUsers` has `"Role": "Admin"`:

```json
"Telegram": {
  "AllowedUsers": [
    {
      "UserId": 123456789,
      "Role": "Admin",
      "ProjectPath": "C:\\Services\\Krutaka\\workspace"
    }
  ]
}
```

Admin users receive:
- ✅ **Service start notification** — Sent when the Telegram bot initializes successfully
- ⚠️ **Rate limit warning** — Sent when the Anthropic API rate limit is hit repeatedly
- ❌ **Fatal error notification** — Sent before the service shuts down due to an unrecoverable error
- 🔴 **Killswitch notification** — Sent when `/killswitch` command is used

### Windows Event Log Monitoring

The Windows Service logs critical events to the Windows Application Event Log. Monitor it with:

```powershell
# View last 10 Krutaka-related events
Get-EventLog -LogName Application -Source "Krutaka" -Newest 10

# Watch for errors in real time
Get-EventLog -LogName Application -EntryType Error -Source "Krutaka" -Newest 5
```

### External Monitoring (Optional)

For production uptime monitoring, use a tool like:

- **Windows Task Scheduler** — Run a health-check script every 5 minutes that verifies the service is running
- **Prometheus + Grafana** — Scrape a custom `/metrics` endpoint (not currently implemented; planned for a future release)
- **Azure Monitor / Application Insights** — Collect Serilog logs via the Application Insights sink

A basic PowerShell health-check script:

```powershell
# health-check.ps1 — run via Task Scheduler every 5 minutes
$svc = Get-Service -Name "Krutaka" -ErrorAction SilentlyContinue
if ($null -eq $svc -or $svc.Status -ne "Running") {
    # Restart the service
    Start-Service -Name "Krutaka"
    # Optionally send an alert (email, webhook, etc.)
    Write-EventLog -LogName Application -Source "KrutakaMonitor" `
        -EventId 1001 -EntryType Warning `
        -Message "Krutaka service was not running and has been restarted."
}
```

---

## Step 7: Backup Strategy

Krutaka stores persistent data in two locations:

### Data Locations

| Data | Location | Format | Sensitivity |
|---|---|---|---|
| Conversation sessions | `%USERPROFILE%\.krutaka\sessions\{project-hash}\*.jsonl` | JSONL (one JSON object per line) | Medium — may contain file contents |
| Memory database | `%USERPROFILE%\.krutaka\memory.db` | SQLite | Low — AI-generated summaries |
| Human-readable memory | `%USERPROFILE%\.krutaka\MEMORY.md` | Markdown | Low |
| Logs | `%USERPROFILE%\.krutaka\logs\*.log` | Text | Low (secrets are redacted) |

> For Windows Services running under `LocalSystem`, `%USERPROFILE%` resolves to `C:\Windows\System32\config\systemprofile\`. Use a dedicated service account with a known profile path to make backups predictable.

### Recommended Backup Approach

**Daily incremental backup using Robocopy:**

```powershell
# backup-krutaka.ps1 — run via Task Scheduler daily at 2 AM
$source = "C:\Windows\System32\config\systemprofile\.krutaka"
$dest   = "D:\Backups\Krutaka\$(Get-Date -Format yyyy-MM-dd)"

robocopy $source $dest /E /XD logs /XF *.log /NP /LOG:"D:\Backups\krutaka-backup.log"
```

> The `/XD logs /XF *.log` flags exclude log files from the backup (they are large and not critical for recovery).

### Restoring from Backup

1. **Stop the service:**
   ```powershell
   sc.exe stop "Krutaka"
   ```

2. **Restore session files:**
   ```powershell
   robocopy "D:\Backups\Krutaka\2026-02-19" `
       "C:\Windows\System32\config\systemprofile\.krutaka" /E
   ```

3. **Start the service:**
   ```powershell
   sc.exe start "Krutaka"
   ```

### SQLite Database Backup

For the `memory.db` SQLite database, use SQLite's online backup API to take a consistent snapshot without stopping the service:

```powershell
# Requires sqlite3.exe — download from https://sqlite.org/download.html
sqlite3 "C:\...\memory.db" ".backup 'D:\Backups\Krutaka\memory-$(Get-Date -Format yyyy-MM-dd).db'"
```

---

## Step 8: Updating the Application

### Standard Update Procedure

1. **Stop the service:**
   ```powershell
   sc.exe stop "Krutaka"
   # Wait for service to stop completely
   Start-Sleep -Seconds 5
   ```

2. **Back up the current deployment:**
   ```powershell
   Copy-Item -Path "C:\Services\Krutaka" `
       -Destination "C:\Services\Krutaka.backup-$(Get-Date -Format yyyy-MM-dd)" `
       -Recurse
   ```

3. **Build the new version** (on your development machine):
   ```powershell
   git pull origin main
   dotnet publish src/Krutaka.Console -c Release
   ```

4. **Copy the new binary** to the production machine:
   ```powershell
   Copy-Item -Path "src\Krutaka.Console\bin\Release\net10.0-windows\win-x64\publish\Krutaka.Console.exe" `
       -Destination "C:\Services\Krutaka\Krutaka.Console.exe" `
       -Force
   ```

5. **Review `appsettings.json`** for any new configuration keys added in the new version (check `CHANGELOG.md`). Merge new settings carefully — do not overwrite your production config.

6. **Start the service:**
   ```powershell
   sc.exe start "Krutaka"
   ```

7. **Verify the service started correctly:**
   ```powershell
   sc.exe query "Krutaka"
   # Check the service account's log directory, e.g.:
   Get-Content "C:\Users\svc-krutaka\.krutaka\logs\krutaka-$(Get-Date -Format yyyyMMdd).log" -Tail 20
   ```

### Rollback Procedure

If the new version fails to start:

```powershell
sc.exe stop "Krutaka"
# Restore previous binary
Copy-Item -Path "C:\Services\Krutaka.backup-2026-02-19\Krutaka.Console.exe" `
    -Destination "C:\Services\Krutaka\Krutaka.Console.exe" -Force
sc.exe start "Krutaka"
```

---

## Security Checklist

Before going live, verify:

- [ ] `appsettings.json` contains **no secrets** (no API keys, no bot tokens)
- [ ] Anthropic API key is stored in **Windows Credential Manager** under the service account (`Krutaka_ApiKey`)
- [ ] `KRUTAKA_TELEGRAM_BOT_TOKEN` is set as an environment variable (not in config)
- [ ] `Telegram.AllowedUsers` is configured with explicit user IDs (not empty)
- [ ] `Telegram.RequireConfirmationForElevated` is `true`
- [ ] `Agent.WorkingDirectory` points to a specific project directory (not `.`)
- [ ] Log directory for the service account is known and accessible
- [ ] Backup schedule is configured and tested
- [ ] At least one Admin user is configured for health notifications
- [ ] Service account has minimal permissions (read/write only to workspace, no admin rights)
- [ ] Bot token is stored per-service (not Machine-scope) if other services share this machine

---

## Related Documentation

- [Local Setup Guide](LOCAL-SETUP.md) — Development environment setup
- [Telegram Setup Guide](TELEGRAM-SETUP.md) — Bot creation and configuration
- [Troubleshooting Guide](TROUBLESHOOTING.md) — Common errors and solutions
- [Security Architecture](../architecture/SECURITY.md) — Threat model and security controls
- [Telegram Architecture](../architecture/TELEGRAM.md) — Multi-session isolation
