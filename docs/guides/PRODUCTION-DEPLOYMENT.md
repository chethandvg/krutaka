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

Krutaka **never** stores secrets in `appsettings.json`. Production deployments must supply secrets via environment variables scoped to the Windows Service account.

### Anthropic API Key (`KRUTAKA_ANTHROPIC_API_KEY`)

> **Note:** In interactive (console) mode, the API key is stored in Windows Credential Manager via the setup wizard. For a Windows Service (which has no interactive session), use the environment variable instead.

Set the environment variable for the **System** scope (visible to Windows Services):

```powershell
# Run as Administrator
[System.Environment]::SetEnvironmentVariable(
    'KRUTAKA_ANTHROPIC_API_KEY',
    'sk-ant-api03-YOUR-KEY-HERE',
    'Machine'
)
```

> ⚠️ **Security:** Machine-scoped environment variables are visible to all processes on the machine. If multiple services share this machine, consider a dedicated service account with User-scoped variables, or use a secrets vault (Azure Key Vault, HashiCorp Vault).

### Telegram Bot Token (`KRUTAKA_TELEGRAM_BOT_TOKEN`)

```powershell
# Run as Administrator
[System.Environment]::SetEnvironmentVariable(
    'KRUTAKA_TELEGRAM_BOT_TOKEN',
    '1234567890:ABCdefGHIjklMNOpqrsTUVwxyz123456789',
    'Machine'
)
```

### Verify Variables Are Set

After setting, verify both variables before continuing:

```powershell
[System.Environment]::GetEnvironmentVariable('KRUTAKA_ANTHROPIC_API_KEY', 'Machine')
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
    "MaxToolResultCharacters": 0
  },
  "Retry": {
    "MaxAttempts": 3,
    "InitialDelaySeconds": 1,
    "MaxDelaySeconds": 30
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

# Per-service environment variables (alternative to Machine-scoped)
nssm set "Krutaka" AppEnvironmentExtra `
    "KRUTAKA_ANTHROPIC_API_KEY=sk-ant-api03-YOUR-KEY-HERE" `
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

Krutaka uses Serilog with a rolling file sink. By default, logs are written to `%USERPROFILE%\.krutaka\logs\` for the account running the service.

For a production Windows Service, the `%USERPROFILE%` path resolves to the service account's profile (e.g., `C:\Windows\System32\config\systemprofile\.krutaka\logs\` for `LocalSystem`). To use a predictable path, configure the log path explicitly in `appsettings.json`:

```json
{
  "Serilog": {
    "WriteTo": [
      {
        "Name": "File",
        "Args": {
          "path": "C:\\Services\\Krutaka\\logs\\krutaka-.log",
          "rollingInterval": "Day",
          "retainedFileCountLimit": 30,
          "fileSizeLimitBytes": 104857600,
          "rollOnFileSizeLimit": true,
          "outputTemplate": "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Message:lj}{NewLine}{Exception}"
        }
      }
    ]
  }
}
```

### Log Retention Policy

| Setting | Recommended Value | Effect |
|---|---|---|
| `rollingInterval` | `"Day"` | New log file each day |
| `retainedFileCountLimit` | `30` | Keep last 30 days of logs |
| `fileSizeLimitBytes` | `104857600` (100 MB) | Roll when file reaches 100 MB |
| `rollOnFileSizeLimit` | `true` | Create new file when size limit hit |

### Monitoring Log Files

```powershell
# View the current day's log
Get-Content "C:\Services\Krutaka\logs\krutaka-$(Get-Date -Format yyyyMMdd).log" -Tail 50

# Follow logs in real-time (PowerShell equivalent of `tail -f`)
Get-Content "C:\Services\Krutaka\logs\krutaka-$(Get-Date -Format yyyyMMdd).log" -Wait -Tail 20

# Search logs for errors
Select-String -Path "C:\Services\Krutaka\logs\*.log" -Pattern "\[ERR\]|\[WRN\]"
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
   Get-Content "C:\Services\Krutaka\logs\krutaka-$(Get-Date -Format yyyyMMdd).log" -Tail 20
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
- [ ] `KRUTAKA_ANTHROPIC_API_KEY` is set as an environment variable (not in config)
- [ ] `KRUTAKA_TELEGRAM_BOT_TOKEN` is set as an environment variable (not in config)
- [ ] `Telegram.AllowedUsers` is configured with explicit user IDs (not empty)
- [ ] `Telegram.RequireConfirmationForElevated` is `true`
- [ ] `Agent.WorkingDirectory` points to a specific project directory (not `.`)
- [ ] Log files are written to a known, accessible path
- [ ] `retainedFileCountLimit` is set to limit disk usage
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
