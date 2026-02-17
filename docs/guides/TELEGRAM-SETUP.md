# Krutaka — Telegram Bot Setup Guide

> **Last updated:** 2026-02-17 (v0.4.0 Telegram Integration)

This guide walks you through setting up Krutaka's Telegram bot interface for remote access to your AI agent.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1: Create a Telegram Bot](#step-1-create-a-telegram-bot)
- [Step 2: Store the Bot Token Securely](#step-2-store-the-bot-token-securely)
- [Step 3: Get Your Telegram User ID](#step-3-get-your-telegram-user-id)
- [Step 4: Configure Telegram Settings](#step-4-configure-telegram-settings)
- [Step 5: Set Operating Mode](#step-5-set-operating-mode)
- [Step 6: First Run and Verification](#step-6-first-run-and-verification)
- [Troubleshooting](#troubleshooting)
- [Security Best Practices](#security-best-practices)

---

## Prerequisites

Before setting up the Telegram bot, ensure you have:

- ✅ Krutaka v0.4.0+ installed and working locally
- ✅ A Telegram account
- ✅ The Telegram app (mobile or desktop)
- ✅ Completed the basic [Local Setup Guide](LOCAL-SETUP.md)

---

## Step 1: Create a Telegram Bot

1. **Open Telegram** and search for [@BotFather](https://t.me/BotFather) (the official bot for creating bots)
2. **Start a chat** with BotFather and send `/newbot`
3. **Choose a name** for your bot (e.g., "My Krutaka Agent")
   - This is the display name shown in chats
4. **Choose a username** for your bot (must end with "bot", e.g., "mykrutaka_agent_bot")
   - This username must be globally unique on Telegram
5. **Copy the bot token** — BotFather will provide a token like:
   ```
   1234567890:ABCdefGHIjklMNOpqrsTUVwxyz123456789
   ```
   - ⚠️ **CRITICAL:** Never share this token publicly or commit it to source control

---

## Step 2: Store the Bot Token Securely

Krutaka **never** stores bot tokens in configuration files. You must use one of these secure methods:

### Option A: Windows Credential Manager (Recommended)

This is the most secure option using Windows DPAPI encryption.

1. **Open PowerShell** as your regular user (no admin needed)
2. **Run the following command** (replace `YOUR_BOT_TOKEN` with the token from BotFather):

   ```powershell
   # Install Meziantou.Framework.Win32.CredentialManager if not already installed
   dotnet tool install --global Meziantou.Framework.Win32.CredentialManager

   # Store the token (replace YOUR_BOT_TOKEN with actual token)
   cmdkey /generic:krutaka_telegram_bot_token /user:krutaka /pass:YOUR_BOT_TOKEN
   ```

3. **Verify** the credential was stored:
   ```powershell
   cmdkey /list | findstr krutaka
   ```
   You should see: `Target: krutaka_telegram_bot_token`

### Option B: Environment Variable

If you cannot use Credential Manager (e.g., in CI/CD), use an environment variable:

1. **Set the environment variable** (replace `YOUR_BOT_TOKEN`):

   **PowerShell:**
   ```powershell
   [System.Environment]::SetEnvironmentVariable('KRUTAKA_TELEGRAM_BOT_TOKEN', 'YOUR_BOT_TOKEN', 'User')
   ```

   **Command Prompt:**
   ```cmd
   setx KRUTAKA_TELEGRAM_BOT_TOKEN "YOUR_BOT_TOKEN"
   ```

2. **Restart your terminal** for the environment variable to take effect

3. **Verify** it was set:
   ```powershell
   $env:KRUTAKA_TELEGRAM_BOT_TOKEN
   ```

⚠️ **Security Note:** Credential Manager is more secure because it uses DPAPI encryption. Environment variables are visible to any process running under your user account.

---

## Step 3: Get Your Telegram User ID

Your Telegram User ID is a numeric identifier (not your @username). You need this to configure the bot's allowlist.

1. **Open Telegram** and search for [@userinfobot](https://t.me/userinfobot)
2. **Start a chat** with userinfobot and send any message
3. **Copy your User ID** from the response (it will be a number like `123456789`)
   - This is your unique Telegram user ID, not your username

---

## Step 4: Configure Telegram Settings

Edit `src/Krutaka.Console/appsettings.json` and add a `Telegram` section:

```json
{
  "Mode": "Console",
  "Logging": { ... },
  "Claude": { ... },
  "Agent": { ... },
  "ToolOptions": { ... },
  
  "Telegram": {
    "AllowedUsers": [
      {
        "UserId": 123456789,
        "Role": "Admin",
        "ProjectPath": "C:\\Users\\YourName\\Projects\\MyProject"
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

### Configuration Fields

| Field | Description | Default | Required |
|---|---|---|---|
| `AllowedUsers` | Array of authorized Telegram users | — | ✅ **YES** |
| `UserId` | Telegram user ID (numeric) | — | ✅ **YES** |
| `Role` | User role: `"User"` or `"Admin"` | `"User"` | No |
| `ProjectPath` | Per-user project directory | Global default | No |
| `RequireConfirmationForElevated` | Require approval for elevated commands | `true` | No |
| `MaxCommandsPerMinute` | Per-user rate limit | `10` | No |
| `MaxTokensPerHour` | Per-user token budget | `100000` | No |
| `MaxFailedAuthAttempts` | Lockout threshold | `3` | No |
| `LockoutDuration` | Lockout duration (HH:MM:SS) | `"01:00:00"` | No |
| `PanicCommand` | Emergency shutdown command | `"/killswitch"` | No |
| `MaxInputMessageLength` | Max message length (chars) | `4000` | No |
| `Mode` | `"LongPolling"` or `"Webhook"` | `"LongPolling"` | No |
| `PollingTimeoutSeconds` | Polling timeout | `30` | No |

### Role Permissions

- **User** — Can use the bot, execute commands with approval, access their own sessions
- **Admin** — All User permissions + receives health notifications, can use `/killswitch`

⚠️ **CRITICAL:** The `AllowedUsers` array **cannot be empty**. If no users are configured, the bot **will refuse to start**. This is a security feature.

---

## Step 5: Set Operating Mode

Krutaka supports three operating modes:

### Mode 1: Console Only (Default)

For local-only use with no Telegram access. This is the existing v0.1.0–v0.3.0 behavior.

```json
{
  "Mode": "Console"
}
```

- Telegram services are **not loaded**
- Telegram configuration is **not required**
- Single-session console UI only

### Mode 2: Telegram Only (Headless)

For server deployment with only Telegram access (no local console UI).

```json
{
  "Mode": "Telegram"
}
```

- Console UI is **not loaded**
- Telegram configuration is **required** (validated at startup)
- Runs as background service until Ctrl+C or `/killswitch`
- Supports multiple concurrent sessions (10 by default)

### Mode 3: Both (Concurrent)

For developers who want both local console and Telegram access simultaneously.

```json
{
  "Mode": "Both"
}
```

- Both Console UI and Telegram bot run concurrently
- Shared session manager — Console and Telegram sessions coexist
- Telegram configuration is **required**
- Console `/exit` shuts down both interfaces

### CLI Override

You can override the config mode with a command-line argument:

```bash
# Run in Telegram mode (ignores config)
dotnet run --project src/Krutaka.Console -- --mode telegram

# Run in Both mode
dotnet run --project src/Krutaka.Console -- --mode both

# Run in Console mode (default)
dotnet run --project src/Krutaka.Console -- --mode console
```

---

## Step 6: First Run and Verification

1. **Start Krutaka** in Telegram or Both mode:
   ```bash
   dotnet run --project src/Krutaka.Console -- --mode telegram
   ```

2. **Check the startup logs** for:
   ```
   [INFO] Starting Krutaka in Telegram mode
   [INFO] Telegram bot initialized successfully
   [INFO] Listening for updates via long polling...
   ```

3. **Open Telegram** and find your bot by its @username (e.g., `@mykrutaka_agent_bot`)

4. **Start a chat** with your bot and send `/start`

5. **You should receive a welcome message** from the bot with available commands

6. **Try a simple command** to verify it's working:
   ```
   /help
   ```

7. **Test the AI agent** by sending a message:
   ```
   List the files in the current directory
   ```

### Verification Checklist

- [ ] Bot responds to `/start` with a welcome message
- [ ] Bot responds to `/help` with command list
- [ ] Bot accepts and processes AI prompts
- [ ] Approval prompts work (if enabled for the command)
- [ ] `/killswitch` stops the bot (Admin only)

---

## Troubleshooting

### Error: "AllowedUsers cannot be null or empty"

**Cause:** The `Telegram.AllowedUsers` array is missing or empty in `appsettings.json`.

**Fix:** Add at least one user to the `AllowedUsers` array with your Telegram User ID:

```json
"Telegram": {
  "AllowedUsers": [
    { "UserId": 123456789, "Role": "Admin" }
  ]
}
```

---

### Error: "Bot token not found"

**Cause:** The bot token is not available in Credential Manager or environment variables.

**Fix:** Follow [Step 2](#step-2-store-the-bot-token-securely) to store the token securely.

---

### Error: "Telegram configuration section is missing"

**Cause:** Running in Telegram or Both mode without a `Telegram` section in `appsettings.json`.

**Fix:** Add the `Telegram` configuration section as shown in [Step 4](#step-4-configure-telegram-settings).

---

### Bot doesn't respond to messages

**Possible causes:**

1. **Your User ID is not in AllowedUsers**
   - Unknown users are **silently dropped** (no error message)
   - Verify your User ID with [@userinfobot](https://t.me/userinfobot)
   - Add your User ID to `AllowedUsers` in config

2. **Bot token is invalid**
   - Verify the token was copied correctly from BotFather
   - Regenerate the token with `/revoke` in BotFather if needed

3. **Rate limit exceeded**
   - Default: 10 commands/minute per user
   - Wait a minute or increase `MaxCommandsPerMinute` in config

4. **User is locked out**
   - Default: 3 failed auth attempts = 1-hour lockout
   - Wait for lockout to expire or restart the bot

---

### Polling conflict error

**Error:** "Cannot acquire polling lock file"

**Cause:** Another instance of Krutaka is already running with Telegram polling enabled.

**Fix:** Only one process can poll Telegram at a time. Either:
- Stop the existing instance
- Use Webhook mode instead (requires public HTTPS endpoint)

---

### Commands not working in group chats

**Note:** Group chat support depends on the session bridge configuration. By default:
- **Direct messages (DM)** → User-scoped sessions (isolated per user)
- **Group chats** → Chat-scoped sessions (shared by all group members in AllowedUsers)

If group chats don't work, ensure:
1. The bot is added to the group
2. All group members using the bot are in `AllowedUsers`
3. The bot has "Read Messages" permission in the group

---

## Security Best Practices

### ✅ Do's

- ✅ **Store bot token in Credential Manager** — Most secure option using DPAPI encryption
- ✅ **Use explicit AllowedUsers list** — Never allow all users
- ✅ **Set Admin role sparingly** — Only trusted users should be Admins
- ✅ **Enable `RequireConfirmationForElevated`** — Prevents accidental destructive commands
- ✅ **Keep `MaxCommandsPerMinute` reasonable** — Prevents API exhaustion
- ✅ **Regenerate bot token if leaked** — Use `/revoke` in BotFather
- ✅ **Monitor audit logs** — Review `~/.krutaka/logs/` for suspicious activity

### ❌ Don'ts

- ❌ **Never commit bot token to Git** — Use `.gitignore` for `appsettings.json` if it contains secrets
- ❌ **Never share bot token publicly** — Treat it like a password
- ❌ **Never disable AllowedUsers validation** — Empty array = bot refuses to start (by design)
- ❌ **Never trust Telegram usernames** — Use numeric User IDs for authentication
- ❌ **Never skip approval for destructive commands** — Keep `RequireConfirmationForElevated: true`
- ❌ **Never expose bot to public groups** — Only use with trusted users/groups

---

## Advanced Configuration

### Using Webhook Mode (Production)

For production deployments, Webhook mode is more reliable than Long Polling:

1. **Set up a public HTTPS endpoint** (e.g., via ngrok, Azure, AWS)
2. **Update `appsettings.json`:**
   ```json
   "Telegram": {
     "Mode": "Webhook",
     "WebhookUrl": "https://yourdomain.com/api/telegram/webhook",
     ...
   }
   ```
3. **Configure your web server** to forward webhook requests to Krutaka
4. **Restart Krutaka** — it will register the webhook with Telegram

⚠️ **Webhook requires HTTPS** — Telegram will not send updates to HTTP endpoints.

---

### Per-User Project Paths

You can configure different project directories for different users:

```json
"AllowedUsers": [
  {
    "UserId": 111111111,
    "Role": "Admin",
    "ProjectPath": "C:\\Projects\\MainProject"
  },
  {
    "UserId": 222222222,
    "Role": "User",
    "ProjectPath": "C:\\Projects\\UserSpecificProject"
  }
]
```

---

### Multi-User Session Limits

Control how many concurrent sessions the bot can handle:

In `appsettings.json`, set `MaxActiveSessions` (applies to Telegram and Both modes):

```json
"SessionManager": {
  "MaxActiveSessions": 20,
  "IdleTimeoutMinutes": 30,
  "SuspendedSessionTtlMinutes": 1440
}
```

- `MaxActiveSessions` — Maximum concurrent sessions (default: 10)
- `IdleTimeoutMinutes` — Auto-suspend idle sessions (default: 30)
- `SuspendedSessionTtlMinutes` — Auto-cleanup suspended sessions (default: 1440 = 24 hours)

---

## Related Documentation

- [Local Setup Guide](LOCAL-SETUP.md) — Prerequisites and build instructions
- [Architecture Overview](../architecture/OVERVIEW.md) — Component structure
- [Telegram Security Architecture](../architecture/TELEGRAM.md) — Threat model and security controls
- [Multi-Session Architecture](../architecture/MULTI-SESSION.md) — Session isolation design

---

## Support

If you encounter issues not covered in this guide:

1. **Check the logs** at `~/.krutaka/logs/`
2. **Review the audit log** for authentication failures or rate limit hits
3. **Open a GitHub issue** with:
   - Your operating mode (Console/Telegram/Both)
   - Relevant log snippets (with tokens redacted)
   - Steps to reproduce

---

**Happy chatting with your AI agent! 🤖💬**
