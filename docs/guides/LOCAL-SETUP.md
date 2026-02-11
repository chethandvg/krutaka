# Krutaka — Local Development Setup

> **Last updated:** 2026-02-11 (Issue #25 — GitHub Actions CI pipeline)

## CI Status

[![Build and Test](https://github.com/chethandvg/krutaka/actions/workflows/build.yml/badge.svg)](https://github.com/chethandvg/krutaka/actions/workflows/build.yml)
[![Security Tests](https://github.com/chethandvg/krutaka/actions/workflows/security-tests.yml/badge.svg)](https://github.com/chethandvg/krutaka/actions/workflows/security-tests.yml)

## Prerequisites

| Requirement | Version | Download |
|---|---|---|
| Windows | 10 22H2+ or 11 (x64) | — |
| .NET SDK | 10.0.102+ (LTS) | [dotnet.microsoft.com](https://dotnet.microsoft.com/download/dotnet/10.0) |
| Git | 2.40+ | [git-scm.com](https://git-scm.com/) |
| Claude API Key | — | [console.anthropic.com](https://console.anthropic.com/) |

### Verify .NET SDK Installation

```bash
dotnet --version
# Should output: 10.0.102 or higher
```

### Optional

| Requirement | Purpose |
|---|---|
| Visual Studio 2026 | IDE with full .NET 10 support |
| VS Code + C# Dev Kit | Lightweight alternative |
| Windows Terminal | Better console rendering for Spectre.Console |

## Clone and Build

```bash
git clone https://github.com/chethandvg/krutaka.git
cd krutaka

# Restore NuGet packages
dotnet restore

# Build all projects
dotnet build

# Expected output: Build succeeded. 0 Warning(s) 0 Error(s)
```

## Solution Structure

```
krutaka/
├── Krutaka.slnx                     # XML-based solution file (.NET 10)
├── global.json                      # SDK version pinning (10.0.102)
├── Directory.Build.props            # Shared MSBuild properties
├── Directory.Packages.props         # Central package management
├── .editorconfig                    # C# coding conventions
├── src/
│   ├── Krutaka.Core/                # Interfaces and models (no dependencies)
│   ├── Krutaka.AI/                  # Claude API client (depends on Core)
│   ├── Krutaka.Tools/               # Tool implementations (depends on Core)
│   ├── Krutaka.Memory/              # Persistence layer (depends on Core)
│   ├── Krutaka.Skills/              # Skill system (depends on Core)
│   └── Krutaka.Console/             # Entry point (depends on all)
└── tests/
    ├── Krutaka.Core.Tests/
    ├── Krutaka.AI.Tests/
    ├── Krutaka.Tools.Tests/
    ├── Krutaka.Memory.Tests/
    └── Krutaka.Console.Tests/
```

## Build Commands

```bash
# Build solution
dotnet build

# Build specific project
dotnet build src/Krutaka.Console

# Build in Release mode
dotnet build -c Release

# Clean build artifacts
dotnet clean
```

## Run Tests

```bash
# All tests
dotnet test

# Specific test project
dotnet test tests/Krutaka.Tools.Tests

# With detailed output
dotnet test --logger "console;verbosity=detailed"

# Security tests only (when implemented)
dotnet test --filter "FullyQualifiedName~SecurityPolicy"
```

## Run the Application

### First-Run Setup Wizard

On first launch, Krutaka will automatically detect if an API key is missing and run an interactive setup wizard:

```bash
cd krutaka
dotnet run --project src/Krutaka.Console
```

The wizard will:
1. Check if an API key is already stored in Windows Credential Manager
2. Prompt you to enter your Anthropic API key (masked input with `*`)
3. Validate that the key starts with `sk-ant-` (Anthropic's key format)
4. Store the key securely using DPAPI (Data Protection API) in Windows Credential Manager
5. Start the application immediately after setup

**API Key Security:**
- ✅ Encrypted at rest using Windows DPAPI
- ✅ Never stored in files, environment variables, or appsettings.json
- ✅ Never logged (redacted by `LogRedactionEnricher`)
- ✅ Not visible in process listings or memory dumps
- ✅ Stored under credential name: `Krutaka_ApiKey` with `LocalMachine` persistence

**To get your API key:**
1. Go to [console.anthropic.com/settings/keys](https://console.anthropic.com/settings/keys)
2. Create a new API key (starts with `sk-ant-api03-...`)
3. Copy the key (you won't be able to see it again!)
4. Paste it into the Krutaka setup wizard

**To update or replace your API key:**
```bash
# Delete credential from Windows Credential Manager and restart
# Open Credential Manager: Control Panel > User Accounts > Credential Manager
# Under "Windows Credentials" > "Generic Credentials", delete "Krutaka_ApiKey"
# Then run the app again to trigger setup wizard
```

**To verify your stored credential:**
- Open Windows Credential Manager (`Control Panel > User Accounts > Credential Manager`)
- Look for "Windows Credentials" → "Generic Credentials"
- Find entry: `Krutaka_ApiKey`

### Running After Setup

After the initial setup, the application will automatically load the API key from Credential Manager:

```bash
# Run from source (after setup)
cd krutaka
dotnet run --project src/Krutaka.Console

# Run with specific configuration
dotnet run --project src/Krutaka.Console -c Release
```

### Application Usage

Once running, you can interact with the AI agent:

**Available Commands:**
- `/help` - Display available commands
- `/exit` or `/quit` - Exit the application
- `Ctrl+C` - Graceful shutdown

**Example Session:**
```
  _  __          _        _         
 | |/ /_ __ _   _| |_ __ _| | ____ _ 
 | ' /| '__| | | | __/ _` | |/ / _` |
 | . \| |  | |_| | || (_| |   < (_| |
 |_|\_\_|   \__,_|\__\__,_|_|\_\__,_|
                                      
Version 0.1.0
OpenClaw-inspired AI agent for Windows
Type /help for commands

> Tell me about this codebase

[Thinking...]
This is the Krutaka repository, a C#/.NET 10 console application...
⚙ Calling list_files...
✓ list_files complete
...
```

### Configuration

Application settings are configured in `src/Krutaka.Console/appsettings.json`:

```json
{
  "Claude": {
    "ModelId": "claude-4-sonnet-20250514",
    "MaxTokens": 8192,
    "Temperature": 0.7
  },
  "Agent": {
    "WorkingDirectory": "",
    "CommandTimeoutSeconds": 30,
    "ToolTimeoutSeconds": 30,
    "RequireApprovalForWrites": true
  }
}
```

**Configuration Notes:**
- `WorkingDirectory`: Defaults to current directory if empty
- `MaxTokens`: Maximum tokens for Claude response (default: 8192)
- `Temperature`: Claude temperature setting (0.0 = deterministic, 1.0 = creative, default: 0.7)
- `CommandTimeoutSeconds`: Reserved for future use. Shell commands currently use a hardcoded 30-second timeout in `run_command` regardless of this setting.
- `ToolTimeoutSeconds`: Timeout for tool execution (default: 30)
- `RequireApprovalForWrites`: Reserved for future use. Approval requirements are currently determined by the security policy and enforced in the agentic loop.

### Application Directories

Krutaka creates the following directories in your user profile:

```
%USERPROFILE%\.krutaka\
├── logs\                      # Application logs (daily rotation, 30-day retention)
│   └── krutaka-20260211.log
├── sessions\                  # Conversation session history (JSONL format)
│   └── {project-hash}\
│       └── {session-id}.jsonl
├── memory.db                  # SQLite database for hybrid memory search
└── MEMORY.md                  # Human-readable memory file
```

### Logs

Logs are stored in `~/.krutaka/logs/` with:
- Daily rotation (`krutaka-YYYYMMDD.log`)
- 30-day retention
- API key redaction (all `sk-ant-*` patterns replaced with `***REDACTED***`)

To view logs:
```bash
# View today's log
cat ~/.krutaka/logs/krutaka-$(date +%Y%m%d).log

# Follow logs in real-time (PowerShell)
Get-Content -Path "$env:USERPROFILE\.krutaka\logs\krutaka-$(Get-Date -Format yyyyMMdd).log" -Wait
```

## Publish Single-File Executable

The `Krutaka.Console.csproj` is pre-configured for self-contained single-file publishing with the following properties:
- `<RuntimeIdentifier>win-x64</RuntimeIdentifier>` - Windows x64 target
- `<PublishSingleFile>true</PublishSingleFile>` - Bundle into single .exe
- `<SelfContained>true</SelfContained>` - Include .NET runtime
- `<IncludeNativeLibrariesForSelfExtract>true</IncludeNativeLibrariesForSelfExtract>` - Include SQLite native libraries

### Publish Command

```bash
# Simple publish command (all settings in .csproj)
dotnet publish src/Krutaka.Console -c Release

# Output location:
# src/Krutaka.Console/bin/Release/net10.0-windows/win-x64/publish/Krutaka.Console.exe

# Custom output directory
dotnet publish src/Krutaka.Console -c Release --output ./publish
```

### Published File Size

The self-contained single-file executable is approximately **82 MB**, which includes:
- .NET 10 runtime (embedded)
- All application dependencies (official Anthropic package, Spectre.Console, Serilog, SQLite, etc.)
- Application code and assemblies
- Native libraries (SQLite, etc.)

### Running the Published Binary

```powershell
# Navigate to publish directory
cd src/Krutaka.Console/bin/Release/net10.0-windows/win-x64/publish

# Run the executable (Windows only)
.\Krutaka.Console.exe

# Or with custom output directory
cd publish
.\Krutaka.Console.exe
```

**Requirements for running the published binary:**
- Windows 10 22H2+ or Windows 11 (x64)
- No .NET SDK required (runtime is embedded)
- No other dependencies (self-contained)

**Files included in publish directory:**
- `Krutaka.Console.exe` - Main executable (82 MB)
- `appsettings.json` - Configuration file
- `prompts/AGENTS.md` - Agent instructions
- `*.pdb` files - Debug symbols (optional, can be deleted)

**First-run behavior:**
1. Executable will create `%USERPROFILE%\.krutaka\` directory structure
2. If no API key is stored, the setup wizard will run automatically
3. After setup, the application starts normally

## Code Style Enforcement

The project uses `.editorconfig` with strict rules:

- **Warnings as errors**: Build fails on any warning
- **Nullable reference types**: Enabled globally
- **File-scoped namespaces**: Required
- **Async suffix**: Required for all async methods
- **Private field prefix**: `_camelCase`

To format code automatically:

```bash
dotnet format
```

## CI/CD Pipeline

The project uses GitHub Actions for continuous integration:

### Build and Test Workflow (`build.yml`)

**Triggers:** Push to `main`, pull requests to `main`

**Jobs:**

1. **build** - Main build and test job
   - Setup .NET 10.0.102 (pinned version from global.json)
   - Restore dependencies with locked-mode (deterministic builds)
   - Build (Release mode, warnings as errors)
   - Run tests (excludes Quarantined category - see note below)
   - Publish self-contained win-x64 executable
   - Upload build artifact (90-day retention)

2. **quarantined-tests** - Runs failing tests separately (allowed to fail)
   - Runs tests marked with `[Trait("Category", "Quarantined")]`
   - Results are visible but don't fail the build
   - Helps track progress on fixing these tests

**Downloadable Artifacts:**
- Navigate to [Actions tab](https://github.com/chethandvg/krutaka/actions)
- Select a successful workflow run
- Download `krutaka-win-x64` artifact

### Security Tests Workflow (`security-tests.yml`)

**Triggers:** Push to `main`, pull requests to `main`

**Runs:** All security policy and security violation logging tests (133 tests)

**Configuration:**
- Uses .NET 10.0.102 (pinned version)
- Locked-mode restore for deterministic builds

**Note on Quarantined Tests:**

12 tests are marked as `[Trait("Category", "Quarantined")]` and run separately in a job that's allowed to fail:

**AgentOrchestratorTests (5 tests):**
- `RunAsync_Should_ProcessToolCalls_WhenClaudeRequestsTools`
- `RunAsync_Should_YieldHumanApprovalRequired_WhenToolRequiresApproval`
- `RunAsync_Should_ProcessMultipleToolCalls_InSingleResponse`
- `RunAsync_Should_SerializeTurnExecution`
- `RunAsync_Should_HandleToolExecutionFailure_WithoutCrashingLoop`

**AuditLoggerTests (7 tests):**
- `Should_TruncateLongUserInput`
- `Should_LogClaudeApiRequestEvent`
- `Should_LogClaudeApiResponseEvent`
- `Should_LogToolExecutionEvent_WithApproval`
- `Should_LogToolExecutionEvent_WithError`
- `Should_LogCompactionEvent`
- `Should_LogSecurityViolationEvent`

These tests validate critical functionality but are currently failing. They are preserved in the codebase and run in a separate CI job that's allowed to fail, keeping them visible until fixed.

## Troubleshooting

| Issue | Solution |
|---|---|
| `dotnet build` fails with SDK error | Verify .NET 10 SDK: `dotnet --list-sdks` should show 10.0.102 |
| `NU1603` package version warning | Check `Directory.Packages.props` for version mismatches |
| API key not found at runtime | Run setup wizard with `--setup` flag or delete credential and restart |
| API key invalid format | Key must start with `sk-ant-` — get a new key from console.anthropic.com |
| SQLite native library not found | Run `dotnet restore` to ensure `Microsoft.Data.Sqlite` is restored |
| Tests fail on non-Windows | Some tests require Windows APIs (Credential Manager, Job Objects) |
| `.slnx` file not supported | Use Visual Studio 2026 or `dotnet` CLI (VS 2025 may not support .slnx) |

## Next Steps

1. **Implement core interfaces**: See `docs/status/PROGRESS.md` for Issue #6
2. **Read architecture docs**: `docs/architecture/OVERVIEW.md` and `docs/architecture/SECURITY.md`
3. **Review coding standards**: See `.editorconfig` and `AGENTS.md`