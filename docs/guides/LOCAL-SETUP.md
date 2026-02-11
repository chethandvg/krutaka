# Krutaka — Local Development Setup

> **Last updated:** 2026-02-11 (Issue #25 — GitHub Actions CI pipeline)

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

```bash
# Self-contained single-file Windows executable
dotnet publish src/Krutaka.Console \
  -c Release \
  -r win-x64 \
  --self-contained \
  -p:PublishSingleFile=true \
  -p:IncludeNativeLibrariesForSelfExtract=true

# Output location:
# src/Krutaka.Console/bin/Release/net10.0-windows/win-x64/publish/Krutaka.Console.exe
```

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

## CI/CD Pipeline

Krutaka uses GitHub Actions for continuous integration and deployment:

### Build Workflow (`.github/workflows/build.yml`)

Runs on every push to `main` and on all pull requests:
- **Setup**: .NET 10 SDK on Windows runner
- **Restore**: NuGet package dependencies
- **Build**: Release configuration with warnings as errors
- **Test**: All test projects (201 tests)
- **Publish**: Self-contained win-x64 executable
- **Artifacts**: Build artifact downloadable for 90 days

**View workflow runs**: [Actions → Build and Test](https://github.com/chethandvg/krutaka/actions/workflows/build.yml)

### Security Tests Workflow (`.github/workflows/security-tests.yml`)

Runs on every pull request and push to `main`:
- **Security Policy Tests**: 125 tests covering command validation, path traversal prevention, environment scrubbing
- **Fails the build** if any security test fails
- **Test Results**: Uploaded as artifacts for 30 days

**View workflow runs**: [Actions → Security Tests](https://github.com/chethandvg/krutaka/actions/workflows/security-tests.yml)

### Downloading Build Artifacts

1. Go to [Actions](https://github.com/chethandvg/krutaka/actions)
2. Select a successful workflow run
3. Scroll down to **Artifacts**
4. Download `krutaka-win-x64` (contains `Krutaka.Console.exe`)

### Running CI Locally

To test the build process locally:

```bash
# Build in Release mode (matches CI)
dotnet build --configuration Release /p:TreatWarningsAsErrors=true

# Run all tests (matches CI)
dotnet test --configuration Release --verbosity normal

# Run security tests only
dotnet test tests/Krutaka.Tools.Tests \
  --filter "FullyQualifiedName~SecurityPolicyTests" \
  --verbosity normal

# Publish single-file executable (matches CI)
dotnet publish src/Krutaka.Console \
  --configuration Release \
  --runtime win-x64 \
  --self-contained \
  -p:PublishSingleFile=true \
  -p:IncludeNativeLibrariesForSelfExtract=true \
  --output ./publish
```

## Next Steps

1. **Implement core interfaces**: See `docs/status/PROGRESS.md` for Issue #6
2. **Read architecture docs**: `docs/architecture/OVERVIEW.md` and `docs/architecture/SECURITY.md`
3. **Review coding standards**: See `.editorconfig` and `AGENTS.md`