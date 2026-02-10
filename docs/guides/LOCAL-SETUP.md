# Krutaka — Local Development Setup

> **Last updated:** 2026-02-10 (Issue #7 — API key setup wizard added)

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

On first launch, Krutaka will run an interactive setup wizard to configure your Anthropic API key:

```bash
dotnet run --project src/Krutaka.Console
```

The wizard will:
1. Check if an API key is already stored in Windows Credential Manager
2. Prompt you to enter your Anthropic API key (masked input with `*`)
3. Validate that the key starts with `sk-ant-` (Anthropic's key format)
4. Store the key securely using DPAPI (Data Protection API) in Windows Credential Manager

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
# Run the setup wizard again
dotnet run --project src/Krutaka.Console -- --setup
# or manually delete from Windows Credential Manager and restart
```

**To verify your stored credential:**
- Open Windows Credential Manager (`Control Panel > User Accounts > Credential Manager`)
- Look for "Windows Credentials" → "Generic Credentials"
- Find entry: `Krutaka_ApiKey`

### Running After Setup

After the initial setup, the application will automatically load the API key from Credential Manager:

```bash
# Run from source (after setup)
dotnet run --project src/Krutaka.Console

# Run with specific configuration
dotnet run --project src/Krutaka.Console -c Release
```

If the API key is not found, the app will display a clear error:
```
API key not found in Windows Credential Manager.
Please run the setup wizard to configure your Anthropic API key.
Expected credential name: 'Krutaka_ApiKey'
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

## Next Steps

1. **Implement core interfaces**: See `docs/status/PROGRESS.md` for Issue #6
2. **Read architecture docs**: `docs/architecture/OVERVIEW.md` and `docs/architecture/SECURITY.md`
3. **Review coding standards**: See `.editorconfig` and `AGENTS.md`