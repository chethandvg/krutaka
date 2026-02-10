# Krutaka — Local Development Setup

> **Last updated:** 2026-02-10 (Pre-implementation)

## Prerequisites

| Requirement | Version | Download |
|---|---|---|
| Windows | 10 22H2+ or 11 (x64) | — |
| .NET SDK | 10.0.x (LTS) | [dotnet.microsoft.com](https://dotnet.microsoft.com/download/dotnet/10.0) |
| Git | 2.40+ | [git-scm.com](https://git-scm.com/) |
| Claude API Key | — | [console.anthropic.com](https://console.anthropic.com/) |

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
dotnet build
```

## Run Tests

```bash
# All tests
dotnet test

# Specific test project
dotnet test tests/Krutaka.Tools.Tests

# Security tests only
dotnet test tests/Krutaka.Tools.Tests --filter "FullyQualifiedName~SecurityPolicy"
```

## First Run

```bash
dotnet run --project src/Krutaka.Console
```

On first run, the setup wizard will prompt for your Claude API key. The key is stored in Windows Credential Manager (DPAPI-encrypted) — not in any file.

## Publish

```bash
dotnet publish src/Krutaka.Console -c Release -r win-x64 --self-contained -p:PublishSingleFile=true
```

Output: `src/Krutaka.Console/bin/Release/net10.0-windows/win-x64/publish/Krutaka.Console.exe`

## Project Structure

See [Architecture Overview](../architecture/OVERVIEW.md) for the full component map.

## Troubleshooting

| Issue | Solution |
|---|---|
| `dotnet build` fails with SDK error | Verify .NET 10 SDK is installed: `dotnet --list-sdks` |
| API key not found at runtime | Re-run setup: the app will prompt again if no credential is found |
| SQLite native library not found | Ensure `Microsoft.Data.Sqlite` package is restored correctly |
| Tests fail on non-Windows | Some tests require Windows APIs (Credential Manager, Job Objects) — run on Windows |