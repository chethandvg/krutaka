# Contributing to Krutaka

Thank you for your interest in contributing to Krutaka! This document explains our branching model, development workflow, and coding standards.

## Branching Model

Krutaka uses a **modified Git Flow** branching model optimized for versioned milestones.

### Branch Types

| Branch | Purpose | PR Target |
|---|---|---|
| `main` | Stable releases only. Every merge is tagged. | — (receives merges from `release/*`) |
| `develop` | Integration branch for the next version. | — (receives merges from `feature/*`) |
| `feature/v{X.Y.Z}/{description}` | Individual work items for a milestone. | `develop` |
| `release/v{X.Y.Z}` | Release candidate stabilization. Bugfixes only. | `main` (and back-merge to `develop`) |
| `hotfix/v{X.Y.Z}/{description}` | Critical fixes to a released version. | `main` (and back-merge to `develop`) |

### Branch Naming Convention

```
feature/v0.2.0/access-policy-engine      ← Feature for v0.2.0 milestone
feature/v0.2.0/dynamic-scoping           ← Another feature for v0.2.0
feature/v0.4.0/telegram-scaffold         ← Can start future work early
release/v0.2.0                            ← Release candidate branch
hotfix/v0.2.1/fix-path-validation         ← Critical fix for v0.2.0
```

## Development Workflow

### For Contributors (Fork-based)

1. **Fork** the repository on GitHub
2. **Clone** your fork locally
3. Check the [milestones](https://github.com/chethandvg/krutaka/milestones) to find work
4. Create your branch:
   ```bash
   git checkout develop
   git pull upstream develop
   git checkout -b feature/v0.2.0/your-description
   ```
5. Make your changes following the coding standards below
6. Ensure all tests pass:
   ```bash
   dotnet test
   ```
7. Push to your fork and open a PR **targeting `develop`** (not `main`)
8. Reference the issue number in your PR description (e.g., "Closes #42")

### For Maintainers (Release process)

1. When all milestone features are merged to `develop`:
   ```bash
   git checkout develop
   git checkout -b release/v0.2.0
   git push origin release/v0.2.0
   ```
2. Only bugfixes go into the release branch — no new features
3. When stable:
   ```bash
   # Merge to main
   git checkout main
   git merge --no-ff release/v0.2.0
   git tag -a v0.2.0 -m "v0.2.0 — Dynamic Directory Scoping"
   git push origin main --tags

   # Back-merge to develop
   git checkout develop
   git merge --no-ff release/v0.2.0
   git push origin develop

   # Delete release branch
   git branch -d release/v0.2.0
   git push origin --delete release/v0.2.0
   ```
4. Create a GitHub Release from the tag with changelog and binaries

## Prerequisites

- Windows 10 22H2+ or Windows 11 (x64)
- [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0)
- Git

## Development Setup

```bash
git clone https://github.com/YOUR-USERNAME/krutaka.git
cd krutaka
git remote add upstream https://github.com/chethandvg/krutaka.git
dotnet build
dotnet test
```

## Coding Standards

- **Target:** .NET 10, C# 13 (`LangVersion latest`)
- **Nullable reference types:** Enabled globally
- **Warnings as errors:** All warnings must be resolved
- **Naming:** PascalCase for public, `_camelCase` for private fields
- **Async:** All I/O methods must be async with `CancellationToken`
- **Testing:** xUnit + FluentAssertions + NSubstitute
- **Format:** Run `dotnet format` before committing

See [AGENTS.md](AGENTS.md) and [.github/copilot-instructions.md](.github/copilot-instructions.md) for complete conventions.

## Security Rules (Mandatory)

All contributors **must** follow these rules. PRs violating them will be rejected:

1. **Never hardcode secrets** — Use Windows Credential Manager
2. **Always validate paths** through `IFileOperations.ValidatePath()`
3. **Always validate commands** through `CommandPolicy.ValidateCommand()`
4. **Use CliWrap** with explicit argument arrays (never string interpolation)
5. **Wrap untrusted content** in `<untrusted_content>` XML tags
6. **Run security tests** before submitting: `dotnet test --filter "FullyQualifiedName~SecurityPolicy"`

See [docs/architecture/SECURITY.md](docs/architecture/SECURITY.md) for the full threat model.

## Reporting Security Vulnerabilities

**DO NOT** open a public issue for security vulnerabilities.

1. Email the maintainer directly (see GitHub profile)
2. Provide detailed description and reproduction steps
3. Wait for acknowledgment before any public disclosure

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Assume good intent
