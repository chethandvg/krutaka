# End-to-End Testing for Krutaka

This directory contains the end-to-end integration test infrastructure for Krutaka.

## Contents

- **`sandbox/`** — Test sandbox environment with sample files
  - `src/` — Sample C# project files
  - `docs/` — Sample documentation files
  - `data/` — Sample data files (JSON, CSV)
- **`TEST-SCENARIOS.md`** — Comprehensive manual test scenarios
- **`run-manual-tests.md`** — Quick reference for running manual tests

## Quick Start

1. **Build Krutaka:**
   ```bash
   cd /home/runner/work/krutaka/krutaka
   dotnet build
   ```

2. **Configure API Key:**
   ```bash
   # Run the console app to trigger setup wizard
   ./src/Krutaka.Console/bin/Debug/net10.0-windows/win-x64/Krutaka.Console.exe
   ```

3. **Run Manual Tests:**
   ```bash
   cd tests/e2e/sandbox
   ../../../src/Krutaka.Console/bin/Debug/net10.0-windows/win-x64/Krutaka.Console.exe
   ```

4. **Follow Test Scenarios:**
   See `TEST-SCENARIOS.md` for detailed test procedures.

## Test Categories

1. **Read-Only Operations** — Auto-approved operations (list, read, search)
2. **Write Operations** — Require approval (create, edit files)
3. **Command Execution** — Always require approval (run_command)
4. **Security Boundary Tests** — Verify blocking of dangerous operations
5. **Session Persistence** — Verify conversation state across restarts
6. **Context Compaction** — Verify token management and compaction
7. **Memory System** — Verify memory storage and retrieval

## Security Tests (Critical)

All security boundary tests MUST pass before release:
- Path traversal blocked
- Sensitive file patterns blocked (`.env`, `.secret`, etc.)
- UNC paths blocked
- Blocked executables rejected (`powershell`, `certutil`, etc.)
- Command injection prevented (shell metacharacters)

See `TEST-SCENARIOS.md` for complete test procedures.

## Automated CI Tests

Note: These are **manual** integration tests designed for local verification.
The CI pipeline runs unit and integration tests automatically via:
```bash
dotnet test
```

For E2E tests, manual execution is required due to:
- Human-in-the-loop approval prompts
- Interactive console UI
- Windows Credential Manager dependency
