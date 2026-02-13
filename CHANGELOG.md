# Changelog

All notable changes to Krutaka will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **4 new tests** for previously deferred test coverage from PR #94:
  - `RunAsync_Should_ThrowTimeoutException_WhenApprovalTimeoutExceeded` - Validates approval timeout mechanism
  - `Constructor_Should_ThrowArgumentOutOfRangeException_WhenApprovalTimeoutNegative` - Validates parameter validation
  - `RunAsync_Should_AllowInfiniteApprovalTimeout_WhenSetToZero` - Confirms zero timeout = infinite wait
  - `Should_ThrowIOException_WhenSymlinkDepthExceedsMaximum` - Tests 32-level symlink depth limit with graceful permission skip

## [0.2.0] - 2026-02-13

### Added
- **Dynamic directory scoping**: Agent can now request access to multiple directories at runtime instead of being locked to a single `WorkingDirectory` at startup
- **Layered access policy engine** (`IAccessPolicyEngine`, `LayeredAccessPolicyEngine`): Four-layer evaluation for directory access requests
  - Layer 1: Hard deny-list (system directories, UNC paths, paths above ceiling)
  - Layer 2: Configurable auto-grant patterns (glob patterns in `appsettings.json`)
  - Layer 3: Session-scoped grants (previously approved by user)
  - Layer 4: Heuristic checks with interactive user prompts
- **Session-scoped access grants** (`ISessionAccessStore`, `InMemorySessionAccessStore`): Time-to-live (TTL) based directory access grants with automatic pruning
- **Glob auto-grant patterns** (`GlobPatternValidator`): Configure trusted directory patterns in `appsettings.json` for auto-approval (e.g., `C:\Users\name\Projects\**`)
- **Symlink and junction resolution** (`PathResolver`): Segment-by-segment symlink resolution to prevent symlink escape attacks
- **Alternate Data Streams (ADS) blocking**: Paths containing `:` after drive letter are rejected to prevent ADS-based attacks
- **Device name blocking**: Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`) blocked in all path segments
- **Device path prefix blocking**: `\\.\` and `\\?\` prefixes are blocked
- **Interactive directory approval UI**: `DirectoryAccessRequested` event with user prompts for directory access decisions
- **Ceiling directory enforcement**: `ToolOptions.CeilingDirectory` configuration to set maximum ancestor directory (default: `%USERPROFILE%`)
- **87 new adversarial security tests** across 3 test suites:
  - `AccessPolicyEngineAdversarialTests` (21 test methods): System directory bypass, ceiling enforcement, path manipulation, session scope accumulation, cross-volume detection
  - `PathResolverAdversarialTests` (18 test methods): ADS attacks, device name blocking, device path prefixes, deeply nested paths
  - `GlobPatternAdversarialTests` (21 test methods): Overly broad patterns, relative traversal, blocked directories

### Changed
- **All 6 file/command tools refactored**: `ReadFileTool`, `WriteFileTool`, `EditFileTool`, `ListFilesTool`, `SearchFilesTool`, `RunCommandTool` now use `IAccessPolicyEngine` for directory access validation instead of static `_projectRoot` field
- **Configuration property renamed**: `ToolOptions.WorkingDirectory` → `ToolOptions.DefaultWorkingDirectory` (still defaults to `.` if not specified)
- **New configuration properties**: `CeilingDirectory`, `AutoGrantPatterns`, `MaxConcurrentGrants`, `DefaultGrantTtlMinutes`
- **Enhanced path validation**: `SafeFileOperations.ValidatePath()` now calls `PathResolver.ResolveToFinalTarget()` before containment checks to resolve all symlinks, junctions, and reparse points

### Security
- **Path hardening**: Segment-by-segment symlink resolution closes v0.1.0 gap where symlinks could escape project root
- **TOCTOU mitigation**: Path resolution happens both at policy evaluation and at file access time
- **Circular symlink detection**: Prevents infinite loops and DoS from symlink cycles
- **Glob pattern abuse prevention**: Patterns must have ≥ 3 path segments, cannot contain blocked directories, must be under ceiling directory
- **Session scope accumulation defense**: Max concurrent grants (default 10), automatic TTL expiry, ceiling enforcement, strict access level checks
- **Comprehensive adversarial test coverage**: 87 new tests simulating attack scenarios (symlink escapes, ADS manipulation, device name exploits, pattern abuse, ceiling violations)

### Fixed
- Symlink escape vulnerability: Symlinks within project directory pointing to blocked locations (e.g., `C:\Windows\System32`) are now correctly blocked after resolution

## [0.1.1] - 2026-02-12

### Added
- **Smart session management**: Auto-resume most recent session on startup
- **Session discovery**: `SessionStore.FindMostRecentSession()` and `SessionStore.ListSessions()` for finding and listing past sessions
- **New commands**: 
  - `/sessions` — List recent sessions for the current project (last 10)
  - `/new` — Start a fresh session with cleared conversation history
- **11 new tests** for session discovery (10) and conversation clearing (1)

### Changed
- **Startup behavior**: Application automatically resumes the most recent session instead of requiring manual `/resume` command
- **Session store API**: Added static methods `FindMostRecentSession` and `ListSessions` to `SessionStore` for discovery

### Fixed
- Data loss between app restarts: Sessions are now automatically resumed on startup
- Broken `/resume` command: Fixed and integrated with auto-resume behavior

## [0.1.0] - 2026-02-11

### Added
- **Initial release**: Complete core features with 576 tests passing
- **Console application**: No network listener (eliminates CVE-2026-25253 attack class)
- **Claude API integration**: Streaming support with official `Anthropic` NuGet package v12.4.0
- **Tool system**: 6 tools (read_file, write_file, edit_file, list_files, search_files, run_command, memory_store, memory_search)
- **Security controls**:
  - Windows Credential Manager integration for API key storage (DPAPI encryption)
  - Command allowlist/blocklist with metacharacter detection
  - Path validation with project root sandboxing
  - Process sandboxing with Windows Job Objects (256MB memory, 30s CPU limits)
  - Human-in-the-loop approval for write/execute operations
  - Environment variable scrubbing (removes API keys from child processes)
  - Log redaction filter for API keys and secrets
  - Prompt injection defense (untrusted content wrapped in XML tags)
- **Memory system**:
  - SQLite FTS5 keyword search
  - JSONL session persistence
  - Token counting and context compaction
  - MEMORY.md management
- **UI**: Spectre.Console streaming interface with rich panels, spinners, and prompts
- **Skills system**: Markdown skill loader with YAML frontmatter
- **Audit logging**: Structured JSON logs with correlation IDs (Serilog)
- **125 security policy tests**: Command validation (40), path validation (40), environment scrubbing (20), attack simulations (25+)
- **CI/CD**: GitHub Actions pipeline with build and security test workflows
- **Self-contained publishing**: Single-file executable with `dotnet publish`

### Security
- **Threat model**: Addresses OpenClaw CVEs (CVE-2026-25253, CVE-2026-25157, CVE-2026-24763)
- **Defense-in-depth**: 9 security controls with comprehensive test coverage

---

[Unreleased]: https://github.com/chethandvg/krutaka/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/chethandvg/krutaka/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/chethandvg/krutaka/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/chethandvg/krutaka/releases/tag/v0.1.0
