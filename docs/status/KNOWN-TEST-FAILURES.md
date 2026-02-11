# Known Test Failures - CI/CD Implementation

## Status
As of 2026-02-11, there are 5 pre-existing test failures in the Krutaka.Core.Tests project that are **not related to the CI/CD implementation**.

## Failed Tests
All failures are in `tests/Krutaka.Core.Tests/AgentOrchestratorTests.cs`:

1. `RunAsync_Should_YieldHumanApprovalRequired_WhenToolRequiresApproval` (line 195)
2. `RunAsync_Should_ProcessToolCalls_WhenClaudeRequestsTools` (line 159)
3. `RunAsync_Should_ProcessMultipleToolCalls_InSingleResponse` (line 282)
4. `RunAsync_Should_SerializeTurnExecution` (line 337)
5. `RunAsync_Should_HandleToolExecutionFailure_WithoutCrashingLoop` (line 227)

## Root Cause
These are integration tests for the agent orchestrator that involve mocking the Claude API client. The failures appear to be related to async event streaming or mock setup issues, not to the logging changes made in issue #25.

## Evidence
- These tests were failing in the initial test run before any CI/CD changes
- The AuditLogger tests that were related to the logging implementation were fixed
- All other test projects (AI, Console, Memory, Skills, Tools) pass completely

## Test Summary
```
Total: 558 tests
Passed: 553 tests (99.1%)
Failed: 5 tests (0.9%) - pre-existing
Skipped: 1 test (RunCommandToolTests.Should_TimeoutLongRunningCommand)
```

## Recommendation for CI
There are three options for handling these failures in CI:

### Option 1: Exclude Failing Tests (Quick Fix)
Modify `.github/workflows/build.yml` to exclude these specific tests:
```yaml
- name: Run tests
  run: |
    dotnet test --no-build --configuration Release `
      --filter "FullyQualifiedName!~AgentOrchestratorTests" `
      --verbosity normal
```

**Pros**: CI passes immediately, unblocks merge
**Cons**: Reduces test coverage, masks issues

### Option 2: Move to Separate Test Project (Recommended)
1. Create `tests/Krutaka.Core.Integration.Tests` for integration tests
2. Move `AgentOrchestratorTests.cs` there
3. Exclude integration tests from main CI, run in separate workflow
4. Fix tests separately without blocking other work

**Pros**: Separates unit tests from integration tests, maintains coverage visibility
**Cons**: Requires some restructuring

### Option 3: Fix Tests Before Merging
Debug and fix all 5 tests before merging the CI/CD PR.

**Pros**: All tests pass, no coverage gaps
**Cons**: Delays CI/CD deployment, requires debugging complex mocks

## Decision
Per the agent instructions: "If you think this reason is valid, then come up with a solution to handle this in CI/CD (should we keep these failing tests in a separate project and exclude them in cicd or should we resolve them before adding them to CI/CD, or can you find the best solution, consider all scenarios)"

**Recommended**: Option 2 (Separate Integration Tests)

This provides the best balance:
- CI/CD pipeline can be deployed immediately
- Test coverage is maintained and visible
- Integration tests can be fixed in a separate issue/PR
- Clear separation between unit and integration tests

## Next Steps
1. Merge CI/CD PR as-is (current approach: all tests run, 5 fail)
2. Create Issue #29: "Fix AgentOrchestratorTests integration test failures"
3. Create Issue #30: "Separate integration tests into dedicated test project"
4. After #30 is complete, update CI to exclude integration tests from main build
5. Create separate workflow for integration tests that can fail without blocking merges
