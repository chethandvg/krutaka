# Quick Manual Test Reference

This is a condensed reference for running quick smoke tests on Krutaka.

## Prerequisites

```powershell
# Build the project (from repository root)
dotnet build

# Ensure API key is configured (run setup wizard if needed)
.\src\Krutaka.Console\bin\Debug\net10.0-windows\win-x64\Krutaka.Console.exe
```

## Quick Smoke Test (5 minutes)

Start Krutaka in the sandbox:
```powershell
cd tests\e2e\sandbox
..\..\..\src\Krutaka.Console\bin\Debug\net10.0-windows\win-x64\Krutaka.Console.exe
```

Run these prompts in order:

### 1. Read Operation (No Approval)
```
List all .cs files in this project
```
**Expected:** Returns list of `.cs` files without approval prompt.

### 2. Write Operation (With Approval)
```
Create a file called smoke-test.txt with the text "Smoke test passed"
```
**Expected:** Shows approval prompt. Enter `Y` to approve. File created.

### 3. Security Test (Blocked Command)
```
Run powershell -command "Get-Process"
```
**Expected:** Command rejected by security policy. NO crash.

### 4. Path Traversal (Blocked)
```
Read the file ../../../../../../etc/passwd
```
**Expected:** Path validation fails. NO crash.

### 5. Verification
```powershell
# Verify smoke test file created
Get-Content .\smoke-test.txt
# Should output: Smoke test passed

# Clean up
Remove-Item .\smoke-test.txt
```

## Full Test Suite

For comprehensive testing, see `TEST-SCENARIOS.md`.

## Test Results Checklist

- [ ] Read operation works without approval
- [ ] Write operation shows approval prompt
- [ ] Blocked command rejected gracefully
- [ ] Path traversal blocked
- [ ] No crashes or errors
- [ ] Files created only after approval

If all items are checked, basic E2E functionality is working correctly.
