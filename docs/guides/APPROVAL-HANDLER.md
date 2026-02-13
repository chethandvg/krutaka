# ApprovalHandler Usage Guide

## Overview

The `ApprovalHandler` class provides a Spectre.Console-based UI for human-in-the-loop approval of destructive tool operations. It displays tool information in formatted panels with color-coded risk levels and captures user decisions.

**v0.3.0 Update**: The approval handler now supports tiered command execution for `run_command` tool, displaying risk tier information (Safe/Moderate/Elevated) and context-dependent approval options.

## Features

### Risk-Based Approval Prompts

Each tool is displayed with:
- **Tool name** and **risk level** (Critical/High/Medium for non-command tools; Safe/Moderate/Elevated for commands)
- **Color-coded border**: Red for Critical/Elevated, Yellow for High/Moderate, Green for Safe, Cyan for others
- **Risk icon**: 🔴 for Critical/Elevated, ⚠️ for High, 🟢 for Safe/Moderate, ⚙️ for others
- **Formatted parameters** showing the tool's input

### Tool-Specific Previews

#### `write_file`
- Shows the full file path
- Displays content preview:
  - First 50 lines shown inline
  - If >50 lines, shows truncation notice: "... (N more lines)"
  - Total line count displayed
  - [V]iew option to see full content in a panel

#### `edit_file`
- Shows the file path, start line, and end line
- Displays a diff preview:
  - Lines to be removed shown in **red** with `-` prefix
  - New content shown in **green** with `+` prefix
  - If file doesn't exist or path is invalid, shows appropriate warning

#### `run_command` (v0.3.0 Tiered Execution)

The `run_command` tool now uses graduated risk tiers:

| Tier | In Trusted Dir | UI Behavior |
|------|----------------|-------------|
| **Safe** | N/A | Auto-approved, shows dim message: `[dim]⚙ Auto-approved (Safe): git status[/]` |
| **Moderate** | Yes | Auto-approved, shows dim message: `[dim]⚙ Auto-approved (Moderate — trusted dir): dotnet build[/]` |
| **Moderate** | No | Approval prompt with [Y]es/[N]o/[A]lways options |
| **Elevated** | N/A | Approval prompt with [Y]es/[N]o only (no "Always") |
| **Dangerous** | N/A | Blocked before reaching UI |

**Elevated tier approval prompt shows:**
- 🟡 **ELEVATED** risk tier label
- Working directory
- Agent's justification for the command
- [Y]es and [N]o options only (no "Always" for security)

**Moderate tier approval prompt (untrusted directory) shows:**
- 🟢 **MODERATE (not in trusted directory)** risk tier label
- Working directory
- Agent's justification for the command
- [Y]es, [N]o, and [A]lways options

Examples of commands by tier:
- **Safe**: `git status`, `git log`, `dotnet --version`, `npm --version`, `echo`, `cat`, `dir`
- **Moderate**: `git commit`, `git add`, `dotnet build`, `dotnet test`, `npm run`, `npm test`, `python script.py`
- **Elevated**: `git push`, `git pull`, `dotnet publish`, `npm install`, `pip install`
- **Dangerous**: `powershell`, `cmd`, `curl`, `wget`, `format`, `diskpart` (always blocked)

### User Choices

**For `run_command` with Elevated tier:**
- `[Y]es - Execute this command`
- `[N]o - Deny this command`

**For `run_command` with Moderate tier (untrusted directory):**
- `[Y]es - Execute this command`
- `[N]o - Deny this command`
- `[A]lways - Approve this command for this session`

**For other tools (`write_file`, `edit_file`):**
- `[Y]es - Approve this operation`
- `[N]o - Deny this operation`
- `[A]lways - Approve all operations of this type this session`
- `[V]iew - View full content` (for `write_file` with >50 lines)

### Session-Level "Always Approve"

- When user selects `[A]lways`, the decision is cached for the session
- Subsequent calls to the same tool auto-approve with a dim message:
  ```
  ⚙ Auto-approving write_file (user selected 'Always' for this session)
  ```
- **v0.3.0**: Moderate tier commands can be approved with "Always" (specific command signature cached)
- **Exception**: Elevated tier `run_command` NEVER supports "Always" per security policy (requires explicit approval every time)

### Denial Handling

When a tool is denied:
- `ApprovalDecision.Approved = false`
- Use `ApprovalHandler.CreateDenialMessage(toolName)` to get a descriptive message:
  ```
  "The user denied execution of write_file. The user chose not to allow this operation. Please try a different approach or ask the user for clarification."
  ```
- This is sent back to Claude as a tool result (not an error) so Claude can adjust its approach

## Usage Example

```csharp
using Krutaka.Console;

// Create the handler (maintains session state)
// projectRoot is the allowed root directory for file access
var handler = new ApprovalHandler(projectRoot: "/path/to/project", fileOps: new SafeFileOperations(null));

// Request approval for a tool invocation
var toolInput = @"{
    ""path"": ""src/Program.cs"",
    ""content"": ""// New file content\n""
}";

var decision = handler.RequestApproval("write_file", toolInput);

if (decision.Approved)
{
    // Execute the tool
    if (decision.AlwaysApprove)
    {
        // User selected "Always" - future calls will auto-approve
    }
}
else
{
    // User denied - send denial message back to Claude
    var denialMessage = ApprovalHandler.CreateDenialMessage("write_file");
    // Return denialMessage as tool result (not error)
}
```

## Integration with AgentOrchestrator

**Status**: Not yet integrated (deferred to Issue #23)

The `AgentOrchestrator` currently yields `HumanApprovalRequired` events but continues tool execution. Full integration requires:

1. Orchestrator waits for approval response before executing
2. If denied, orchestrator sends denial message as tool result
3. If approved with `AlwaysApprove`, orchestrator calls `ApproveTool(toolName, alwaysApprove: true)`

Example future integration:

```csharp
await foreach (var evt in orchestrator.RunAsync(prompt, systemPrompt))
{
    switch (evt)
    {
        case HumanApprovalRequired approval:
            var decision = approvalHandler.RequestApproval(
                approval.ToolName, 
                approval.Input);
            
            if (decision.Approved)
            {
                orchestrator.ApproveTool(
                    approval.ToolName, 
                    decision.AlwaysApprove);
            }
            else
            {
                orchestrator.DenyTool(
                    approval.ToolUseId,
                    ApprovalHandler.CreateDenialMessage(approval.ToolName));
            }
            break;
        
        // Handle other events...
    }
}
```

## Testing

The `ApprovalHandlerTests` class provides 8 unit tests covering:
- Argument validation (null/empty/whitespace tool name and input)
- Invalid JSON handling
- Record equality for `ApprovalDecision`

Interactive approval flow is tested through manual verification or integration tests.

## Security Considerations

1. **No "Always" for `run_command`**: Critical commands require explicit approval every time
2. **Session scope**: "Always approve" state is per-session only, not persisted
3. **Denial as result**: Denials are sent as tool results (not errors) to allow Claude to adjust
4. **Input validation**: All inputs are validated; invalid JSON returns `Approved = false`
5. **File preview safety**: Edit file previews catch and handle file access exceptions gracefully
