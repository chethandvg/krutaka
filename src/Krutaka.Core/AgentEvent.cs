namespace Krutaka.Core;

/// <summary>
/// Base class for all agent events emitted during streaming responses.
/// Events represent different stages of the agentic loop.
/// </summary>
public abstract record AgentEvent
{
    /// <summary>
    /// Timestamp when the event was created.
    /// </summary>
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;
}

/// <summary>
/// Represents a text delta event from Claude's streaming response.
/// </summary>
/// <param name="Text">The text delta content.</param>
public sealed record TextDelta(string Text) : AgentEvent;

/// <summary>
/// Represents the start of a tool call by Claude.
/// </summary>
/// <param name="ToolName">The name of the tool being invoked.</param>
/// <param name="ToolUseId">The unique identifier for this tool use.</param>
/// <param name="Input">The input parameters for the tool.</param>
public sealed record ToolCallStarted(string ToolName, string ToolUseId, string Input) : AgentEvent;

/// <summary>
/// Represents successful completion of a tool call.
/// </summary>
/// <param name="ToolName">The name of the tool that was executed.</param>
/// <param name="ToolUseId">The unique identifier for this tool use.</param>
/// <param name="Result">The tool execution result.</param>
public sealed record ToolCallCompleted(string ToolName, string ToolUseId, string Result) : AgentEvent;

/// <summary>
/// Represents a failed tool execution.
/// </summary>
/// <param name="ToolName">The name of the tool that failed.</param>
/// <param name="ToolUseId">The unique identifier for this tool use.</param>
/// <param name="Error">The error message.</param>
public sealed record ToolCallFailed(string ToolName, string ToolUseId, string Error) : AgentEvent;

/// <summary>
/// Represents Claude's final response after all tool calls have completed.
/// </summary>
/// <param name="Content">The final response content.</param>
/// <param name="StopReason">The reason the response stopped (e.g., "end_turn", "max_tokens").</param>
public sealed record FinalResponse(string Content, string StopReason) : AgentEvent;

/// <summary>
/// Represents a request for human approval before executing a tool.
/// </summary>
/// <param name="ToolName">The name of the tool requiring approval.</param>
/// <param name="ToolUseId">The unique identifier for this tool use.</param>
/// <param name="Input">The input parameters for the tool.</param>
public sealed record HumanApprovalRequired(string ToolName, string ToolUseId, string Input) : AgentEvent;

/// <summary>
/// Represents the capture of a request ID from the Claude API response header.
/// Emitted at the start of each streaming response to enable correlation tracking.
/// </summary>
/// <param name="RequestId">The request ID from the Claude API response header.</param>
public sealed record RequestIdCaptured(string RequestId) : AgentEvent;

/// <summary>
/// Represents a request for human approval before granting directory access.
/// </summary>
/// <param name="Path">The directory path being requested.</param>
/// <param name="AccessLevel">The level of access being requested (ReadOnly, ReadWrite, or Execute).</param>
/// <param name="Justification">The agent's justification for requesting access to this directory.</param>
public sealed record DirectoryAccessRequested(string Path, AccessLevel AccessLevel, string Justification) : AgentEvent;

/// <summary>
/// Represents a request for human approval before executing a command.
/// </summary>
/// <param name="Request">The command execution request requiring approval.</param>
/// <param name="Decision">The policy decision containing tier and reason.</param>
public sealed record CommandApprovalRequested(CommandExecutionRequest Request, CommandDecision Decision) : AgentEvent;
