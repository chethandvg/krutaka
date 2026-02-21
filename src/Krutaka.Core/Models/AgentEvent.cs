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
/// <param name="InputTokens">Number of input tokens consumed in this API call (0 if not reported).</param>
/// <param name="OutputTokens">Number of output tokens consumed in this API call (0 if not reported).</param>
public sealed record FinalResponse(string Content, string StopReason, int InputTokens = 0, int OutputTokens = 0) : AgentEvent;

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

/// <summary>
/// Represents the completion of a context compaction operation.
/// Emitted after CompactAsync completes successfully to enable JSONL persistence.
/// </summary>
/// <param name="Summary">The compaction summary (first 200 chars).</param>
/// <param name="TokensBefore">Token count before compaction.</param>
/// <param name="TokensAfter">Token count after compaction.</param>
/// <param name="MessagesRemoved">Number of messages removed during compaction.</param>
public sealed record CompactionCompleted(string Summary, int TokensBefore, int TokensAfter, int MessagesRemoved) : AgentEvent;

/// <summary>
/// Emitted when the agent transitions to <see cref="AgentState.Paused"/>.
/// The agentic loop will block until a resume signal is received.
/// </summary>
/// <param name="Reason">The human-readable reason for the pause.</param>
public sealed record AgentPaused(string Reason) : AgentEvent;

/// <summary>
/// Emitted when the agent transitions from <see cref="AgentState.Paused"/> back to <see cref="AgentState.Running"/>.
/// </summary>
public sealed record AgentResumed : AgentEvent;

/// <summary>
/// Emitted when a budget dimension crosses the 80% consumption threshold.
/// Fired at most once per dimension per session.
/// </summary>
/// <param name="Dimension">The budget dimension that crossed 80%.</param>
/// <param name="Percentage">The current consumption percentage (0.0–1.0).</param>
public sealed record BudgetWarning(BudgetDimension Dimension, double Percentage) : AgentEvent;

/// <summary>
/// Emitted when a budget dimension reaches 100% (limit exhausted).
/// The agentic loop will transition to <see cref="AgentState.Aborted"/> and stop.
/// </summary>
/// <param name="Dimension">The budget dimension that was exhausted.</param>
public sealed record BudgetExhausted(BudgetDimension Dimension) : AgentEvent;
