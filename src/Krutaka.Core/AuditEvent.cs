namespace Krutaka.Core;

/// <summary>
/// Base class for all audit events logged to the audit trail.
/// All events include correlation IDs for session/turn/request tracing.
/// </summary>
public abstract record AuditEvent
{
    /// <summary>
    /// Session identifier (GUID, per session).
    /// </summary>
    public required Guid SessionId { get; init; }

    /// <summary>
    /// Turn identifier (incrementing integer, per user turn within session).
    /// </summary>
    public required int TurnId { get; init; }

    /// <summary>
    /// Request identifier from Claude API response header (if applicable).
    /// </summary>
    public string? RequestId { get; init; }

    /// <summary>
    /// Timestamp when the event occurred.
    /// </summary>
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;
}

/// <summary>
/// Logged when user provides input to the agent.
/// </summary>
public sealed record UserInputEvent : AuditEvent
{
    /// <summary>
    /// The sanitized user input content.
    /// </summary>
    public required string Content { get; init; }

    /// <summary>
    /// Length of the original content before sanitization.
    /// </summary>
    public required int ContentLength { get; init; }
}

/// <summary>
/// Logged when sending a request to Claude API.
/// </summary>
public sealed record ClaudeApiRequestEvent : AuditEvent
{
    /// <summary>
    /// The model identifier used for the request.
    /// </summary>
    public required string Model { get; init; }

    /// <summary>
    /// Token count in the request.
    /// </summary>
    public required int TokenCount { get; init; }

    /// <summary>
    /// Number of tool definitions sent to Claude.
    /// </summary>
    public required int ToolCount { get; init; }
}

/// <summary>
/// Logged when receiving a response from Claude API.
/// </summary>
public sealed record ClaudeApiResponseEvent : AuditEvent
{
    /// <summary>
    /// The stop reason from Claude (e.g., "end_turn", "max_tokens", "tool_use").
    /// </summary>
    public required string StopReason { get; init; }

    /// <summary>
    /// Input tokens used in the request.
    /// </summary>
    public required int InputTokens { get; init; }

    /// <summary>
    /// Output tokens generated in the response.
    /// </summary>
    public required int OutputTokens { get; init; }
}

/// <summary>
/// Logged when executing a tool.
/// </summary>
public sealed record ToolExecutionEvent : AuditEvent
{
    /// <summary>
    /// The name of the tool being executed.
    /// </summary>
    public required string ToolName { get; init; }

    /// <summary>
    /// Whether the tool required and received approval.
    /// </summary>
    public required bool Approved { get; init; }

    /// <summary>
    /// Whether the approval was "always approve" for the session.
    /// </summary>
    public bool AlwaysApprove { get; init; }

    /// <summary>
    /// Duration of tool execution in milliseconds.
    /// </summary>
    public required long DurationMs { get; init; }

    /// <summary>
    /// Length of the result content (if success) or error message (if failure).
    /// </summary>
    public required int ResultLength { get; init; }

    /// <summary>
    /// Error message if tool execution failed.
    /// </summary>
    public string? Error { get; init; }
}

/// <summary>
/// Logged when context compaction occurs.
/// </summary>
public sealed record CompactionEvent : AuditEvent
{
    /// <summary>
    /// Token count before compaction.
    /// </summary>
    public required int BeforeTokenCount { get; init; }

    /// <summary>
    /// Token count after compaction.
    /// </summary>
    public required int AfterTokenCount { get; init; }

    /// <summary>
    /// Number of messages removed during compaction.
    /// </summary>
    public required int MessagesRemoved { get; init; }
}

/// <summary>
/// Logged when a security policy violation occurs.
/// </summary>
public sealed record SecurityViolationEvent : AuditEvent
{
    /// <summary>
    /// Type of security violation (e.g., "blocked_path", "blocked_command", "blocked_tool").
    /// </summary>
    public required string ViolationType { get; init; }

    /// <summary>
    /// The blocked path, command, or tool name.
    /// </summary>
    public required string BlockedValue { get; init; }

    /// <summary>
    /// Full context of the violation (e.g., tool name, input parameters).
    /// </summary>
    public required string Context { get; init; }
}
