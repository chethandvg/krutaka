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
    /// Agent identifier (GUID, per agent instance).
    /// Null in single-agent mode (v0.4.0). Will be set in v0.9.0 multi-agent coordination.
    /// </summary>
    public Guid? AgentId { get; init; }

    /// <summary>
    /// Parent agent identifier (GUID, for hierarchical agent relationships).
    /// Null in single-agent mode or for root agents. Will be set in v0.9.0 multi-agent coordination.
    /// </summary>
    public Guid? ParentAgentId { get; init; }

    /// <summary>
    /// Agent role identifier (e.g., "coordinator", "researcher", "executor").
    /// Null in single-agent mode. Will be set in v0.9.0 multi-agent coordination.
    /// </summary>
    public string? AgentRole { get; init; }

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
/// Logged when a tool call is automatically approved by the autonomy level provider (v0.5.0).
/// </summary>
public sealed record ToolAutoApprovedEvent : AuditEvent
{
    /// <summary>
    /// The name of the tool that was auto-approved.
    /// </summary>
    public required string ToolName { get; init; }

    /// <summary>
    /// The autonomy level that triggered auto-approval.
    /// </summary>
    public required AutonomyLevel Level { get; init; }

    /// <summary>
    /// Whether the security policy originally required human approval for this tool.
    /// </summary>
    public required bool WasApprovalRequired { get; init; }
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

/// <summary>
/// Logged when a command is classified and evaluated for execution.
/// Captures the risk tier, approval decision, and directory context.
/// </summary>
public sealed record CommandClassificationEvent : AuditEvent
{
    /// <summary>
    /// The command executable name.
    /// </summary>
    public required string Executable { get; init; }

    /// <summary>
    /// The command arguments (sanitized for logging - truncated if too long).
    /// </summary>
    public required string Arguments { get; init; }

    /// <summary>
    /// The risk tier assigned to the command.
    /// </summary>
    public required CommandRiskTier Tier { get; init; }

    /// <summary>
    /// Whether the command was auto-approved (true) or required manual approval (false).
    /// </summary>
    public required bool AutoApproved { get; init; }

    /// <summary>
    /// The trusted directory path if auto-approval was granted based on directory trust.
    /// Null if auto-approval was not based on directory trust (e.g., Safe tier).
    /// </summary>
    public string? TrustedDirectory { get; init; }

    /// <summary>
    /// The reason/justification for the approval decision.
    /// </summary>
    public required string Reason { get; init; }
}

/// <summary>
/// Outcome of a Telegram authentication check.
/// </summary>
public enum AuthOutcome
{
    /// <summary>
    /// User authenticated successfully.
    /// </summary>
    Allowed,

    /// <summary>
    /// User authentication denied.
    /// </summary>
    Denied,

    /// <summary>
    /// User rate-limited.
    /// </summary>
    RateLimited,

    /// <summary>
    /// User locked out.
    /// </summary>
    LockedOut
}

/// <summary>
/// Type of Telegram session event.
/// </summary>
public enum SessionEventType
{
    /// <summary>
    /// Session was created.
    /// </summary>
    Created,

    /// <summary>
    /// Session was suspended.
    /// </summary>
    Suspended,

    /// <summary>
    /// Session was resumed.
    /// </summary>
    Resumed,

    /// <summary>
    /// Session was terminated.
    /// </summary>
    Terminated
}

/// <summary>
/// Type of Telegram security incident.
/// </summary>
public enum IncidentType
{
    /// <summary>
    /// User lockout was triggered.
    /// </summary>
    LockoutTriggered,

    /// <summary>
    /// Unknown user attempted access.
    /// </summary>
    UnknownUserAttempt,

    /// <summary>
    /// Callback data tampering detected.
    /// </summary>
    CallbackTampering,

    /// <summary>
    /// Replay attack attempt detected.
    /// </summary>
    ReplayAttempt
}

/// <summary>
/// Logged when a Telegram authentication check occurs.
/// </summary>
public sealed record TelegramAuthEvent : AuditEvent
{
    /// <summary>
    /// Telegram user identifier.
    /// </summary>
    public required long TelegramUserId { get; init; }

    /// <summary>
    /// Telegram chat identifier.
    /// </summary>
    public required long TelegramChatId { get; init; }

    /// <summary>
    /// Authentication outcome.
    /// </summary>
    public required AuthOutcome Outcome { get; init; }

    /// <summary>
    /// Reason for denial (null if allowed).
    /// </summary>
    public string? DeniedReason { get; init; }

    /// <summary>
    /// Telegram update ID.
    /// </summary>
    public required int UpdateId { get; init; }
}

/// <summary>
/// Logged when a Telegram message is received.
/// </summary>
public sealed record TelegramMessageEvent : AuditEvent
{
    /// <summary>
    /// Telegram user identifier.
    /// </summary>
    public required long TelegramUserId { get; init; }

    /// <summary>
    /// Telegram chat identifier.
    /// </summary>
    public required long TelegramChatId { get; init; }

    /// <summary>
    /// Command name (e.g., "/ask", "/status").
    /// </summary>
    public required string Command { get; init; }

    /// <summary>
    /// Length of the message content.
    /// </summary>
    public required int MessageLength { get; init; }
}

/// <summary>
/// Logged when a Telegram approval/rejection occurs.
/// </summary>
public sealed record TelegramApprovalEvent : AuditEvent
{
    /// <summary>
    /// Telegram user identifier.
    /// </summary>
    public required long TelegramUserId { get; init; }

    /// <summary>
    /// Telegram chat identifier.
    /// </summary>
    public required long TelegramChatId { get; init; }

    /// <summary>
    /// Tool name being approved/rejected.
    /// </summary>
    public required string ToolName { get; init; }

    /// <summary>
    /// Tool use ID from Claude API.
    /// </summary>
    public required string ToolUseId { get; init; }

    /// <summary>
    /// Whether the tool was approved (true) or rejected (false).
    /// </summary>
    public required bool Approved { get; init; }
}

/// <summary>
/// Logged when a Telegram session lifecycle event occurs.
/// </summary>
public sealed record TelegramSessionEvent : AuditEvent
{
    /// <summary>
    /// Telegram chat identifier.
    /// </summary>
    public required long TelegramChatId { get; init; }

    /// <summary>
    /// Session event type.
    /// </summary>
    public required SessionEventType EventType { get; init; }

    /// <summary>
    /// User ID (nullable for backwards compatibility or when user context is unavailable).
    /// </summary>
    public string? UserId { get; init; }
}

/// <summary>
/// Logged when a Telegram rate limit is applied.
/// </summary>
public sealed record TelegramRateLimitEvent : AuditEvent
{
    /// <summary>
    /// Telegram user identifier.
    /// </summary>
    public required long TelegramUserId { get; init; }

    /// <summary>
    /// Current command count within the time window.
    /// </summary>
    public required int CommandCount { get; init; }

    /// <summary>
    /// Rate limit threshold per minute.
    /// </summary>
    public required int LimitPerMinute { get; init; }

    /// <summary>
    /// Time window duration.
    /// </summary>
    public required TimeSpan WindowDuration { get; init; }
}

/// <summary>
/// Logged when a Telegram security incident occurs.
/// </summary>
public sealed record TelegramSecurityIncidentEvent : AuditEvent
{
    /// <summary>
    /// Telegram user identifier (null if not available).
    /// </summary>
    public long? TelegramUserId { get; init; }

    /// <summary>
    /// Incident type.
    /// </summary>
    public required IncidentType Type { get; init; }

    /// <summary>
    /// Incident details.
    /// </summary>
    public required string Details { get; init; }
}
