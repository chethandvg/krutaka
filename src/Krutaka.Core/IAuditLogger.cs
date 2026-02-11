namespace Krutaka.Core;

/// <summary>
/// Service for writing audit events to structured log files.
/// All audit events include correlation IDs (SessionId, TurnId, RequestId) for tracing.
/// </summary>
public interface IAuditLogger
{
    /// <summary>
    /// Logs an audit event.
    /// </summary>
    /// <param name="auditEvent">The audit event to log.</param>
    void Log(AuditEvent auditEvent);

    /// <summary>
    /// Logs a user input event.
    /// </summary>
    /// <param name="correlationContext">The correlation context for this event.</param>
    /// <param name="content">The user input content (will be sanitized for logging).</param>
    void LogUserInput(CorrelationContext correlationContext, string content);

    /// <summary>
    /// Logs a Claude API request event.
    /// </summary>
    /// <param name="correlationContext">The correlation context for this event.</param>
    /// <param name="model">The model identifier.</param>
    /// <param name="tokenCount">The token count in the request.</param>
    /// <param name="toolCount">The number of tool definitions sent.</param>
    void LogClaudeApiRequest(CorrelationContext correlationContext, string model, int tokenCount, int toolCount);

    /// <summary>
    /// Logs a Claude API response event.
    /// </summary>
    /// <param name="correlationContext">The correlation context for this event.</param>
    /// <param name="stopReason">The stop reason from Claude.</param>
    /// <param name="inputTokens">Input tokens used.</param>
    /// <param name="outputTokens">Output tokens generated.</param>
    void LogClaudeApiResponse(CorrelationContext correlationContext, string stopReason, int inputTokens, int outputTokens);

    /// <summary>
    /// Logs a tool execution event.
    /// </summary>
    /// <param name="correlationContext">The correlation context for this event.</param>
    /// <param name="toolName">The name of the tool.</param>
    /// <param name="approved">Whether the tool was approved.</param>
    /// <param name="alwaysApprove">Whether "always approve" was selected.</param>
    /// <param name="durationMs">Duration of execution in milliseconds.</param>
    /// <param name="resultLength">Length of the result or error message.</param>
    /// <param name="errorMessage">Error message if execution failed.</param>
    void LogToolExecution(
        CorrelationContext correlationContext,
        string toolName,
        bool approved,
        bool alwaysApprove,
        long durationMs,
        int resultLength,
        string? errorMessage = null);

    /// <summary>
    /// Logs a context compaction event.
    /// </summary>
    /// <param name="correlationContext">The correlation context for this event.</param>
    /// <param name="beforeTokenCount">Token count before compaction.</param>
    /// <param name="afterTokenCount">Token count after compaction.</param>
    /// <param name="messagesRemoved">Number of messages removed.</param>
    void LogCompaction(CorrelationContext correlationContext, int beforeTokenCount, int afterTokenCount, int messagesRemoved);

    /// <summary>
    /// Logs a security policy violation event.
    /// </summary>
    /// <param name="correlationContext">The correlation context for this event.</param>
    /// <param name="violationType">Type of violation (e.g., "blocked_path", "blocked_command").</param>
    /// <param name="blockedValue">The blocked path, command, or tool name.</param>
    /// <param name="context">Full context of the violation.</param>
    void LogSecurityViolation(CorrelationContext correlationContext, string violationType, string blockedValue, string context);
}
