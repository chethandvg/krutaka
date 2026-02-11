using Krutaka.Core;
using Serilog;
using Serilog.Events;

namespace Krutaka.Console.Logging;

/// <summary>
/// Implementation of IAuditLogger that writes structured audit events to Serilog.
/// All events include correlation IDs (SessionId, TurnId, RequestId) for tracing.
/// </summary>
internal sealed class AuditLogger : IAuditLogger
{
    private readonly ILogger _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="AuditLogger"/> class.
    /// </summary>
    /// <param name="logger">The Serilog logger instance.</param>
    public AuditLogger(ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        _logger = logger;
    }

    /// <inheritdoc />
    public void Log(AuditEvent auditEvent)
    {
        ArgumentNullException.ThrowIfNull(auditEvent);

        // Log the entire event as a structured property
        // Use GetType() to ensure derived type properties are captured
        var eventType = auditEvent.GetType();

        _logger.Write(
            LogEventLevel.Information,
            "Audit: {EventType} | SessionId={SessionId} TurnId={TurnId} RequestId={RequestId} | {@AuditEvent}",
            eventType.Name,
            auditEvent.SessionId,
            auditEvent.TurnId,
            auditEvent.RequestId ?? "N/A",
            auditEvent);
    }

    /// <inheritdoc />
    public void LogUserInput(CorrelationContext correlationContext, string content)
    {
        ArgumentNullException.ThrowIfNull(correlationContext);
        ArgumentNullException.ThrowIfNull(content);

        // Sanitize content by truncating if too long
        var sanitizedContent = content.Length > 500
            ? content[..500] + "... (truncated)"
            : content;

        var @event = new UserInputEvent
        {
            SessionId = correlationContext.SessionId,
            TurnId = correlationContext.TurnId,
            RequestId = correlationContext.RequestId,
            Content = sanitizedContent,
            ContentLength = content.Length
        };

        Log(@event);
    }

    /// <inheritdoc />
    public void LogClaudeApiRequest(CorrelationContext correlationContext, string model, int tokenCount, int toolCount)
    {
        ArgumentNullException.ThrowIfNull(correlationContext);
        ArgumentException.ThrowIfNullOrWhiteSpace(model);

        var @event = new ClaudeApiRequestEvent
        {
            SessionId = correlationContext.SessionId,
            TurnId = correlationContext.TurnId,
            RequestId = correlationContext.RequestId,
            Model = model,
            TokenCount = tokenCount,
            ToolCount = toolCount
        };

        Log(@event);
    }

    /// <inheritdoc />
    public void LogClaudeApiResponse(CorrelationContext correlationContext, string stopReason, int inputTokens, int outputTokens)
    {
        ArgumentNullException.ThrowIfNull(correlationContext);
        ArgumentException.ThrowIfNullOrWhiteSpace(stopReason);

        var @event = new ClaudeApiResponseEvent
        {
            SessionId = correlationContext.SessionId,
            TurnId = correlationContext.TurnId,
            RequestId = correlationContext.RequestId,
            StopReason = stopReason,
            InputTokens = inputTokens,
            OutputTokens = outputTokens
        };

        Log(@event);
    }

    /// <inheritdoc />
    public void LogToolExecution(
        CorrelationContext correlationContext,
        string toolName,
        bool approved,
        bool alwaysApprove,
        long durationMs,
        int resultLength,
        string? errorMessage = null)
    {
        ArgumentNullException.ThrowIfNull(correlationContext);
        ArgumentException.ThrowIfNullOrWhiteSpace(toolName);

        var @event = new ToolExecutionEvent
        {
            SessionId = correlationContext.SessionId,
            TurnId = correlationContext.TurnId,
            RequestId = correlationContext.RequestId,
            ToolName = toolName,
            Approved = approved,
            AlwaysApprove = alwaysApprove,
            DurationMs = durationMs,
            ResultLength = resultLength,
            Error = errorMessage
        };

        Log(@event);
    }

    /// <inheritdoc />
    public void LogCompaction(CorrelationContext correlationContext, int beforeTokenCount, int afterTokenCount, int messagesRemoved)
    {
        ArgumentNullException.ThrowIfNull(correlationContext);

        var @event = new CompactionEvent
        {
            SessionId = correlationContext.SessionId,
            TurnId = correlationContext.TurnId,
            RequestId = correlationContext.RequestId,
            BeforeTokenCount = beforeTokenCount,
            AfterTokenCount = afterTokenCount,
            MessagesRemoved = messagesRemoved
        };

        Log(@event);
    }

    /// <inheritdoc />
    public void LogSecurityViolation(CorrelationContext correlationContext, string violationType, string blockedValue, string context)
    {
        ArgumentNullException.ThrowIfNull(correlationContext);
        ArgumentException.ThrowIfNullOrWhiteSpace(violationType);
        ArgumentException.ThrowIfNullOrWhiteSpace(blockedValue);
        ArgumentException.ThrowIfNullOrWhiteSpace(context);

        var @event = new SecurityViolationEvent
        {
            SessionId = correlationContext.SessionId,
            TurnId = correlationContext.TurnId,
            RequestId = correlationContext.RequestId,
            ViolationType = violationType,
            BlockedValue = blockedValue,
            Context = context
        };

        Log(@event);
    }
}
