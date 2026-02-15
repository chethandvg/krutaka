using System.Text.Json;
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

        // Build EventData dictionary from event-specific (derived type) properties,
        // excluding base AuditEvent properties which are logged separately as correlation IDs.
        var eventType = auditEvent.GetType();
        var baseProperties = typeof(AuditEvent).GetProperties().Select(p => p.Name).ToHashSet();
        var eventData = eventType.GetProperties()
            .Where(p => !baseProperties.Contains(p.Name))
            .ToDictionary(
                p => char.ToLowerInvariant(p.Name[0]) + p.Name[1..],
                p => p.GetValue(auditEvent));

        // Serialize EventData as JSON to ensure consistent formatting
        // (lowercase booleans, proper string escaping for paths)
        var eventDataJson = JsonSerializer.Serialize(eventData);

        WriteAuditLog(LogEventLevel.Information, eventType.Name, auditEvent, eventDataJson);
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
            AgentId = correlationContext.AgentId,
            ParentAgentId = correlationContext.ParentAgentId,
            AgentRole = correlationContext.AgentRole,
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
            AgentId = correlationContext.AgentId,
            ParentAgentId = correlationContext.ParentAgentId,
            AgentRole = correlationContext.AgentRole,
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
            AgentId = correlationContext.AgentId,
            ParentAgentId = correlationContext.ParentAgentId,
            AgentRole = correlationContext.AgentRole,
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
            AgentId = correlationContext.AgentId,
            ParentAgentId = correlationContext.ParentAgentId,
            AgentRole = correlationContext.AgentRole,
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
            AgentId = correlationContext.AgentId,
            ParentAgentId = correlationContext.ParentAgentId,
            AgentRole = correlationContext.AgentRole,
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
            AgentId = correlationContext.AgentId,
            ParentAgentId = correlationContext.ParentAgentId,
            AgentRole = correlationContext.AgentRole,
            ViolationType = violationType,
            BlockedValue = blockedValue,
            Context = context
        };

        Log(@event);
    }

    /// <inheritdoc />
    public void LogCommandClassification(
        CorrelationContext correlationContext,
        string executable,
        string arguments,
        CommandRiskTier tier,
        bool autoApproved,
        string? trustedDirectory,
        string reason)
    {
        ArgumentNullException.ThrowIfNull(correlationContext);
        ArgumentException.ThrowIfNullOrWhiteSpace(executable);
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);

        // Sanitize arguments by truncating if too long
        var sanitizedArguments = arguments.Length > 500
            ? arguments[..500] + "... (truncated)"
            : arguments;

        var @event = new CommandClassificationEvent
        {
            SessionId = correlationContext.SessionId,
            TurnId = correlationContext.TurnId,
            RequestId = correlationContext.RequestId,
            AgentId = correlationContext.AgentId,
            ParentAgentId = correlationContext.ParentAgentId,
            AgentRole = correlationContext.AgentRole,
            Executable = executable,
            Arguments = sanitizedArguments,
            Tier = tier,
            AutoApproved = autoApproved,
            TrustedDirectory = trustedDirectory,
            Reason = reason
        };

        // Log at different levels based on tier
        // Safe: Information (needs to be visible in production logs)
        // Moderate: Information (noteworthy but routine)
        // Elevated: Warning (always notable, requires human approval)
        // Dangerous: Error (security event - command blocked)
        var logLevel = tier switch
        {
            CommandRiskTier.Safe => LogEventLevel.Information,
            CommandRiskTier.Moderate => LogEventLevel.Information,
            CommandRiskTier.Elevated => LogEventLevel.Warning,
            CommandRiskTier.Dangerous => LogEventLevel.Error,
            _ => LogEventLevel.Information
        };

        // Build EventData dictionary from event-specific properties with string enum serialization
        var eventType = @event.GetType();
        var baseProperties = typeof(AuditEvent).GetProperties().Select(p => p.Name).ToHashSet();
        var eventData = eventType.GetProperties()
            .Where(p => !baseProperties.Contains(p.Name))
            .ToDictionary(
                p => char.ToLowerInvariant(p.Name[0]) + p.Name[1..],
                p =>
                {
                    var value = p.GetValue(@event);
                    // Convert enums to string names instead of numeric values
                    return value is Enum enumValue ? enumValue.ToString() : value;
                });

        // Serialize EventData as JSON
        var eventDataJson = JsonSerializer.Serialize(eventData);

        WriteAuditLog(logLevel, eventType.Name, @event, eventDataJson);
    }

    /// <summary>
    /// Writes an audit log entry with conditional agent context fields.
    /// When AgentId is present, includes AgentId, ParentAgentId, and AgentRole in the log.
    /// When AgentId is null, uses the standard log format without agent fields.
    /// </summary>
    /// <param name="logLevel">The log event level.</param>
    /// <param name="eventTypeName">The event type name.</param>
    /// <param name="auditEvent">The audit event containing correlation and agent context.</param>
    /// <param name="eventDataJson">The serialized event data JSON.</param>
    private void WriteAuditLog(LogEventLevel logLevel, string eventTypeName, AuditEvent auditEvent, string eventDataJson)
    {
        // Conditionally include agent context fields when AgentId is non-null
        if (auditEvent.AgentId.HasValue)
        {
            _logger.Write(
                logLevel,
                "Audit: {EventType} | SessionId={SessionId} TurnId={TurnId} RequestId={RequestId} AgentId={AgentId} ParentAgentId={ParentAgentId} AgentRole={AgentRole} | {EventData}",
                eventTypeName,
                auditEvent.SessionId,
                auditEvent.TurnId,
                auditEvent.RequestId ?? "N/A",
                auditEvent.AgentId,
                auditEvent.ParentAgentId,
                auditEvent.AgentRole,
                eventDataJson);
        }
        else
        {
            _logger.Write(
                logLevel,
                "Audit: {EventType} | SessionId={SessionId} TurnId={TurnId} RequestId={RequestId} | {EventData}",
                eventTypeName,
                auditEvent.SessionId,
                auditEvent.TurnId,
                auditEvent.RequestId ?? "N/A",
                eventDataJson);
        }
    }
}
