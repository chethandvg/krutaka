using FluentAssertions;
using Krutaka.Console.Logging;
using Krutaka.Core;
using Serilog;
using Serilog.Events;

namespace Krutaka.Console.Tests;

public class AuditLoggerTests
{
    [Fact]
    public void Should_ThrowArgumentNullException_WhenLoggerIsNull()
    {
        // Act & Assert
        var act = () => new AuditLogger(null!);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Should_LogUserInputEvent()
    {
        // Arrange
        var (logger, sink) = CreateLoggerWithSink();
        var auditLogger = new AuditLogger(logger);
        var correlationContext = new CorrelationContext(Guid.NewGuid());
        correlationContext.IncrementTurn();

        // Act
        auditLogger.LogUserInput(correlationContext, "test user input");

        // Assert
        var logEvent = sink.Events.Should().ContainSingle().Subject;
        logEvent.Level.Should().Be(LogEventLevel.Information);
        logEvent.MessageTemplate.Text.Should().Contain("Audit:");
        logEvent.Properties.Should().ContainKey("EventType");
        logEvent.Properties["EventType"].ToString().Should().Contain("UserInputEvent");
    }

    [Fact]
    [Trait("Category", "Quarantined")]
    public void Should_TruncateLongUserInput()
    {
        // Arrange
        var (logger, sink) = CreateLoggerWithSink();
        var auditLogger = new AuditLogger(logger);
        var correlationContext = new CorrelationContext(Guid.NewGuid());
        correlationContext.IncrementTurn();
        var longInput = new string('a', 600);

        // Act
        auditLogger.LogUserInput(correlationContext, longInput);

        // Assert
        var logEvent = sink.Events.Should().ContainSingle().Subject;
        logEvent.Properties.Should().ContainKey("EventData");
        var eventData = logEvent.Properties["EventData"].ToString();
        eventData.Should().Contain("truncated");
    }

    [Fact]
    [Trait("Category", "Quarantined")]
    public void Should_LogClaudeApiRequestEvent()
    {
        // Arrange
        var (logger, sink) = CreateLoggerWithSink();
        var auditLogger = new AuditLogger(logger);
        var correlationContext = new CorrelationContext(Guid.NewGuid());
        correlationContext.IncrementTurn();

        // Act
        auditLogger.LogClaudeApiRequest(correlationContext, "claude-4-sonnet-20250514", 1500, 8);

        // Assert
        var logEvent = sink.Events.Should().ContainSingle().Subject;
        logEvent.Properties["EventType"].ToString().Should().Contain("ClaudeApiRequestEvent");
        var eventData = logEvent.Properties["EventData"].ToString();
        eventData.Should().Contain("claude-4-sonnet-20250514");
        eventData.Should().Contain("1500");
        eventData.Should().Contain("toolCount");
        eventData.Should().Contain("8");
    }

    [Fact]
    [Trait("Category", "Quarantined")]
    public void Should_LogClaudeApiResponseEvent()
    {
        // Arrange
        var (logger, sink) = CreateLoggerWithSink();
        var auditLogger = new AuditLogger(logger);
        var correlationContext = new CorrelationContext(Guid.NewGuid());
        correlationContext.IncrementTurn();
        correlationContext.SetRequestId("req_abc123");

        // Act
        auditLogger.LogClaudeApiResponse(correlationContext, "end_turn", 1200, 300);

        // Assert
        var logEvent = sink.Events.Should().ContainSingle().Subject;
        logEvent.Properties["EventType"].ToString().Should().Contain("ClaudeApiResponseEvent");
        logEvent.Properties["RequestId"].ToString().Should().Contain("req_abc123");
        var eventData = logEvent.Properties["EventData"].ToString();
        eventData.Should().Contain("end_turn");
        eventData.Should().Contain("inputTokens");
        eventData.Should().Contain("1200");
        eventData.Should().Contain("outputTokens");
        eventData.Should().Contain("300");
    }

    [Fact]
    [Trait("Category", "Quarantined")]
    public void Should_LogToolExecutionEvent_WithApproval()
    {
        // Arrange
        var (logger, sink) = CreateLoggerWithSink();
        var auditLogger = new AuditLogger(logger);
        var correlationContext = new CorrelationContext(Guid.NewGuid());
        correlationContext.IncrementTurn();

        // Act
        auditLogger.LogToolExecution(correlationContext, "read_file", true, false, 150, 2048);

        // Assert
        var logEvent = sink.Events.Should().ContainSingle().Subject;
        logEvent.Properties["EventType"].ToString().Should().Contain("ToolExecutionEvent");
        var eventData = logEvent.Properties["EventData"].ToString();
        eventData.Should().Contain("read_file");
        eventData.Should().Contain("approved");
        eventData.Should().Contain("true");
        eventData.Should().Contain("alwaysApprove");
        eventData.Should().Contain("false");
        eventData.Should().Contain("durationMs");
        eventData.Should().Contain("150");
    }

    [Fact]
    [Trait("Category", "Quarantined")]
    public void Should_LogToolExecutionEvent_WithError()
    {
        // Arrange
        var (logger, sink) = CreateLoggerWithSink();
        var auditLogger = new AuditLogger(logger);
        var correlationContext = new CorrelationContext(Guid.NewGuid());
        correlationContext.IncrementTurn();

        // Act
        auditLogger.LogToolExecution(
            correlationContext,
            "run_command",
            true,
            false,
            2500,
            0,
            "Command execution timed out");

        // Assert
        var logEvent = sink.Events.Should().ContainSingle().Subject;
        var eventData = logEvent.Properties["EventData"].ToString();
        eventData.Should().Contain("Command execution timed out");
        eventData.Should().Contain("error");
    }

    [Fact]
    [Trait("Category", "Quarantined")]
    public void Should_LogCompactionEvent()
    {
        // Arrange
        var (logger, sink) = CreateLoggerWithSink();
        var auditLogger = new AuditLogger(logger);
        var correlationContext = new CorrelationContext(Guid.NewGuid());
        correlationContext.IncrementTurn();

        // Act
        auditLogger.LogCompaction(correlationContext, 10000, 5000, 12);

        // Assert
        var logEvent = sink.Events.Should().ContainSingle().Subject;
        logEvent.Properties["EventType"].ToString().Should().Contain("CompactionEvent");
        var eventData = logEvent.Properties["EventData"].ToString();
        eventData.Should().Contain("beforeTokenCount");
        eventData.Should().Contain("10000");
        eventData.Should().Contain("afterTokenCount");
        eventData.Should().Contain("5000");
        eventData.Should().Contain("messagesRemoved");
        eventData.Should().Contain("12");
    }

    [Fact]
    [Trait("Category", "Quarantined")]
    public void Should_LogSecurityViolationEvent()
    {
        // Arrange
        var (logger, sink) = CreateLoggerWithSink();
        var auditLogger = new AuditLogger(logger);
        var correlationContext = new CorrelationContext(Guid.NewGuid());
        correlationContext.IncrementTurn();

        // Act
        auditLogger.LogSecurityViolation(
            correlationContext,
            "blocked_path",
            "C:\\Windows\\System32",
            "Attempted to access blocked system directory");

        // Assert
        var logEvent = sink.Events.Should().ContainSingle().Subject;
        logEvent.Properties["EventType"].ToString().Should().Contain("SecurityViolationEvent");
        var eventData = logEvent.Properties["EventData"].ToString();
        eventData.Should().Contain("blocked_path");
        eventData.Should().Contain("C:\\\\Windows\\\\System32");
        eventData.Should().Contain("Attempted to access blocked system directory");
    }

    [Fact]
    public void Should_IncludeCorrelationIds_InAllEvents()
    {
        // Arrange
        var (logger, sink) = CreateLoggerWithSink();
        var auditLogger = new AuditLogger(logger);
        var sessionId = Guid.NewGuid();
        var correlationContext = new CorrelationContext(sessionId);
        correlationContext.IncrementTurn();
        correlationContext.IncrementTurn();
        correlationContext.SetRequestId("req_xyz789");

        // Act
        auditLogger.LogUserInput(correlationContext, "test");

        // Assert
        var logEvent = sink.Events.Should().ContainSingle().Subject;
        logEvent.Properties["SessionId"].ToString().Should().Contain(sessionId.ToString());
        logEvent.Properties["TurnId"].ToString().Should().Be("2");
        logEvent.Properties["RequestId"].ToString().Should().Contain("req_xyz789");
    }

    [Fact]
    public void Should_HandleNullRequestId()
    {
        // Arrange
        var (logger, sink) = CreateLoggerWithSink();
        var auditLogger = new AuditLogger(logger);
        var correlationContext = new CorrelationContext(Guid.NewGuid());
        correlationContext.IncrementTurn();
        // RequestId not set (null)

        // Act
        auditLogger.LogUserInput(correlationContext, "test");

        // Assert
        var logEvent = sink.Events.Should().ContainSingle().Subject;
        logEvent.Properties["RequestId"].ToString().Should().Contain("N/A");
    }

    [Fact]
    public void Should_ThrowArgumentNullException_WhenCorrelationContextIsNull()
    {
        // Arrange
        var (logger, _) = CreateLoggerWithSink();
        var auditLogger = new AuditLogger(logger);

        // Act & Assert
        var act = () => auditLogger.LogUserInput(null!, "test");
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Should_ThrowArgumentException_WhenModelIsNullOrWhitespace()
    {
        // Arrange
        var (logger, _) = CreateLoggerWithSink();
        var auditLogger = new AuditLogger(logger);
        var correlationContext = new CorrelationContext(Guid.NewGuid());

        // Act & Assert
        var act = () => auditLogger.LogClaudeApiRequest(correlationContext, "", 100, 5);
        act.Should().Throw<ArgumentException>();
    }

    private static (ILogger Logger, TestSink Sink) CreateLoggerWithSink()
    {
        var sink = new TestSink();
        var logger = new LoggerConfiguration()
            .MinimumLevel.Verbose()
            .WriteTo.Sink(sink)
            .CreateLogger();

        return (logger, sink);
    }

    private class TestSink : Serilog.Core.ILogEventSink
    {
        public List<LogEvent> Events { get; } = [];

        public void Emit(LogEvent logEvent)
        {
            Events.Add(logEvent);
        }
    }
}
