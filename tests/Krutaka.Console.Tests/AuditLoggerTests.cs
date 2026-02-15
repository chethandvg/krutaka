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

    [Fact]
    public void Should_LogCommandClassification_WithSafeTier()
    {
        // Arrange
        var (logger, sink) = CreateLoggerWithSink();
        var auditLogger = new AuditLogger(logger);
        var correlationContext = new CorrelationContext(Guid.NewGuid());
        correlationContext.IncrementTurn();

        // Act
        auditLogger.LogCommandClassification(
            correlationContext,
            "git",
            "status",
            CommandRiskTier.Safe,
            autoApproved: true,
            trustedDirectory: null,
            "Auto-approved (Safe tier - read-only operation)");

        // Assert
        var logEvent = sink.Events.Should().ContainSingle().Subject;
        logEvent.Level.Should().Be(LogEventLevel.Information); // Changed from Debug to Information for production visibility
        logEvent.Properties["EventType"].ToString().Should().Contain("CommandClassificationEvent");
        var eventData = logEvent.Properties["EventData"].ToString();
        eventData.Should().Contain("git");
        eventData.Should().Contain("status");
        eventData.Should().Contain("Safe");
        eventData.Should().Contain("autoApproved");
        eventData.Should().Contain("true");
    }

    [Fact]
    public void Should_LogCommandClassification_WithModerateTier_AutoApproved()
    {
        // Arrange
        var (logger, sink) = CreateLoggerWithSink();
        var auditLogger = new AuditLogger(logger);
        var correlationContext = new CorrelationContext(Guid.NewGuid());
        correlationContext.IncrementTurn();

        // Act
        auditLogger.LogCommandClassification(
            correlationContext,
            "dotnet",
            "build",
            CommandRiskTier.Moderate,
            autoApproved: true,
            trustedDirectory: "C:\\Projects\\MyApp",
            "Auto-approved (Moderate tier in trusted directory)");

        // Assert
        var logEvent = sink.Events.Should().ContainSingle().Subject;
        logEvent.Level.Should().Be(LogEventLevel.Information);
        var eventData = logEvent.Properties["EventData"].ToString();
        eventData.Should().Contain("dotnet");
        eventData.Should().Contain("build");
        eventData.Should().Contain("Moderate");
        eventData.Should().Contain("autoApproved");
        eventData.Should().Contain("true");
        eventData.Should().Contain("C:\\\\Projects\\\\MyApp");
    }

    [Fact]
    public void Should_LogCommandClassification_WithModerateTier_RequiresApproval()
    {
        // Arrange
        var (logger, sink) = CreateLoggerWithSink();
        var auditLogger = new AuditLogger(logger);
        var correlationContext = new CorrelationContext(Guid.NewGuid());
        correlationContext.IncrementTurn();

        // Act
        auditLogger.LogCommandClassification(
            correlationContext,
            "dotnet",
            "build",
            CommandRiskTier.Moderate,
            autoApproved: false,
            trustedDirectory: null,
            "Requires approval (Moderate tier in untrusted directory)");

        // Assert
        var logEvent = sink.Events.Should().ContainSingle().Subject;
        logEvent.Level.Should().Be(LogEventLevel.Information);
        var eventData = logEvent.Properties["EventData"].ToString();
        eventData.Should().Contain("dotnet");
        eventData.Should().Contain("build");
        eventData.Should().Contain("Moderate");
        eventData.Should().Contain("autoApproved");
        eventData.Should().Contain("false");
    }

    [Fact]
    public void Should_LogCommandClassification_WithElevatedTier()
    {
        // Arrange
        var (logger, sink) = CreateLoggerWithSink();
        var auditLogger = new AuditLogger(logger);
        var correlationContext = new CorrelationContext(Guid.NewGuid());
        correlationContext.IncrementTurn();

        // Act
        auditLogger.LogCommandClassification(
            correlationContext,
            "git",
            "push origin main",
            CommandRiskTier.Elevated,
            autoApproved: false,
            trustedDirectory: null,
            "Requires approval (Elevated tier - potentially destructive operation)");

        // Assert
        var logEvent = sink.Events.Should().ContainSingle().Subject;
        logEvent.Level.Should().Be(LogEventLevel.Warning);
        var eventData = logEvent.Properties["EventData"].ToString();
        eventData.Should().Contain("git");
        eventData.Should().Contain("push origin main");
        eventData.Should().Contain("Elevated");
        eventData.Should().Contain("autoApproved");
        eventData.Should().Contain("false");
    }

    [Fact]
    public void Should_LogCommandClassification_WithDangerousTier()
    {
        // Arrange
        var (logger, sink) = CreateLoggerWithSink();
        var auditLogger = new AuditLogger(logger);
        var correlationContext = new CorrelationContext(Guid.NewGuid());
        correlationContext.IncrementTurn();

        // Act
        auditLogger.LogCommandClassification(
            correlationContext,
            "powershell",
            "-Command Get-Process",
            CommandRiskTier.Dangerous,
            autoApproved: false,
            trustedDirectory: null,
            "Denied (Dangerous tier - blocked executable)");

        // Assert
        var logEvent = sink.Events.Should().ContainSingle().Subject;
        logEvent.Level.Should().Be(LogEventLevel.Error);
        var eventData = logEvent.Properties["EventData"].ToString();
        eventData.Should().Contain("powershell");
        eventData.Should().Contain("Dangerous");
    }

    [Fact]
    public void Should_TruncateLongArguments_InCommandClassification()
    {
        // Arrange
        var (logger, sink) = CreateLoggerWithSink();
        var auditLogger = new AuditLogger(logger);
        var correlationContext = new CorrelationContext(Guid.NewGuid());
        correlationContext.IncrementTurn();
        var longArguments = new string('a', 600);

        // Act
        auditLogger.LogCommandClassification(
            correlationContext,
            "git",
            longArguments,
            CommandRiskTier.Safe,
            autoApproved: true,
            trustedDirectory: null,
            "Auto-approved");

        // Assert
        var logEvent = sink.Events.Should().ContainSingle().Subject;
        var eventData = logEvent.Properties["EventData"].ToString();
        eventData.Should().Contain("truncated");
    }

    [Fact]
    public void Should_ThrowArgumentException_WhenExecutableIsNullOrWhitespace_InCommandClassification()
    {
        // Arrange
        var (logger, _) = CreateLoggerWithSink();
        var auditLogger = new AuditLogger(logger);
        var correlationContext = new CorrelationContext(Guid.NewGuid());

        // Act & Assert
        var act = () => auditLogger.LogCommandClassification(
            correlationContext,
            "",
            "status",
            CommandRiskTier.Safe,
            autoApproved: true,
            trustedDirectory: null,
            "Auto-approved");
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Should_ThrowArgumentException_WhenReasonIsNullOrWhitespace_InCommandClassification()
    {
        // Arrange
        var (logger, _) = CreateLoggerWithSink();
        var auditLogger = new AuditLogger(logger);
        var correlationContext = new CorrelationContext(Guid.NewGuid());

        // Act & Assert
        var act = () => auditLogger.LogCommandClassification(
            correlationContext,
            "git",
            "status",
            CommandRiskTier.Safe,
            autoApproved: true,
            trustedDirectory: null,
            "");
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Should_IncludeAgentId_WhenAgentContextIsSet()
    {
        // Arrange
        var (logger, sink) = CreateLoggerWithSink();
        var auditLogger = new AuditLogger(logger);
        var correlationContext = new CorrelationContext(Guid.NewGuid());
        correlationContext.IncrementTurn();

        var agentId = Guid.NewGuid();
        var parentAgentId = Guid.NewGuid();
        const string role = "coordinator";
        correlationContext.SetAgentContext(agentId, parentAgentId, role);

        // Act
        auditLogger.LogUserInput(correlationContext, "test input");

        // Assert
        var logEvent = sink.Events.Should().ContainSingle().Subject;
        logEvent.Properties.Should().ContainKey("AgentId");
        logEvent.Properties["AgentId"].ToString().Should().Contain(agentId.ToString());
    }

    [Fact]
    public void Should_IncludeParentAgentId_WhenAgentContextIsSet()
    {
        // Arrange
        var (logger, sink) = CreateLoggerWithSink();
        var auditLogger = new AuditLogger(logger);
        var correlationContext = new CorrelationContext(Guid.NewGuid());
        correlationContext.IncrementTurn();

        var agentId = Guid.NewGuid();
        var parentAgentId = Guid.NewGuid();
        const string role = "executor";
        correlationContext.SetAgentContext(agentId, parentAgentId, role);

        // Act
        auditLogger.LogUserInput(correlationContext, "test input");

        // Assert
        var logEvent = sink.Events.Should().ContainSingle().Subject;
        logEvent.Properties.Should().ContainKey("ParentAgentId");
        logEvent.Properties["ParentAgentId"].ToString().Should().Contain(parentAgentId.ToString());
    }

    [Fact]
    public void Should_IncludeAgentRole_WhenAgentContextIsSet()
    {
        // Arrange
        var (logger, sink) = CreateLoggerWithSink();
        var auditLogger = new AuditLogger(logger);
        var correlationContext = new CorrelationContext(Guid.NewGuid());
        correlationContext.IncrementTurn();

        var agentId = Guid.NewGuid();
        const string role = "researcher";
        correlationContext.SetAgentContext(agentId, null, role);

        // Act
        auditLogger.LogUserInput(correlationContext, "test input");

        // Assert
        var logEvent = sink.Events.Should().ContainSingle().Subject;
        logEvent.Properties.Should().ContainKey("AgentRole");
        logEvent.Properties["AgentRole"].ToString().Should().Contain(role);
    }

    [Fact]
    public void Should_OmitAgentFields_WhenAgentIdIsNull()
    {
        // Arrange
        var (logger, sink) = CreateLoggerWithSink();
        var auditLogger = new AuditLogger(logger);
        var correlationContext = new CorrelationContext(Guid.NewGuid());
        correlationContext.IncrementTurn();
        // AgentId not set (null)

        // Act
        auditLogger.LogUserInput(correlationContext, "test input");

        // Assert
        var logEvent = sink.Events.Should().ContainSingle().Subject;
        logEvent.Properties.Should().NotContainKey("AgentId");
        logEvent.Properties.Should().NotContainKey("ParentAgentId");
        logEvent.Properties.Should().NotContainKey("AgentRole");
    }

    [Fact]
    public void Should_IncludeAgentFields_InToolExecutionEvent()
    {
        // Arrange
        var (logger, sink) = CreateLoggerWithSink();
        var auditLogger = new AuditLogger(logger);
        var correlationContext = new CorrelationContext(Guid.NewGuid());
        correlationContext.IncrementTurn();

        var agentId = Guid.NewGuid();
        correlationContext.SetAgentContext(agentId, null, "tool-executor");

        // Act
        auditLogger.LogToolExecution(correlationContext, "read_file", true, false, 150, 2048);

        // Assert
        var logEvent = sink.Events.Should().ContainSingle().Subject;
        logEvent.Properties.Should().ContainKey("AgentId");
        logEvent.Properties["AgentId"].ToString().Should().Contain(agentId.ToString());
        logEvent.Properties.Should().ContainKey("AgentRole");
        logEvent.Properties["AgentRole"].ToString().Should().Contain("tool-executor");
    }

    [Fact]
    public void Should_IncludeAgentFields_InCommandClassificationEvent()
    {
        // Arrange
        var (logger, sink) = CreateLoggerWithSink();
        var auditLogger = new AuditLogger(logger);
        var correlationContext = new CorrelationContext(Guid.NewGuid());
        correlationContext.IncrementTurn();

        var agentId = Guid.NewGuid();
        correlationContext.SetAgentContext(agentId, null, "command-executor");

        // Act
        auditLogger.LogCommandClassification(
            correlationContext,
            "git",
            "status",
            CommandRiskTier.Safe,
            autoApproved: true,
            trustedDirectory: null,
            "Auto-approved");

        // Assert
        var logEvent = sink.Events.Should().ContainSingle().Subject;
        logEvent.Properties.Should().ContainKey("AgentId");
        logEvent.Properties["AgentId"].ToString().Should().Contain(agentId.ToString());
        logEvent.Properties.Should().ContainKey("AgentRole");
        logEvent.Properties["AgentRole"].ToString().Should().Contain("command-executor");
    }

    [Fact]
    public void Should_IncludeNullParentAgentId_WhenAgentIdIsSetWithoutParent()
    {
        // Arrange
        var (logger, sink) = CreateLoggerWithSink();
        var auditLogger = new AuditLogger(logger);
        var correlationContext = new CorrelationContext(Guid.NewGuid());
        correlationContext.IncrementTurn();

        var agentId = Guid.NewGuid();
        correlationContext.SetAgentContext(agentId, null, "root-agent");

        // Act
        auditLogger.LogUserInput(correlationContext, "test input");

        // Assert
        var logEvent = sink.Events.Should().ContainSingle().Subject;
        logEvent.Properties.Should().ContainKey("ParentAgentId");
        // ParentAgentId should be present as a nullable GUID (Serilog represents null as "null" string)
        var parentAgentIdProperty = logEvent.Properties["ParentAgentId"];
        parentAgentIdProperty.ToString().Should().Be("null");
    }

    [Fact]
    public void Should_PreserveNullableGuidType_ForParentAgentId()
    {
        // Arrange
        var (logger, sink) = CreateLoggerWithSink();
        var auditLogger = new AuditLogger(logger);
        var correlationContext = new CorrelationContext(Guid.NewGuid());
        correlationContext.IncrementTurn();

        var agentId = Guid.NewGuid();
        var parentAgentId = Guid.NewGuid();
        correlationContext.SetAgentContext(agentId, parentAgentId, "executor");

        // Act
        auditLogger.LogUserInput(correlationContext, "test input");

        // Assert
        var logEvent = sink.Events.Should().ContainSingle().Subject;
        logEvent.Properties.Should().ContainKey("ParentAgentId");
        // ParentAgentId should contain the GUID value, not be converted to "N/A"
        logEvent.Properties["ParentAgentId"].ToString().Should().Contain(parentAgentId.ToString());
    }

    [Fact]
    public void Should_PreserveNullableStringType_ForAgentRole()
    {
        // Arrange
        var (logger, sink) = CreateLoggerWithSink();
        var auditLogger = new AuditLogger(logger);
        var correlationContext = new CorrelationContext(Guid.NewGuid());
        correlationContext.IncrementTurn();

        var agentId = Guid.NewGuid();
        correlationContext.SetAgentContext(agentId, null, "coordinator");

        // Act
        auditLogger.LogUserInput(correlationContext, "test input");

        // Assert
        var logEvent = sink.Events.Should().ContainSingle().Subject;
        logEvent.Properties.Should().ContainKey("AgentRole");
        // AgentRole should contain the string value, not be converted to "N/A"
        logEvent.Properties["AgentRole"].ToString().Should().Contain("coordinator");
    }

    [Fact]
    public void Should_LogTelegramAuthEvent_WithAllowedOutcome()
    {
        // Arrange
        var (logger, sink) = CreateLoggerWithSink();
        var auditLogger = new AuditLogger(logger);
        var correlationContext = new CorrelationContext(Guid.NewGuid());
        correlationContext.IncrementTurn();
        var evt = new TelegramAuthEvent
        {
            SessionId = correlationContext.SessionId,
            TurnId = correlationContext.TurnId,
            TelegramUserId = 123456789,
            TelegramChatId = 987654321,
            Outcome = AuthOutcome.Allowed,
            DeniedReason = null,
            UpdateId = 42
        };

        // Act
        auditLogger.LogTelegramAuth(correlationContext, evt);

        // Assert
        var logEvent = sink.Events.Should().ContainSingle().Subject;
        logEvent.Level.Should().Be(LogEventLevel.Information);
        logEvent.Properties["EventType"].ToString().Should().Contain("TelegramAuthEvent");
        var eventData = logEvent.Properties["EventData"].ToString();
        eventData.Should().Contain("123456789");
        eventData.Should().Contain("987654321");
        eventData.Should().Contain("Allowed");
        eventData.Should().Contain("updateId");
        eventData.Should().Contain("42");
    }

    [Fact]
    public void Should_LogTelegramAuthEvent_WithDeniedOutcome()
    {
        // Arrange
        var (logger, sink) = CreateLoggerWithSink();
        var auditLogger = new AuditLogger(logger);
        var correlationContext = new CorrelationContext(Guid.NewGuid());
        correlationContext.IncrementTurn();
        var evt = new TelegramAuthEvent
        {
            SessionId = correlationContext.SessionId,
            TurnId = correlationContext.TurnId,
            TelegramUserId = 123456789,
            TelegramChatId = 987654321,
            Outcome = AuthOutcome.Denied,
            DeniedReason = "User not authorized",
            UpdateId = 43
        };

        // Act
        auditLogger.LogTelegramAuth(correlationContext, evt);

        // Assert
        var logEvent = sink.Events.Should().ContainSingle().Subject;
        var eventData = logEvent.Properties["EventData"].ToString();
        eventData.Should().Contain("Denied");
        eventData.Should().Contain("User not authorized");
    }

    [Fact]
    public void Should_LogTelegramMessageEvent()
    {
        // Arrange
        var (logger, sink) = CreateLoggerWithSink();
        var auditLogger = new AuditLogger(logger);
        var correlationContext = new CorrelationContext(Guid.NewGuid());
        correlationContext.IncrementTurn();
        var evt = new TelegramMessageEvent
        {
            SessionId = correlationContext.SessionId,
            TurnId = correlationContext.TurnId,
            TelegramUserId = 123456789,
            TelegramChatId = 987654321,
            Command = "/ask",
            MessageLength = 256
        };

        // Act
        auditLogger.LogTelegramMessage(correlationContext, evt);

        // Assert
        var logEvent = sink.Events.Should().ContainSingle().Subject;
        logEvent.Level.Should().Be(LogEventLevel.Information);
        logEvent.Properties["EventType"].ToString().Should().Contain("TelegramMessageEvent");
        var eventData = logEvent.Properties["EventData"].ToString();
        eventData.Should().Contain("123456789");
        eventData.Should().Contain("987654321");
        eventData.Should().Contain("/ask");
        eventData.Should().Contain("messageLength");
        eventData.Should().Contain("256");
    }

    [Fact]
    public void Should_LogTelegramApprovalEvent_Approved()
    {
        // Arrange
        var (logger, sink) = CreateLoggerWithSink();
        var auditLogger = new AuditLogger(logger);
        var correlationContext = new CorrelationContext(Guid.NewGuid());
        correlationContext.IncrementTurn();
        var evt = new TelegramApprovalEvent
        {
            SessionId = correlationContext.SessionId,
            TurnId = correlationContext.TurnId,
            TelegramUserId = 123456789,
            TelegramChatId = 987654321,
            ToolName = "execute_command",
            ToolUseId = "toolu_abc123",
            Approved = true
        };

        // Act
        auditLogger.LogTelegramApproval(correlationContext, evt);

        // Assert
        var logEvent = sink.Events.Should().ContainSingle().Subject;
        logEvent.Properties["EventType"].ToString().Should().Contain("TelegramApprovalEvent");
        var eventData = logEvent.Properties["EventData"].ToString();
        eventData.Should().Contain("execute_command");
        eventData.Should().Contain("toolu_abc123");
        eventData.Should().Contain("approved");
        eventData.Should().Contain("true");
    }

    [Fact]
    public void Should_LogTelegramSessionEvent_Created()
    {
        // Arrange
        var (logger, sink) = CreateLoggerWithSink();
        var auditLogger = new AuditLogger(logger);
        var correlationContext = new CorrelationContext(Guid.NewGuid());
        correlationContext.IncrementTurn();
        var evt = new TelegramSessionEvent
        {
            SessionId = correlationContext.SessionId,
            TurnId = correlationContext.TurnId,
            TelegramChatId = 987654321,
            EventType = SessionEventType.Created,
            UserId = "user_123"
        };

        // Act
        auditLogger.LogTelegramSession(correlationContext, evt);

        // Assert
        var logEvent = sink.Events.Should().ContainSingle().Subject;
        logEvent.Properties["EventType"].ToString().Should().Contain("TelegramSessionEvent");
        var eventData = logEvent.Properties["EventData"].ToString();
        eventData.Should().Contain("987654321");
        eventData.Should().Contain("Created");
        eventData.Should().Contain("user_123");
    }

    [Fact]
    public void Should_LogTelegramRateLimitEvent()
    {
        // Arrange
        var (logger, sink) = CreateLoggerWithSink();
        var auditLogger = new AuditLogger(logger);
        var correlationContext = new CorrelationContext(Guid.NewGuid());
        correlationContext.IncrementTurn();
        var evt = new TelegramRateLimitEvent
        {
            SessionId = correlationContext.SessionId,
            TurnId = correlationContext.TurnId,
            TelegramUserId = 123456789,
            CommandCount = 15,
            LimitPerMinute = 10,
            WindowDuration = TimeSpan.FromMinutes(1)
        };

        // Act
        auditLogger.LogTelegramRateLimit(correlationContext, evt);

        // Assert
        var logEvent = sink.Events.Should().ContainSingle().Subject;
        logEvent.Properties["EventType"].ToString().Should().Contain("TelegramRateLimitEvent");
        var eventData = logEvent.Properties["EventData"].ToString();
        eventData.Should().Contain("123456789");
        eventData.Should().Contain("commandCount");
        eventData.Should().Contain("15");
        eventData.Should().Contain("limitPerMinute");
        eventData.Should().Contain("10");
        eventData.Should().Contain("windowDuration");
    }

    [Fact]
    public void Should_LogTelegramSecurityIncidentEvent_AtWarningLevel()
    {
        // Arrange
        var (logger, sink) = CreateLoggerWithSink();
        var auditLogger = new AuditLogger(logger);
        var correlationContext = new CorrelationContext(Guid.NewGuid());
        correlationContext.IncrementTurn();
        var evt = new TelegramSecurityIncidentEvent
        {
            SessionId = correlationContext.SessionId,
            TurnId = correlationContext.TurnId,
            TelegramUserId = 123456789,
            Type = IncidentType.CallbackTampering,
            Details = "HMAC signature mismatch detected"
        };

        // Act
        auditLogger.LogTelegramSecurityIncident(correlationContext, evt);

        // Assert
        var logEvent = sink.Events.Should().ContainSingle().Subject;
        logEvent.Level.Should().Be(LogEventLevel.Warning);
        logEvent.Properties["EventType"].ToString().Should().Contain("TelegramSecurityIncidentEvent");
        var eventData = logEvent.Properties["EventData"].ToString();
        eventData.Should().Contain("123456789");
        eventData.Should().Contain("CallbackTampering");
        eventData.Should().Contain("HMAC signature mismatch detected");
    }

    [Fact]
    public void Should_IncludeAgentId_InTelegramAuthEvent_WhenAgentContextIsSet()
    {
        // Arrange
        var (logger, sink) = CreateLoggerWithSink();
        var auditLogger = new AuditLogger(logger);
        var correlationContext = new CorrelationContext(Guid.NewGuid());
        correlationContext.IncrementTurn();
        var agentId = Guid.NewGuid();
        correlationContext.SetAgentContext(agentId, null, "telegram-handler");

        var evt = new TelegramAuthEvent
        {
            SessionId = correlationContext.SessionId,
            TurnId = correlationContext.TurnId,
            TelegramUserId = 123456789,
            TelegramChatId = 987654321,
            Outcome = AuthOutcome.Allowed,
            UpdateId = 42
        };

        // Act
        auditLogger.LogTelegramAuth(correlationContext, evt);

        // Assert
        var logEvent = sink.Events.Should().ContainSingle().Subject;
        logEvent.Properties.Should().ContainKey("AgentId");
        logEvent.Properties["AgentId"].ToString().Should().Contain(agentId.ToString());
        logEvent.Properties.Should().ContainKey("AgentRole");
        logEvent.Properties["AgentRole"].ToString().Should().Contain("telegram-handler");
    }

    [Fact]
    public void Should_OmitAgentId_InTelegramMessageEvent_WhenAgentIdIsNull()
    {
        // Arrange
        var (logger, sink) = CreateLoggerWithSink();
        var auditLogger = new AuditLogger(logger);
        var correlationContext = new CorrelationContext(Guid.NewGuid());
        correlationContext.IncrementTurn();
        // AgentId not set (null)

        var evt = new TelegramMessageEvent
        {
            SessionId = correlationContext.SessionId,
            TurnId = correlationContext.TurnId,
            TelegramUserId = 123456789,
            TelegramChatId = 987654321,
            Command = "/status",
            MessageLength = 10
        };

        // Act
        auditLogger.LogTelegramMessage(correlationContext, evt);

        // Assert
        var logEvent = sink.Events.Should().ContainSingle().Subject;
        logEvent.Properties.Should().NotContainKey("AgentId");
        logEvent.Properties.Should().NotContainKey("ParentAgentId");
        logEvent.Properties.Should().NotContainKey("AgentRole");
    }

    [Fact]
    public void TelegramAuthEvent_ShouldConstruct_WithAllProperties()
    {
        // Act
        var evt = new TelegramAuthEvent
        {
            SessionId = Guid.NewGuid(),
            TurnId = 1,
            TelegramUserId = 123456789,
            TelegramChatId = 987654321,
            Outcome = AuthOutcome.RateLimited,
            DeniedReason = "Too many requests",
            UpdateId = 100
        };

        // Assert
        evt.TelegramUserId.Should().Be(123456789);
        evt.TelegramChatId.Should().Be(987654321);
        evt.Outcome.Should().Be(AuthOutcome.RateLimited);
        evt.DeniedReason.Should().Be("Too many requests");
        evt.UpdateId.Should().Be(100);
    }

    [Fact]
    public void TelegramSecurityIncidentEvent_ShouldConstruct_WithNullUserId()
    {
        // Act
        var evt = new TelegramSecurityIncidentEvent
        {
            SessionId = Guid.NewGuid(),
            TurnId = 1,
            TelegramUserId = null,
            Type = IncidentType.UnknownUserAttempt,
            Details = "User ID not recognized"
        };

        // Assert
        evt.TelegramUserId.Should().BeNull();
        evt.Type.Should().Be(IncidentType.UnknownUserAttempt);
        evt.Details.Should().Be("User ID not recognized");
    }

    [Fact]
    public void AuthOutcome_ShouldHaveAllExpectedValues()
    {
        // Assert
        Enum.GetNames<AuthOutcome>().Should().Contain(["Allowed", "Denied", "RateLimited", "LockedOut"]);
    }

    [Fact]
    public void SessionEventType_ShouldHaveAllExpectedValues()
    {
        // Assert
        Enum.GetNames<SessionEventType>().Should().Contain(["Created", "Suspended", "Resumed", "Terminated"]);
    }

    [Fact]
    public void IncidentType_ShouldHaveAllExpectedValues()
    {
        // Assert
        Enum.GetNames<IncidentType>().Should().Contain(["LockoutTriggered", "UnknownUserAttempt", "CallbackTampering", "ReplayAttempt"]);
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
