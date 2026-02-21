using FluentAssertions;
using Krutaka.Core;
using Krutaka.Tools;
using NSubstitute;
using Xunit;

namespace Krutaka.Console.Tests;

/// <summary>
/// Unit tests for ConsoleUI class.
/// </summary>
public class ConsoleUITests
{
    [Fact]
    public void Constructor_WithNullApprovalHandler_ThrowsArgumentNullException()
    {
        // Arrange, Act & Assert
        var act = () => new ConsoleUI(null!);
        act.Should().ThrowExactly<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_WithValidApprovalHandler_Initializes()
    {
        // Arrange
        var approvalHandler = new ApprovalHandler(Environment.CurrentDirectory, new SafeFileOperations(null));

        // Act
        using var ui = new ConsoleUI(approvalHandler);

        // Assert
        ui.Should().NotBeNull();
        ui.ShutdownToken.Should().NotBeNull();
    }

    [Fact]
    public void ShutdownToken_ShouldNotBeCancelled_Initially()
    {
        // Arrange
        var approvalHandler = new ApprovalHandler(Environment.CurrentDirectory, new SafeFileOperations(null));
        using var ui = new ConsoleUI(approvalHandler);

        // Act & Assert
        ui.ShutdownToken.IsCancellationRequested.Should().BeFalse();
    }

    [Fact]
    public void Dispose_ShouldNotThrow()
    {
        // Arrange
        var approvalHandler = new ApprovalHandler(Environment.CurrentDirectory, new SafeFileOperations(null));

        // Act & Assert
        var act = () =>
        {
            using var ui = new ConsoleUI(approvalHandler);
        };
        act.Should().NotThrow();
    }

    [Fact]
    public void Dispose_MultipleCalls_ShouldNotThrow()
    {
        // Arrange
        var approvalHandler = new ApprovalHandler(Environment.CurrentDirectory, new SafeFileOperations(null));
        var ui = new ConsoleUI(approvalHandler);

        // Act & Assert
        ui.Dispose();
        var act = () => ui.Dispose();
        act.Should().NotThrow();
    }

    [Fact]
    public void DisplayError_WithNullErrorMessage_ThrowsArgumentNullException()
    {
        // Arrange
        var approvalHandler = new ApprovalHandler(Environment.CurrentDirectory, new SafeFileOperations(null));
        using var ui = new ConsoleUI(approvalHandler);

        // Act & Assert
        var act = () => ui.DisplayError(null!);
        act.Should().ThrowExactly<ArgumentNullException>();
    }

    [Fact]
    public void DisplayError_WithEmptyErrorMessage_ThrowsArgumentException()
    {
        // Arrange
        var approvalHandler = new ApprovalHandler(Environment.CurrentDirectory, new SafeFileOperations(null));
        using var ui = new ConsoleUI(approvalHandler);

        // Act & Assert
        var act = () => ui.DisplayError(string.Empty);
        act.Should().ThrowExactly<ArgumentException>();
    }

    [Fact]
    public void DisplayError_WithWhitespaceErrorMessage_ThrowsArgumentException()
    {
        // Arrange
        var approvalHandler = new ApprovalHandler(Environment.CurrentDirectory, new SafeFileOperations(null));
        using var ui = new ConsoleUI(approvalHandler);

        // Act & Assert
        var act = () => ui.DisplayError("   ");
        act.Should().ThrowExactly<ArgumentException>();
    }

    [Fact]
    public void DisplayMemoryStats_WithNullStats_ThrowsArgumentNullException()
    {
        // Arrange
        var approvalHandler = new ApprovalHandler(Environment.CurrentDirectory, new SafeFileOperations(null));
        using var ui = new ConsoleUI(approvalHandler);

        // Act & Assert
        var act = () => ui.DisplayMemoryStats(null!);
        act.Should().ThrowExactly<ArgumentNullException>();
    }

    [Fact]
    public void DisplaySessionInfo_WithNullInfo_ThrowsArgumentNullException()
    {
        // Arrange
        var approvalHandler = new ApprovalHandler(Environment.CurrentDirectory, new SafeFileOperations(null));
        using var ui = new ConsoleUI(approvalHandler);

        // Act & Assert
        var act = () => ui.DisplaySessionInfo(null!);
        act.Should().ThrowExactly<ArgumentNullException>();
    }

    [Fact]
    public async Task DisplayStreamingResponseAsync_WithNullEvents_ThrowsArgumentNullException()
    {
        // Arrange
        var approvalHandler = new ApprovalHandler(Environment.CurrentDirectory, new SafeFileOperations(null));
        using var ui = new ConsoleUI(approvalHandler);

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentNullException>(async () =>
            await ui.DisplayStreamingResponseAsync(null!).ConfigureAwait(false));
    }

    [Fact]
    public void MemoryStats_Constructor_InitializesProperties()
    {
        // Arrange & Act
        var stats = new MemoryStats(100, 500, 2048);

        // Assert
        stats.TotalFacts.Should().Be(100);
        stats.TotalChunks.Should().Be(500);
        stats.DatabaseSizeBytes.Should().Be(2048);
    }

    [Fact]
    public void SessionInfo_Constructor_InitializesProperties()
    {
        // Arrange
        var sessionId = Guid.NewGuid().ToString();
        var startTime = DateTimeOffset.UtcNow;
        var projectPath = "/path/to/project";
        var modelId = "claude-sonnet-4-5";
        var turnCount = 5;

        // Act
        var info = new SessionInfo(sessionId, startTime, projectPath, modelId, turnCount);

        // Assert
        info.SessionId.Should().Be(sessionId);
        info.StartTime.Should().Be(startTime);
        info.ProjectPath.Should().Be(projectPath);
        info.ModelId.Should().Be(modelId);
        info.TurnCount.Should().Be(turnCount);
    }

    [Fact]
    public void MemoryStats_Equality_WorksCorrectly()
    {
        // Arrange
        var stats1 = new MemoryStats(100, 500, 2048);
        var stats2 = new MemoryStats(100, 500, 2048);
        var stats3 = new MemoryStats(200, 500, 2048);

        // Act & Assert
        stats1.Should().Be(stats2);
        stats1.Should().NotBe(stats3);
    }

    [Fact]
    public void SessionInfo_Equality_WorksCorrectly()
    {
        // Arrange
        var sessionId = Guid.NewGuid().ToString();
        var startTime = DateTimeOffset.UtcNow;
        var projectPath = "/path/to/project";
        var modelId = "claude-sonnet-4-5";
        var turnCount = 5;

        var info1 = new SessionInfo(sessionId, startTime, projectPath, modelId, turnCount);
        var info2 = new SessionInfo(sessionId, startTime, projectPath, modelId, turnCount);
        var info3 = new SessionInfo(Guid.NewGuid().ToString(), startTime, projectPath, modelId, turnCount);

        // Act & Assert
        info1.Should().Be(info2);
        info1.Should().NotBe(info3);
    }

    [Fact]
    public void DisplayAutonomyLevel_WithNullProvider_DoesNotThrow()
    {
        // Arrange
        var approvalHandler = new ApprovalHandler(Environment.CurrentDirectory, new SafeFileOperations(null));
        using var ui = new ConsoleUI(approvalHandler);

        // Act & Assert — null provider should display graceful message, not throw
        var act = () => ui.DisplayAutonomyLevel(null);
        act.Should().NotThrow();
    }

    [Theory]
    [InlineData(AutonomyLevel.Supervised)]
    [InlineData(AutonomyLevel.Guided)]
    [InlineData(AutonomyLevel.SemiAutonomous)]
    [InlineData(AutonomyLevel.Autonomous)]
    public void DisplayAutonomyLevel_AtEachLevel_DoesNotThrow(AutonomyLevel level)
    {
        // Arrange
        var approvalHandler = new ApprovalHandler(Environment.CurrentDirectory, new SafeFileOperations(null));
        using var ui = new ConsoleUI(approvalHandler);
        var options = new AutonomyLevelOptions
        {
            Level = level,
            AllowAutonomousMode = level == AutonomyLevel.Autonomous
        };
        IAutonomyLevelProvider provider = new AutonomyLevelProvider(options);

        // Act & Assert
        var act = () => ui.DisplayAutonomyLevel(provider);
        act.Should().NotThrow();
    }

    [Fact]
    public void DisplayBudget_WithNullTracker_DoesNotThrow()
    {
        // Arrange
        var approvalHandler = new ApprovalHandler(Environment.CurrentDirectory, new SafeFileOperations(null));
        using var ui = new ConsoleUI(approvalHandler);

        // Act & Assert — null tracker should display graceful "not enabled" message, not throw
        var act = () => ui.DisplayBudget(null);
        act.Should().NotThrow();
    }

    [Fact]
    public void DisplayBudget_WithFreshTracker_AllZeroPercent_DoesNotThrow()
    {
        // Arrange
        var approvalHandler = new ApprovalHandler(Environment.CurrentDirectory, new SafeFileOperations(null));
        using var ui = new ConsoleUI(approvalHandler);
        var tracker = new TaskBudgetTracker(new TaskBudget());

        // Act & Assert — fresh tracker (all 0%) should render cleanly without throwing
        var act = () => ui.DisplayBudget(tracker);
        act.Should().NotThrow();
    }

    [Fact]
    public void DisplayBudget_WithHalfConsumption_DoesNotThrow()
    {
        // Arrange
        var approvalHandler = new ApprovalHandler(Environment.CurrentDirectory, new SafeFileOperations(null));
        using var ui = new ConsoleUI(approvalHandler);
        var tracker = new TaskBudgetTracker(new TaskBudget(MaxClaudeTokens: 200_000, MaxToolCalls: 100, MaxFilesModified: 20, MaxProcessesSpawned: 10));
        tracker.TryConsume(BudgetDimension.Tokens, 100_000);
        tracker.TryConsume(BudgetDimension.ToolCalls, 50);

        // Act & Assert
        var act = () => ui.DisplayBudget(tracker);
        act.Should().NotThrow();
    }

    [Fact]
    public void DisplayBudget_WithWarningLevel_DoesNotThrow()
    {
        // Arrange — tokens at 85% (warning zone)
        var approvalHandler = new ApprovalHandler(Environment.CurrentDirectory, new SafeFileOperations(null));
        using var ui = new ConsoleUI(approvalHandler);
        var tracker = new TaskBudgetTracker(new TaskBudget(MaxClaudeTokens: 100, MaxToolCalls: 100));
        tracker.TryConsume(BudgetDimension.Tokens, 85);

        // Act & Assert — 85% should show yellow progress without throwing
        var act = () => ui.DisplayBudget(tracker);
        act.Should().NotThrow();
    }

    [Fact]
    public void DisplayBudget_WithExhaustedDimension_DoesNotThrow()
    {
        // Arrange — tool calls at 100% (exhausted)
        var approvalHandler = new ApprovalHandler(Environment.CurrentDirectory, new SafeFileOperations(null));
        using var ui = new ConsoleUI(approvalHandler);
        var tracker = new TaskBudgetTracker(new TaskBudget(MaxToolCalls: 10));
        tracker.TryConsume(BudgetDimension.ToolCalls, 10);

        // Act & Assert — 100% should show red progress without throwing
        var act = () => ui.DisplayBudget(tracker);
        act.Should().NotThrow();
    }
}
