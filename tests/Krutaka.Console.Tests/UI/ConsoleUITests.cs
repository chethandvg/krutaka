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
}
