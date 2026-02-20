using FluentAssertions;

namespace Krutaka.Core.Tests;

public class SessionSummaryTests
{
    [Fact]
    public void RecordEquality_Should_WorkCorrectly()
    {
        // Arrange
        var sessionId = Guid.NewGuid();
        var createdAt = DateTimeOffset.UtcNow;
        var lastActivity = DateTimeOffset.UtcNow;

        var summary1 = new SessionSummary(
            sessionId,
            SessionState.Active,
            "/test/path",
            "key1",
            "user1",
            createdAt,
            lastActivity,
            1000,
            5);

        var summary2 = new SessionSummary(
            sessionId,
            SessionState.Active,
            "/test/path",
            "key1",
            "user1",
            createdAt,
            lastActivity,
            1000,
            5);

        var summary3 = new SessionSummary(
            Guid.NewGuid(), // Different SessionId
            SessionState.Active,
            "/test/path",
            "key1",
            "user1",
            createdAt,
            lastActivity,
            1000,
            5);

        // Assert
        summary1.Should().Be(summary2); // Equal
        summary1.Should().NotBe(summary3); // Not equal (different SessionId)
    }

    [Fact]
    public void Constructor_Should_InitializeAllProperties()
    {
        // Arrange
        var sessionId = Guid.NewGuid();
        var state = SessionState.Idle;
        var projectPath = "/test/path";
        var externalKey = "telegram:12345";
        var userId = "user123";
        var createdAt = DateTimeOffset.UtcNow.AddHours(-1);
        var lastActivity = DateTimeOffset.UtcNow;
        var tokensUsed = 5000;
        var turnsUsed = 10;

        // Act
        var summary = new SessionSummary(
            sessionId,
            state,
            projectPath,
            externalKey,
            userId,
            createdAt,
            lastActivity,
            tokensUsed,
            turnsUsed);

        // Assert
        summary.SessionId.Should().Be(sessionId);
        summary.State.Should().Be(state);
        summary.ProjectPath.Should().Be(projectPath);
        summary.ExternalKey.Should().Be(externalKey);
        summary.UserId.Should().Be(userId);
        summary.CreatedAt.Should().Be(createdAt);
        summary.LastActivity.Should().Be(lastActivity);
        summary.TokensUsed.Should().Be(tokensUsed);
        summary.TurnsUsed.Should().Be(turnsUsed);
    }
}
