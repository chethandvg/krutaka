using FluentAssertions;
using Krutaka.Core;

namespace Krutaka.Core.Tests;

public class CorrelationContextTests
{
    [Fact]
    public void Should_GenerateNewSessionId_WhenNoneProvided()
    {
        // Act
        var context = new CorrelationContext();

        // Assert
        context.SessionId.Should().NotBe(Guid.Empty);
    }

    [Fact]
    public void Should_UseProvidedSessionId()
    {
        // Arrange
        var sessionId = Guid.NewGuid();

        // Act
        var context = new CorrelationContext(sessionId);

        // Assert
        context.SessionId.Should().Be(sessionId);
    }

    [Fact]
    public void Should_InitializeTurnIdToZero()
    {
        // Act
        var context = new CorrelationContext();

        // Assert
        context.TurnId.Should().Be(0);
    }

    [Fact]
    public void Should_IncrementTurnId()
    {
        // Arrange
        var context = new CorrelationContext();

        // Act
        context.IncrementTurn();
        context.IncrementTurn();
        context.IncrementTurn();

        // Assert
        context.TurnId.Should().Be(3);
    }

    [Fact]
    public void Should_InitializeRequestIdToNull()
    {
        // Act
        var context = new CorrelationContext();

        // Assert
        context.RequestId.Should().BeNull();
    }

    [Fact]
    public void Should_SetRequestId()
    {
        // Arrange
        var context = new CorrelationContext();

        // Act
        context.SetRequestId("req_abc123");

        // Assert
        context.RequestId.Should().Be("req_abc123");
    }

    [Fact]
    public void Should_ClearRequestId()
    {
        // Arrange
        var context = new CorrelationContext();
        context.SetRequestId("req_abc123");

        // Act
        context.ClearRequestId();

        // Assert
        context.RequestId.Should().BeNull();
    }

    [Fact]
    public void Should_AllowNullRequestId()
    {
        // Arrange
        var context = new CorrelationContext();

        // Act
        context.SetRequestId(null);

        // Assert
        context.RequestId.Should().BeNull();
    }

    [Fact]
    public void Should_MaintainSameSessionId_AcrossTurns()
    {
        // Arrange
        var sessionId = Guid.NewGuid();
        var context = new CorrelationContext(sessionId);

        // Act
        context.IncrementTurn();
        context.IncrementTurn();

        // Assert
        context.SessionId.Should().Be(sessionId);
    }

    [Fact]
    public void Should_ResetSession_WithNewSessionId()
    {
        // Arrange
        var originalSessionId = Guid.NewGuid();
        var context = new CorrelationContext(originalSessionId);
        context.IncrementTurn();
        context.IncrementTurn();
        context.SetRequestId("req_123");

        var newSessionId = Guid.NewGuid();

        // Act
        context.ResetSession(newSessionId);

        // Assert
        context.SessionId.Should().Be(newSessionId);
        context.TurnId.Should().Be(0);
        context.RequestId.Should().BeNull();
    }

    [Fact]
    public void Should_ResetSession_AndAllowNewTurns()
    {
        // Arrange
        var context = new CorrelationContext(Guid.NewGuid());
        context.IncrementTurn();
        context.IncrementTurn();
        context.IncrementTurn();

        var newSessionId = Guid.NewGuid();

        // Act
        context.ResetSession(newSessionId);
        context.IncrementTurn();

        // Assert
        context.SessionId.Should().Be(newSessionId);
        context.TurnId.Should().Be(1);
    }
}
