using FluentAssertions;

namespace Krutaka.Core.Tests;

public class SessionRequestTests
{
    [Fact]
    public void Constructor_Should_ThrowArgumentException_WhenProjectPathIsNull()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentNullException>(() => new SessionRequest(null!));
        exception.ParamName.Should().Be("projectPath");
    }

    [Fact]
    public void Constructor_Should_ThrowArgumentException_WhenProjectPathIsEmpty()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => new SessionRequest(string.Empty));
        exception.ParamName.Should().Be("projectPath");
    }

    [Fact]
    public void Constructor_Should_ThrowArgumentException_WhenProjectPathIsWhitespace()
    {
        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() => new SessionRequest("   "));
        exception.ParamName.Should().Be("projectPath");
    }

    [Fact]
    public void Constructor_Should_SetDefaultMaxTokenBudget()
    {
        // Act
        var request = new SessionRequest("/test/path");

        // Assert
        request.MaxTokenBudget.Should().Be(200_000);
    }

    [Fact]
    public void Constructor_Should_SetDefaultMaxToolCallBudget()
    {
        // Act
        var request = new SessionRequest("/test/path");

        // Assert
        request.MaxToolCallBudget.Should().Be(100);
    }

    [Fact]
    public void RecordEquality_Should_WorkCorrectly()
    {
        // Arrange
        var request1 = new SessionRequest("/test/path", "key1", "user1", 100_000, 50, MaxDuration: TimeSpan.FromHours(1));
        var request2 = new SessionRequest("/test/path", "key1", "user1", 100_000, 50, MaxDuration: TimeSpan.FromHours(1));
        var request3 = new SessionRequest("/test/path", "key2", "user1", 100_000, 50, MaxDuration: TimeSpan.FromHours(1));

        // Assert
        request1.Should().Be(request2); // Equal
        request1.Should().NotBe(request3); // Not equal (different ExternalKey)
    }

    [Fact]
    public void Constructor_Should_AcceptAllParameters()
    {
        // Arrange
        var projectPath = "/test/path";
        var externalKey = "telegram:12345";
        var userId = "user123";
        var maxTokenBudget = 150_000;
        var maxToolCallBudget = 75;
        var maxDuration = TimeSpan.FromHours(2);

        // Act
        var request = new SessionRequest(projectPath, externalKey, userId, maxTokenBudget, maxToolCallBudget, MaxDuration: maxDuration);

        // Assert
        request.ProjectPath.Should().Be(projectPath);
        request.ExternalKey.Should().Be(externalKey);
        request.UserId.Should().Be(userId);
        request.MaxTokenBudget.Should().Be(maxTokenBudget);
        request.MaxToolCallBudget.Should().Be(maxToolCallBudget);
        request.MaxDuration.Should().Be(maxDuration);
    }
}
