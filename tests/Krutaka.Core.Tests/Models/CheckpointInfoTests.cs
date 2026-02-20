using FluentAssertions;

namespace Krutaka.Core.Tests;

public class CheckpointInfoTests
{
    [Fact]
    public void CheckpointInfo_Should_StoreAllProperties()
    {
        // Arrange
        var createdAt = new DateTime(2026, 1, 15, 10, 0, 0, DateTimeKind.Utc);

        // Act
        var info = new CheckpointInfo(
            CheckpointId: "abc123",
            Message: "Before refactor",
            CreatedAt: createdAt,
            FilesModified: 3
        );

        // Assert
        info.CheckpointId.Should().Be("abc123");
        info.Message.Should().Be("Before refactor");
        info.CreatedAt.Should().Be(createdAt);
        info.FilesModified.Should().Be(3);
    }

    [Fact]
    public void CheckpointInfo_Should_SupportValueEquality()
    {
        // Arrange
        var createdAt = new DateTime(2026, 1, 15, 10, 0, 0, DateTimeKind.Utc);
        var info1 = new CheckpointInfo("abc123", "Before refactor", createdAt, 3);
        var info2 = new CheckpointInfo("abc123", "Before refactor", createdAt, 3);

        // Assert
        info1.Should().Be(info2);
        (info1 == info2).Should().BeTrue();
    }

    [Fact]
    public void CheckpointInfo_Should_NotBeEqual_WhenValuesDiffer()
    {
        // Arrange
        var createdAt = new DateTime(2026, 1, 15, 10, 0, 0, DateTimeKind.Utc);
        var info1 = new CheckpointInfo("abc123", "Before refactor", createdAt, 3);
        var info2 = new CheckpointInfo("def456", "Before refactor", createdAt, 3);

        // Assert
        info1.Should().NotBe(info2);
    }

    [Fact]
    public void CheckpointInfo_Should_SupportWithExpression()
    {
        // Arrange
        var createdAt = new DateTime(2026, 1, 15, 10, 0, 0, DateTimeKind.Utc);
        var original = new CheckpointInfo("abc123", "Before refactor", createdAt, 3);

        // Act
        var updated = original with { FilesModified = 7 };

        // Assert
        updated.CheckpointId.Should().Be("abc123");
        updated.Message.Should().Be("Before refactor");
        updated.CreatedAt.Should().Be(createdAt);
        updated.FilesModified.Should().Be(7);
    }
}
