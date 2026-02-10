using FluentAssertions;
using System.Text.Json;

namespace Krutaka.Core.Tests;

public class MemoryResultTests
{
    [Fact]
    public void MemoryResult_Should_HaveCorrectProperties()
    {
        // Arrange & Act
        var result = new MemoryResult(
            Id: 42,
            Content: "Important fact to remember",
            Source: "session_123",
            CreatedAt: new DateTimeOffset(2026, 2, 10, 12, 0, 0, TimeSpan.Zero),
            Score: 0.95
        );

        // Assert
        result.Id.Should().Be(42);
        result.Content.Should().Be("Important fact to remember");
        result.Source.Should().Be("session_123");
        result.CreatedAt.Year.Should().Be(2026);
        result.Score.Should().Be(0.95);
    }

    [Fact]
    public void MemoryResult_Should_SerializeAndDeserialize()
    {
        // Arrange
        var original = new MemoryResult(
            Id: 1,
            Content: "Test memory",
            Source: "test.md",
            CreatedAt: DateTimeOffset.UtcNow,
            Score: 0.8
        );

        // Act
        var json = JsonSerializer.Serialize(original);
        var deserialized = JsonSerializer.Deserialize<MemoryResult>(json);

        // Assert
        deserialized.Should().NotBeNull();
        deserialized!.Id.Should().Be(1);
        deserialized.Content.Should().Be("Test memory");
        deserialized.Source.Should().Be("test.md");
        deserialized.Score.Should().Be(0.8);
    }
}
