using System.Text.Json;
using FluentAssertions;

namespace Krutaka.Core.Tests;

internal class SessionEventTests
{
    [Fact]
    public void SessionEvent_Should_SerializeAndDeserialize()
    {
        // Arrange
        var original = new SessionEvent(
            Type: "user",
            Role: "user",
            Content: "Hello, Claude!",
            Timestamp: DateTimeOffset.UtcNow,
            ToolName: null,
            ToolUseId: null,
            IsMeta: false
        );

        // Act
        var json = JsonSerializer.Serialize(original);
        var deserialized = JsonSerializer.Deserialize<SessionEvent>(json);

        // Assert
        deserialized.Should().NotBeNull();
        deserialized!.Type.Should().Be("user");
        deserialized.Role.Should().Be("user");
        deserialized.Content.Should().Be("Hello, Claude!");
        deserialized.IsMeta.Should().BeFalse();
    }

    [Fact]
    public void SessionEvent_Should_HandleToolEvent()
    {
        // Arrange & Act
        var evt = new SessionEvent(
            Type: "tool_use",
            Role: null,
            Content: null,
            Timestamp: DateTimeOffset.UtcNow,
            ToolName: "read_file",
            ToolUseId: "tool_123",
            IsMeta: false
        );

        // Assert
        evt.Type.Should().Be("tool_use");
        evt.Role.Should().BeNull();
        evt.ToolName.Should().Be("read_file");
        evt.ToolUseId.Should().Be("tool_123");
    }
}
