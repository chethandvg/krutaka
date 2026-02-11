using System.Text.Json;
using FluentAssertions;

namespace Krutaka.Core.Tests;

public class AgentEventTests
{
    [Fact]
    public void TextDelta_Should_HaveCorrectProperties()
    {
        // Arrange & Act
        var evt = new TextDelta("Hello, world!");

        // Assert
        evt.Text.Should().Be("Hello, world!");
        evt.Timestamp.Should().BeCloseTo(DateTimeOffset.UtcNow, TimeSpan.FromSeconds(1));
    }

    [Fact]
    public void ToolCallStarted_Should_HaveCorrectProperties()
    {
        // Arrange & Act
        var evt = new ToolCallStarted("read_file", "tool_123", "{\"path\":\"test.txt\"}");

        // Assert
        evt.ToolName.Should().Be("read_file");
        evt.ToolUseId.Should().Be("tool_123");
        evt.Input.Should().Be("{\"path\":\"test.txt\"}");
    }

    [Fact]
    public void ToolCallCompleted_Should_HaveCorrectProperties()
    {
        // Arrange & Act
        var evt = new ToolCallCompleted("read_file", "tool_123", "file contents");

        // Assert
        evt.ToolName.Should().Be("read_file");
        evt.ToolUseId.Should().Be("tool_123");
        evt.Result.Should().Be("file contents");
    }

    [Fact]
    public void ToolCallFailed_Should_HaveCorrectProperties()
    {
        // Arrange & Act
        var evt = new ToolCallFailed("read_file", "tool_123", "File not found");

        // Assert
        evt.ToolName.Should().Be("read_file");
        evt.ToolUseId.Should().Be("tool_123");
        evt.Error.Should().Be("File not found");
    }

    [Fact]
    public void FinalResponse_Should_HaveCorrectProperties()
    {
        // Arrange & Act
        var evt = new FinalResponse("Done!", "end_turn");

        // Assert
        evt.Content.Should().Be("Done!");
        evt.StopReason.Should().Be("end_turn");
    }

    [Fact]
    public void HumanApprovalRequired_Should_HaveCorrectProperties()
    {
        // Arrange & Act
        var evt = new HumanApprovalRequired("write_file", "tool_456", "{\"path\":\"test.txt\"}");

        // Assert
        evt.ToolName.Should().Be("write_file");
        evt.ToolUseId.Should().Be("tool_456");
        evt.Input.Should().Be("{\"path\":\"test.txt\"}");
    }

    [Fact]
    public void AgentEvent_Should_SupportPolymorphism()
    {
        // Arrange & Act
        AgentEvent evt1 = new TextDelta("text");
        AgentEvent evt2 = new FinalResponse("response", "end_turn");

        // Assert
        evt1.Should().BeOfType<TextDelta>();
        evt2.Should().BeOfType<FinalResponse>();
    }
}
