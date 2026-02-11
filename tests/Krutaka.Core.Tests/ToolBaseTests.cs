using System.Text.Json;
using FluentAssertions;

namespace Krutaka.Core.Tests;

internal class ToolBaseTests
{
    private class TestTool : ToolBase
    {
        public override string Name => "test_tool";
        public override string Description => "A test tool for unit testing.";

        public override JsonElement InputSchema => BuildSchema(
            ("path", "string", "The file path", true),
            ("content", "string", "The file content", false)
        );

        public override Task<string> ExecuteAsync(JsonElement input, CancellationToken cancellationToken)
        {
            return Task.FromResult("test result");
        }
    }

    [Fact]
    public void BuildSchema_Should_CreateValidJsonSchema()
    {
        // Arrange & Act
        var tool = new TestTool();
        var schema = tool.InputSchema;

        // Assert
        schema.ValueKind.Should().Be(JsonValueKind.Object);
        schema.GetProperty("type").GetString().Should().Be("object");
        schema.GetProperty("properties").ValueKind.Should().Be(JsonValueKind.Object);

        var properties = schema.GetProperty("properties");
        properties.TryGetProperty("path", out var pathProp).Should().BeTrue();
        pathProp.GetProperty("type").GetString().Should().Be("string");
        pathProp.GetProperty("description").GetString().Should().Be("The file path");

        var required = schema.GetProperty("required");
        required.ValueKind.Should().Be(JsonValueKind.Array);
        required.GetArrayLength().Should().Be(1);
        required[0].GetString().Should().Be("path");
    }
}
