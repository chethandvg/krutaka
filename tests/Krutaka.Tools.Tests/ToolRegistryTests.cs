using System.Text.Json;
using FluentAssertions;
using Krutaka.Core;
using Krutaka.Tools;

namespace Krutaka.Tools.Tests;

public sealed class ToolRegistryTests
{
    private readonly ToolRegistry _registry;

    public ToolRegistryTests()
    {
        _registry = new ToolRegistry();
    }

    [Fact]
    public void Should_RegisterTool_Successfully()
    {
        // Arrange
        var tool = new MockTool("test_tool", "Test description");

        // Act
        _registry.Register(tool);
        var definitions = _registry.GetToolDefinitions();

        // Assert
        definitions.Should().NotBeNull();
    }

    [Fact]
    public void Should_ThrowArgumentNullException_WhenRegisteringNullTool()
    {
        // Act & Assert
        var act = () => _registry.Register(null!);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Should_GetToolDefinitions_ReturnCorrectFormat()
    {
        // Arrange
        var tool1 = new MockTool("tool_one", "First tool");
        var tool2 = new MockTool("tool_two", "Second tool");

        _registry.Register(tool1);
        _registry.Register(tool2);

        // Act
        var definitions = _registry.GetToolDefinitions();

        // Assert
        definitions.Should().NotBeNull();

        // Serialize to JSON to verify structure
        var json = JsonSerializer.Serialize(definitions);
        var jsonDoc = JsonDocument.Parse(json);

        jsonDoc.RootElement.ValueKind.Should().Be(JsonValueKind.Array);
        jsonDoc.RootElement.GetArrayLength().Should().Be(2);

        var firstTool = jsonDoc.RootElement[0];
        firstTool.GetProperty("name").GetString().Should().Be("tool_one");
        firstTool.GetProperty("description").GetString().Should().Be("First tool");
        firstTool.TryGetProperty("input_schema", out _).Should().BeTrue();
    }

    [Fact]
    public async Task Should_ExecuteAsync_DispatchToCorrectTool()
    {
        // Arrange
        var tool = new MockTool("test_tool", "Test description");
        _registry.Register(tool);

        var input = JsonSerializer.SerializeToElement(new { param = "value" });

        // Act
        var result = await _registry.ExecuteAsync("test_tool", input, CancellationToken.None).ConfigureAwait(true);

        // Assert
        result.Should().Be("MockTool executed with input");
        tool.WasExecuted.Should().BeTrue();
    }

    [Fact]
    public async Task Should_ThrowInvalidOperationException_ForUnknownTool()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { param = "value" });

        // Act
        var act = async () => await _registry.ExecuteAsync("unknown_tool", input, CancellationToken.None).ConfigureAwait(true);

        // Assert
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("Unknown tool: unknown_tool");
    }

    [Fact]
    public async Task Should_ThrowArgumentNullException_WhenExecutingWithNullName()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { param = "value" });

        // Act
        var act = async () => await _registry.ExecuteAsync(null!, input, CancellationToken.None).ConfigureAwait(true);

        // Assert
        await act.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public void Should_OverwriteExistingTool_WhenRegisteringWithSameName()
    {
        // Arrange
        var tool1 = new MockTool("test_tool", "First description");
        var tool2 = new MockTool("test_tool", "Second description");

        // Act
        _registry.Register(tool1);
        _registry.Register(tool2);

        var definitions = _registry.GetToolDefinitions();
        var json = JsonSerializer.Serialize(definitions);
        var jsonDoc = JsonDocument.Parse(json);

        // Assert
        jsonDoc.RootElement.GetArrayLength().Should().Be(1);
        jsonDoc.RootElement[0].GetProperty("description").GetString().Should().Be("Second description");
    }

    [Fact]
    public void Should_BeCaseInsensitive_WhenLookingUpTools()
    {
        // Arrange
        var tool = new MockTool("Test_Tool", "Test description");
        _registry.Register(tool);

        var input = JsonSerializer.SerializeToElement(new { param = "value" });

        // Act & Assert - should work with different casing
        var act = async () => await _registry.ExecuteAsync("test_tool", input, CancellationToken.None).ConfigureAwait(true);
        act.Should().NotThrowAsync();
    }

    [Fact]
    public void Should_GetToolDefinitions_ReturnEmptyList_WhenNoToolsRegistered()
    {
        // Act
        var definitions = _registry.GetToolDefinitions();

        // Assert
        var json = JsonSerializer.Serialize(definitions);
        var jsonDoc = JsonDocument.Parse(json);

        jsonDoc.RootElement.ValueKind.Should().Be(JsonValueKind.Array);
        jsonDoc.RootElement.GetArrayLength().Should().Be(0);
    }

    [Fact]
    public void Should_GetToolDefinitions_IncludeAllToolProperties()
    {
        // Arrange
        var tool = new MockTool("test_tool", "Test description with details");
        _registry.Register(tool);

        // Act
        var definitions = _registry.GetToolDefinitions();
        var json = JsonSerializer.Serialize(definitions);
        var jsonDoc = JsonDocument.Parse(json);

        // Assert
        var toolDef = jsonDoc.RootElement[0];
        toolDef.GetProperty("name").GetString().Should().Be("test_tool");
        toolDef.GetProperty("description").GetString().Should().Be("Test description with details");

        var inputSchema = toolDef.GetProperty("input_schema");
        inputSchema.GetProperty("type").GetString().Should().Be("object");
    }

    // Mock tool implementation for testing
    private sealed class MockTool : ToolBase
    {
        private readonly string _name;
        private readonly string _description;

        public bool WasExecuted { get; private set; }

        public MockTool(string name, string description)
        {
            _name = name;
            _description = description;
        }

        public override string Name => _name;

        public override string Description => _description;

        public override JsonElement InputSchema => BuildSchema(
            ("param", "string", "A test parameter", true)
        );

        public override Task<string> ExecuteAsync(JsonElement input, CancellationToken cancellationToken)
        {
            WasExecuted = true;
            return Task.FromResult("MockTool executed with input");
        }
    }
}
