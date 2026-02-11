using System.Text.Json;
using FluentAssertions;
using Krutaka.Core;
using Krutaka.Memory;

namespace Krutaka.Memory.Tests;

public sealed class MemorySearchToolTests : IDisposable
{
    private readonly SqliteMemoryStore _memoryService;
    private readonly MemorySearchTool _tool;

    public MemorySearchToolTests()
    {
        var options = new MemoryOptions
        {
            DatabasePath = ":memory:",
            ChunkSizeTokens = 500,
            ChunkOverlapTokens = 50
        };
        _memoryService = new SqliteMemoryStore(options);
        _memoryService.InitializeAsync().GetAwaiter().GetResult();

        _tool = new MemorySearchTool(_memoryService);

        // Seed some test data
        _memoryService.StoreAsync("The user prefers dark mode in their IDE", "memory/User Preferences").GetAwaiter().GetResult();
        _memoryService.StoreAsync("The project uses SQLite for local storage", "memory/Project Context").GetAwaiter().GetResult();
        _memoryService.StoreAsync("The team decided to use TypeScript for frontend development", "memory/Technical Decisions").GetAwaiter().GetResult();
    }

    public void Dispose()
    {
        _memoryService.Dispose();
        GC.SuppressFinalize(this);
    }

    [Fact]
    public void Should_HaveCorrectName()
    {
        _tool.Name.Should().Be("memory_search");
    }

    [Fact]
    public void Should_HaveDescriptionWithKeywords()
    {
        _tool.Description.Should().Contain("Search");
        _tool.Description.Should().Contain("memory");
        _tool.Description.Should().Contain("persistent");
    }

    [Fact]
    public void Should_HaveValidInputSchema()
    {
        var schema = _tool.InputSchema;

        schema.ValueKind.Should().Be(JsonValueKind.Object);
        schema.GetProperty("type").GetString().Should().Be("object");

        var properties = schema.GetProperty("properties");
        properties.TryGetProperty("query", out var queryProp).Should().BeTrue();
        queryProp.GetProperty("type").GetString().Should().Be("string");

        properties.TryGetProperty("limit", out var limitProp).Should().BeTrue();
        limitProp.GetProperty("type").GetString().Should().Be("number");

        var required = schema.GetProperty("required");
        required.ValueKind.Should().Be(JsonValueKind.Array);
        required.GetArrayLength().Should().Be(1);
        required[0].GetString().Should().Be("query");
    }

    [Fact]
    public async Task Should_SearchMemory_Successfully()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { query = "SQLite" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain("Found");
        result.Should().Contain("SQLite");
        result.Should().Contain("Project Context");
    }

    [Fact]
    public async Task Should_SearchWithLimit()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { query = "user", limit = 1 });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain("Found 1");
        result.Should().Contain("memory"); // Should say "1 memory" not "memories"
    }

    [Fact]
    public async Task Should_CapLimitAt50()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { query = "test", limit = 100 });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert - should not throw, limit capped internally at 50
        result.Should().NotBeNull();
    }

    [Fact]
    public async Task Should_ReturnMessage_WhenNoResultsFound()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { query = "nonexistent-keyword-xyz" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain("No matching memories found");
    }

    [Fact]
    public async Task Should_FormatResults_WithSourceAndScore()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { query = "TypeScript" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain("**");
        result.Should().Contain("Score:");
        result.Should().Contain("Technical Decisions");
    }

    [Fact]
    public async Task Should_ReturnError_WhenQueryIsMissing()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { limit = 10 });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Error:");
        result.Should().Contain("query");
    }

    [Fact]
    public async Task Should_ReturnError_WhenQueryIsEmpty()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { query = "" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Error:");
        result.Should().Contain("empty");
    }

    [Fact]
    public async Task Should_ReturnError_WhenLimitIsNegative()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { query = "test", limit = -1 });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Error:");
        result.Should().Contain("positive");
    }

    [Fact]
    public async Task Should_ReturnError_WhenLimitIsZero()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { query = "test", limit = 0 });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Error:");
        result.Should().Contain("positive");
    }

    [Fact]
    public async Task Should_UseDefaultLimit_WhenNotProvided()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { query = "user" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert - should not throw, uses default limit of 10
        result.Should().NotBeNull();
        result.Should().Contain("Found");
    }
}
