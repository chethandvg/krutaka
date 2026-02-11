using System.Text.Json;
using FluentAssertions;
using Krutaka.Core;
using Krutaka.Memory;

namespace Krutaka.Memory.Tests;

public sealed class MemoryStoreToolTests : IDisposable
{
    private readonly string _testRoot;
    private readonly string _memoryFilePath;
    private readonly MemoryFileService _memoryFileService;
    private readonly SqliteMemoryStore _memoryService;
    private readonly MemoryStoreTool _tool;

    public MemoryStoreToolTests()
    {
        // Use CI-safe test directory (avoids LocalAppData and reduces SQLite lock issues)
        _testRoot = TestDirectoryHelper.GetTestDirectory("memorystore-test");
        Directory.CreateDirectory(_testRoot);
        _memoryFilePath = Path.Combine(_testRoot, "MEMORY.md");

        _memoryFileService = new MemoryFileService(_memoryFilePath);

        // Create file-based SQLite database for testing (in-memory doesn't work well with FTS5)
        var dbPath = Path.Combine(_testRoot, "test.db");
        var options = new MemoryOptions
        {
            DatabasePath = dbPath,
            ChunkSizeTokens = 500,
            ChunkOverlapTokens = 50
        };
        _memoryService = new SqliteMemoryStore(options);
        _memoryService.InitializeAsync().GetAwaiter().GetResult();

        _tool = new MemoryStoreTool(_memoryFileService, _memoryService);
    }

    public void Dispose()
    {
        _memoryFileService.Dispose();
        _memoryService.Dispose();

        // Force garbage collection to release SQLite connections
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        // Use helper with longer delays for SQLite file locks
        TestDirectoryHelper.TryDeleteDirectory(_testRoot);

        GC.SuppressFinalize(this);
    }

    [Fact]
    public void Should_HaveCorrectName()
    {
        _tool.Name.Should().Be("memory_store");
    }

    [Fact]
    public void Should_HaveDescriptionWithKeywords()
    {
        _tool.Description.Should().Contain("Store");
        _tool.Description.Should().Contain("memory");
        _tool.Description.Should().Contain("MEMORY.md");
    }

    [Fact]
    public void Should_HaveValidInputSchema()
    {
        var schema = _tool.InputSchema;

        schema.ValueKind.Should().Be(JsonValueKind.Object);
        schema.GetProperty("type").GetString().Should().Be("object");

        var properties = schema.GetProperty("properties");
        properties.TryGetProperty("key", out var keyProp).Should().BeTrue();
        keyProp.GetProperty("type").GetString().Should().Be("string");

        properties.TryGetProperty("value", out var valueProp).Should().BeTrue();
        valueProp.GetProperty("type").GetString().Should().Be("string");

        var required = schema.GetProperty("required");
        required.ValueKind.Should().Be(JsonValueKind.Array);
        required.GetArrayLength().Should().Be(2);
    }

    [Fact]
    public async Task Should_StoreMemory_Successfully()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new
        {
            key = "User Preferences",
            value = "Prefers TypeScript over JavaScript"
        });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain("Successfully stored");
        result.Should().Contain("User Preferences");

        // Verify MEMORY.md was updated
        var memoryContent = await _memoryFileService.ReadMemoryAsync();
        memoryContent.Should().Contain("## User Preferences");
        memoryContent.Should().Contain("- Prefers TypeScript over JavaScript");
    }

    [Fact]
    public async Task Should_IndexIntoSqlite()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new
        {
            key = "Project Context",
            value = "Uses SQLite for local storage and FTS5 for search"
        });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain("Successfully stored");

        // Verify indexed into SQLite (use single keyword for better match)
        var searchResults = await _memoryService.HybridSearchAsync("SQLite", topK: 10);
        searchResults.Should().NotBeEmpty();
    }

    [Fact]
    public async Task Should_ReturnMessage_WhenDuplicateDetected()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new
        {
            key = "Settings",
            value = "Max line length: 120"
        });

        await _tool.ExecuteAsync(input, CancellationToken.None);

        // Act - try to add duplicate
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain("not added");
        result.Should().Contain("already exists");
    }

    [Fact]
    public async Task Should_ReturnError_WhenKeyIsMissing()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { value = "test value" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Error:");
        result.Should().Contain("key");
    }

    [Fact]
    public async Task Should_ReturnError_WhenValueIsMissing()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { key = "test key" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Error:");
        result.Should().Contain("value");
    }

    [Fact]
    public async Task Should_ReturnError_WhenKeyIsEmpty()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { key = "", value = "test value" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Error:");
        result.Should().Contain("empty");
    }

    [Fact]
    public async Task Should_ReturnError_WhenValueIsEmpty()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { key = "test key", value = "" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Error:");
        result.Should().Contain("empty");
    }
}
