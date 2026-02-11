using System.Security;
using System.Text.Json;
using FluentAssertions;
using Krutaka.Tools;

namespace Krutaka.Tools.Tests;

public sealed class ReadFileToolTests : IDisposable
{
    private readonly string _testRoot;
    private readonly ReadFileTool _tool;

    public ReadFileToolTests()
    {
        // Use a unique directory for each test run
        var uniqueId = Guid.NewGuid().ToString("N")[..8];
        _testRoot = Path.Combine(Path.GetTempPath(), $"krutaka-readfile-test-{uniqueId}");
        Directory.CreateDirectory(_testRoot);
        var fileOps = new SafeFileOperations(null);
        _tool = new ReadFileTool(_testRoot, fileOps);
    }

    public void Dispose()
    {
        // Cleanup test directory
        if (Directory.Exists(_testRoot))
        {
            Directory.Delete(_testRoot, true);
        }

        GC.SuppressFinalize(this);
    }

    [Fact]
    public void Should_HaveCorrectName()
    {
        _tool.Name.Should().Be("read_file");
    }

    [Fact]
    public void Should_HaveDescriptionWithKeywords()
    {
        _tool.Description.Should().Contain("Reads");
        _tool.Description.Should().Contain("file");
        _tool.Description.Should().Contain("1MB");
    }

    [Fact]
    public void Should_HaveValidInputSchema()
    {
        var schema = _tool.InputSchema;

        schema.ValueKind.Should().Be(JsonValueKind.Object);
        schema.GetProperty("type").GetString().Should().Be("object");

        var properties = schema.GetProperty("properties");
        properties.TryGetProperty("path", out var pathProp).Should().BeTrue();
        pathProp.GetProperty("type").GetString().Should().Be("string");

        var required = schema.GetProperty("required");
        required.ValueKind.Should().Be(JsonValueKind.Array);
        required.GetArrayLength().Should().Be(1);
        required[0].GetString().Should().Be("path");
    }

    [Fact]
    public async Task Should_ReadFileSuccessfully()
    {
        // Arrange
        var testFile = Path.Combine(_testRoot, "test.txt");
        var content = "Hello, World!\nThis is a test file.";
        await File.WriteAllTextAsync(testFile, content);

        var input = JsonSerializer.SerializeToElement(new { path = "test.txt" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain("Hello, World!");
        result.Should().Contain("This is a test file.");
        result.Should().Contain("<untrusted_content>");
        result.Should().Contain("</untrusted_content>");
    }

    [Fact]
    public async Task Should_ReadFileWithAbsolutePath()
    {
        // Arrange
        var testFile = Path.Combine(_testRoot, "absolute.txt");
        var content = "Absolute path test";
        await File.WriteAllTextAsync(testFile, content);

        var input = JsonSerializer.SerializeToElement(new { path = testFile });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain("Absolute path test");
        result.Should().Contain("<untrusted_content>");
    }

    [Fact]
    public async Task Should_ReturnErrorForMissingPath()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Error:");
        result.Should().Contain("Missing required parameter 'path'");
    }

    [Fact]
    public async Task Should_ReturnErrorForEmptyPath()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { path = "" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Error:");
        result.Should().Contain("cannot be empty");
    }

    [Fact]
    public async Task Should_ReturnErrorForNonExistentFile()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { path = "nonexistent.txt" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Error:");
        result.Should().Contain("File not found");
    }

    [Fact]
    public async Task Should_BlockPathTraversal()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { path = "../../../etc/passwd" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Error:");
        result.Should().Contain("Security validation failed");
    }

    [Fact]
    public async Task Should_BlockSensitiveFiles()
    {
        // Arrange
        var testFile = Path.Combine(_testRoot, ".env");
        await File.WriteAllTextAsync(testFile, "API_KEY=secret");

        var input = JsonSerializer.SerializeToElement(new { path = ".env" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Error:");
        result.Should().Contain("Security validation failed");
    }

    [Fact]
    public async Task Should_EnforceFileSizeLimit()
    {
        // Arrange
        var testFile = Path.Combine(_testRoot, "large.txt");
        var fileOps = new SafeFileOperations(null);
        var largeContent = new string('x', (int)fileOps.MaxFileSizeBytes + 1);
        await File.WriteAllTextAsync(testFile, largeContent);

        var input = JsonSerializer.SerializeToElement(new { path = "large.txt" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Error:");
        result.Should().Contain("File size validation failed");
    }

    [Fact]
    public async Task Should_ReadFileWithSpecialCharacters()
    {
        // Arrange
        var testFile = Path.Combine(_testRoot, "special.txt");
        var content = "Special chars: <tag>, &amp;, \"quotes\", 'apostrophes'";
        await File.WriteAllTextAsync(testFile, content);

        var input = JsonSerializer.SerializeToElement(new { path = "special.txt" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain("Special chars:");
        result.Should().Contain("<tag>");
        result.Should().Contain("&amp;");
    }

    [Fact]
    public async Task Should_ReadFileFromSubdirectory()
    {
        // Arrange
        var subDir = Path.Combine(_testRoot, "subdir");
        Directory.CreateDirectory(subDir);
        var testFile = Path.Combine(subDir, "nested.txt");
        await File.WriteAllTextAsync(testFile, "Nested file content");

        var input = JsonSerializer.SerializeToElement(new { path = "subdir/nested.txt" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain("Nested file content");
    }

    [Fact]
    public void Should_ThrowOnNullProjectRoot()
    {
        // Act & Assert
        var fileOps = new SafeFileOperations(null);
        var action = () => new ReadFileTool(null!, fileOps);
        action.Should().Throw<ArgumentNullException>();
    }
}
