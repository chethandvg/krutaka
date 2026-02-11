using System.Text.Json;
using FluentAssertions;
using Krutaka.Tools;

namespace Krutaka.Tools.Tests;

public sealed class SearchFilesToolTests : IDisposable
{
    private readonly string _testRoot;
    private readonly SearchFilesTool _tool;

    public SearchFilesToolTests()
    {
        // Use a unique directory for each test run
        var uniqueId = Guid.NewGuid().ToString("N")[..8];
        _testRoot = Path.Combine(Path.GetTempPath(), $"krutaka-searchfiles-test-{uniqueId}");
        Directory.CreateDirectory(_testRoot);
        var fileOps = new SafeFileOperations(null);
        _tool = new SearchFilesTool(_testRoot, fileOps);
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
        _tool.Name.Should().Be("search_files");
    }

    [Fact]
    public void Should_HaveDescriptionWithKeywords()
    {
        _tool.Description.Should().Contain("Searches");
        _tool.Description.Should().Contain("pattern");
        _tool.Description.Should().Contain("files");
    }

    [Fact]
    public void Should_HaveValidInputSchema()
    {
        var schema = _tool.InputSchema;

        schema.ValueKind.Should().Be(JsonValueKind.Object);
        schema.GetProperty("type").GetString().Should().Be("object");

        var properties = schema.GetProperty("properties");
        properties.TryGetProperty("pattern", out var patternProp).Should().BeTrue();
        patternProp.GetProperty("type").GetString().Should().Be("string");

        var required = schema.GetProperty("required");
        required.ValueKind.Should().Be(JsonValueKind.Array);
        required[0].GetString().Should().Be("pattern");
    }

    [Fact]
    public async Task Should_FindTextInSingleFile()
    {
        // Arrange
        var testFile = Path.Combine(_testRoot, "test.txt");
        await File.WriteAllTextAsync(testFile, "Line 1\nHello World\nLine 3");

        var input = JsonSerializer.SerializeToElement(new { pattern = "Hello" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain("test.txt");
        result.Should().Contain("2:"); // Line number
        result.Should().Contain("Hello World");
        result.Should().Contain("Found 1 match");
        result.Should().Contain("<untrusted_content>");
        result.Should().Contain("</untrusted_content>");
    }

    [Fact]
    public async Task Should_FindTextInMultipleFiles()
    {
        // Arrange
        await File.WriteAllTextAsync(Path.Combine(_testRoot, "file1.txt"), "Hello World");
        await File.WriteAllTextAsync(Path.Combine(_testRoot, "file2.txt"), "Goodbye World\nHello Again");

        var input = JsonSerializer.SerializeToElement(new { pattern = "Hello" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain("file1.txt");
        result.Should().Contain("file2.txt");
        result.Should().Contain("Found 2 match");
    }

    [Fact]
    public async Task Should_SearchCaseInsensitiveByDefault()
    {
        // Arrange
        await File.WriteAllTextAsync(Path.Combine(_testRoot, "test.txt"), "HELLO world");

        var input = JsonSerializer.SerializeToElement(new { pattern = "hello" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain("HELLO world");
    }

    [Fact]
    public async Task Should_SearchCaseSensitiveWhenRequested()
    {
        // Arrange
        await File.WriteAllTextAsync(Path.Combine(_testRoot, "test.txt"), "HELLO\nhello");

        var input = JsonSerializer.SerializeToElement(new { pattern = "hello", case_sensitive = true });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain("2:"); // Only line 2
        result.Should().NotContain("1:"); // Not line 1
    }

    [Fact]
    public async Task Should_SupportRegexSearch()
    {
        // Arrange
        await File.WriteAllTextAsync(Path.Combine(_testRoot, "test.txt"), "test123\ntest456\nabc789");

        var input = JsonSerializer.SerializeToElement(new { pattern = "test\\d+", regex = true });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain("test123");
        result.Should().Contain("test456");
        result.Should().NotContain("abc789");
    }

    [Fact]
    public async Task Should_ReturnErrorForInvalidRegex()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { pattern = "[invalid(", regex = true });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Error:");
        result.Should().Contain("Invalid regex pattern");
    }

    [Fact]
    public async Task Should_FilterByFilePattern()
    {
        // Arrange
        await File.WriteAllTextAsync(Path.Combine(_testRoot, "test.txt"), "Hello");
        await File.WriteAllTextAsync(Path.Combine(_testRoot, "test.cs"), "Hello");

        var input = JsonSerializer.SerializeToElement(new { pattern = "Hello", file_pattern = "*.txt" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain("test.txt");
        result.Should().NotContain("test.cs");
    }

    [Fact]
    public async Task Should_SearchInSubdirectories()
    {
        // Arrange
        var subDir = Path.Combine(_testRoot, "subdir");
        Directory.CreateDirectory(subDir);
        await File.WriteAllTextAsync(Path.Combine(_testRoot, "root.txt"), "Hello");
        await File.WriteAllTextAsync(Path.Combine(subDir, "nested.txt"), "Hello");

        var input = JsonSerializer.SerializeToElement(new { pattern = "Hello" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain("root.txt");
        result.Should().Contain("nested.txt");
    }

    [Fact]
    public async Task Should_SearchInSpecificDirectory()
    {
        // Arrange
        var subDir = Path.Combine(_testRoot, "specific");
        Directory.CreateDirectory(subDir);
        await File.WriteAllTextAsync(Path.Combine(_testRoot, "root.txt"), "Hello");
        await File.WriteAllTextAsync(Path.Combine(subDir, "sub.txt"), "Hello");

        var input = JsonSerializer.SerializeToElement(new { pattern = "Hello", path = "specific" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain("sub.txt");
        result.Should().NotContain("root.txt");
    }

    [Fact]
    public async Task Should_ReturnErrorForMissingPattern()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Error:");
        result.Should().Contain("Missing required parameter 'pattern'");
    }

    [Fact]
    public async Task Should_ReturnErrorForEmptyPattern()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { pattern = "" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Error:");
        result.Should().Contain("cannot be empty");
    }

    [Fact]
    public async Task Should_ReturnErrorForNonExistentDirectory()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { pattern = "test", path = "nonexistent" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Error:");
        result.Should().Contain("Directory not found");
    }

    [Fact]
    public async Task Should_BlockPathTraversal()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { pattern = "test", path = "../../../etc" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Error:");
        result.Should().Contain("Security validation failed");
    }

    [Fact]
    public async Task Should_SkipBlockedFiles()
    {
        // Arrange
        await File.WriteAllTextAsync(Path.Combine(_testRoot, "normal.txt"), "Hello");
        await File.WriteAllTextAsync(Path.Combine(_testRoot, ".env"), "Hello");

        var input = JsonSerializer.SerializeToElement(new { pattern = "Hello" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain("normal.txt");
        result.Should().NotContain(".env");
    }

    [Fact]
    public async Task Should_SkipFilesOverSizeLimit()
    {
        // Arrange
        var smallFile = Path.Combine(_testRoot, "small.txt");
        var largeFile = Path.Combine(_testRoot, "large.txt");
        await File.WriteAllTextAsync(smallFile, "Hello");
        var fileOps = new SafeFileOperations(null);
        await File.WriteAllTextAsync(largeFile, new string('x', (int)fileOps.MaxFileSizeBytes + 1));

        var input = JsonSerializer.SerializeToElement(new { pattern = "Hello" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain("small.txt");
        result.Should().NotContain("large.txt");
    }

    [Fact]
    public async Task Should_ReturnMessageWhenNoMatchesFound()
    {
        // Arrange
        await File.WriteAllTextAsync(Path.Combine(_testRoot, "test.txt"), "Goodbye");

        var input = JsonSerializer.SerializeToElement(new { pattern = "Hello" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain("No matches found");
    }

    [Fact]
    public async Task Should_ShowCorrectLineNumbers()
    {
        // Arrange
        await File.WriteAllTextAsync(Path.Combine(_testRoot, "test.txt"),
            "Line 1\nLine 2 Hello\nLine 3\nLine 4 Hello\nLine 5");

        var input = JsonSerializer.SerializeToElement(new { pattern = "Hello" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain("2:"); // First match on line 2
        result.Should().Contain("4:"); // Second match on line 4
        result.Should().NotContain("1:");
        result.Should().NotContain("3:");
        result.Should().NotContain("5:");
    }

    [Fact]
    public void Should_ThrowOnNullProjectRoot()
    {
        // Act & Assert
        var fileOps = new SafeFileOperations(null);
        var action = () => new SearchFilesTool(null!, fileOps);
        action.Should().Throw<ArgumentNullException>();
    }
}
