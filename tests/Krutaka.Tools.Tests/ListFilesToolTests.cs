using System.Text.Json;
using FluentAssertions;
using Krutaka.Tools;

namespace Krutaka.Tools.Tests;

public sealed class ListFilesToolTests : IDisposable
{
    private readonly string _testRoot;
    private readonly ListFilesTool _tool;

    public ListFilesToolTests()
    {
        // Use a unique directory for each test run
        var uniqueId = Guid.NewGuid().ToString("N")[..8];
        _testRoot = Path.Combine(Path.GetTempPath(), $"krutaka-listfiles-test-{uniqueId}");
        Directory.CreateDirectory(_testRoot);
        var fileOps = new SafeFileOperations(null);
        _tool = new ListFilesTool(_testRoot, fileOps);
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
        _tool.Name.Should().Be("list_files");
    }

    [Fact]
    public void Should_HaveDescriptionWithKeywords()
    {
        _tool.Description.Should().Contain("Lists");
        _tool.Description.Should().Contain("files");
        _tool.Description.Should().Contain("pattern");
    }

    [Fact]
    public void Should_HaveValidInputSchema()
    {
        var schema = _tool.InputSchema;

        schema.ValueKind.Should().Be(JsonValueKind.Object);
        schema.GetProperty("type").GetString().Should().Be("object");

        var properties = schema.GetProperty("properties");
        properties.TryGetProperty("path", out _).Should().BeTrue();
        properties.TryGetProperty("pattern", out _).Should().BeTrue();
    }

    [Fact]
    public async Task Should_ListAllFilesInRoot()
    {
        // Arrange
        await File.WriteAllTextAsync(Path.Combine(_testRoot, "file1.txt"), "content");
        await File.WriteAllTextAsync(Path.Combine(_testRoot, "file2.txt"), "content");
        await File.WriteAllTextAsync(Path.Combine(_testRoot, "file3.cs"), "content");

        var input = JsonSerializer.SerializeToElement(new { });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain("file1.txt");
        result.Should().Contain("file2.txt");
        result.Should().Contain("file3.cs");
        result.Should().Contain("<untrusted_content>");
        result.Should().Contain("</untrusted_content>");
    }

    [Fact]
    public async Task Should_FilterFilesByPattern()
    {
        // Arrange
        await File.WriteAllTextAsync(Path.Combine(_testRoot, "test1.txt"), "content");
        await File.WriteAllTextAsync(Path.Combine(_testRoot, "test2.txt"), "content");
        await File.WriteAllTextAsync(Path.Combine(_testRoot, "readme.md"), "content");

        var input = JsonSerializer.SerializeToElement(new { pattern = "*.txt" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain("test1.txt");
        result.Should().Contain("test2.txt");
        result.Should().NotContain("readme.md");
    }

    [Fact]
    public async Task Should_SearchRecursively()
    {
        // Arrange
        var subDir = Path.Combine(_testRoot, "subdir");
        Directory.CreateDirectory(subDir);
        await File.WriteAllTextAsync(Path.Combine(_testRoot, "root.txt"), "content");
        await File.WriteAllTextAsync(Path.Combine(subDir, "nested.txt"), "content");

        var input = JsonSerializer.SerializeToElement(new { pattern = "*.txt" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain("root.txt");
        result.Should().Contain("nested.txt");
    }

    [Fact]
    public async Task Should_ListFilesInSpecificDirectory()
    {
        // Arrange
        var subDir = Path.Combine(_testRoot, "specific");
        Directory.CreateDirectory(subDir);
        await File.WriteAllTextAsync(Path.Combine(_testRoot, "root.txt"), "content");
        await File.WriteAllTextAsync(Path.Combine(subDir, "sub.txt"), "content");

        var input = JsonSerializer.SerializeToElement(new { path = "specific" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain("sub.txt");
        result.Should().NotContain("root.txt");
    }

    [Fact]
    public async Task Should_ReturnErrorForNonExistentDirectory()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { path = "nonexistent" });

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
        var input = JsonSerializer.SerializeToElement(new { path = "../../../etc" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Error:");
        result.Should().Contain("Security validation failed");
    }

    [Fact]
    public async Task Should_FilterOutBlockedFiles()
    {
        // Arrange
        await File.WriteAllTextAsync(Path.Combine(_testRoot, "normal.txt"), "content");
        await File.WriteAllTextAsync(Path.Combine(_testRoot, ".env"), "API_KEY=secret");
        await File.WriteAllTextAsync(Path.Combine(_testRoot, "id_rsa"), "private key");

        var input = JsonSerializer.SerializeToElement(new { });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain("normal.txt");
        result.Should().NotContain(".env");
        result.Should().NotContain("id_rsa");
    }

    [Fact]
    public async Task Should_ReturnMessageWhenNoFilesFound()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { pattern = "*.nonexistent" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain("No files found");
    }

    [Fact]
    public async Task Should_UseWildcardPattern()
    {
        // Arrange
        await File.WriteAllTextAsync(Path.Combine(_testRoot, "test1.txt"), "content");
        await File.WriteAllTextAsync(Path.Combine(_testRoot, "test2.txt"), "content");
        await File.WriteAllTextAsync(Path.Combine(_testRoot, "other.txt"), "content");

        var input = JsonSerializer.SerializeToElement(new { pattern = "test*.txt" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain("test1.txt");
        result.Should().Contain("test2.txt");
        result.Should().NotContain("other.txt");
    }

    [Fact]
    public async Task Should_ReturnRelativePaths()
    {
        // Arrange
        var subDir = Path.Combine(_testRoot, "sub");
        Directory.CreateDirectory(subDir);
        await File.WriteAllTextAsync(Path.Combine(subDir, "file.txt"), "content");

        var input = JsonSerializer.SerializeToElement(new { });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain("sub");
        result.Should().Contain("file.txt");
        result.Should().NotContain(_testRoot); // Should not include full path
    }

    [Fact]
    public async Task Should_HandleEmptyDirectory()
    {
        // Arrange
        var emptyDir = Path.Combine(_testRoot, "empty");
        Directory.CreateDirectory(emptyDir);

        var input = JsonSerializer.SerializeToElement(new { path = "empty" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain("No files found");
    }

    [Fact]
    public void Should_ThrowOnNullProjectRoot()
    {
        // Act & Assert
        var fileOps = new SafeFileOperations(null);
        var action = () => new ListFilesTool(null!, fileOps);
        action.Should().Throw<ArgumentNullException>();
    }
}
