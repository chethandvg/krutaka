using System.Security;
using System.Text.Json;
using FluentAssertions;
using Krutaka.Tools;

namespace Krutaka.Tools.Tests;

public sealed class WriteFileToolTests : IDisposable
{
    private readonly string _testRoot;
    private readonly WriteFileTool _tool;

    public WriteFileToolTests()
    {
        // Use a unique directory for each test run
        var uniqueId = Guid.NewGuid().ToString("N")[..8];
        _testRoot = Path.Combine(Path.GetTempPath(), $"krutaka-writefile-test-{uniqueId}");
        Directory.CreateDirectory(_testRoot);
        _tool = new WriteFileTool(_testRoot);
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
        _tool.Name.Should().Be("write_file");
    }

    [Fact]
    public void Should_HaveDescriptionWithKeywords()
    {
        _tool.Description.Should().Contain("Creates");
        _tool.Description.Should().Contain("overwrites");
        _tool.Description.Should().Contain("backup");
        _tool.Description.Should().Contain("approval");
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

        properties.TryGetProperty("content", out var contentProp).Should().BeTrue();
        contentProp.GetProperty("type").GetString().Should().Be("string");

        var required = schema.GetProperty("required");
        required.ValueKind.Should().Be(JsonValueKind.Array);
        required.GetArrayLength().Should().Be(2);
        var requiredArray = required.EnumerateArray().Select(e => e.GetString()).ToArray();
        requiredArray.Should().Contain("path");
        requiredArray.Should().Contain("content");
    }

    [Fact]
    public async Task Should_CreateNewFile()
    {
        // Arrange
        var testFile = "newfile.txt";
        var content = "Hello, World!";
        var input = JsonSerializer.SerializeToElement(new { path = testFile, content });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Successfully wrote file:");
        result.Should().Contain(testFile);

        var fullPath = Path.Combine(_testRoot, testFile);
        File.Exists(fullPath).Should().BeTrue();
        var writtenContent = await File.ReadAllTextAsync(fullPath);
        writtenContent.Should().Be(content);
    }

    [Fact]
    public async Task Should_OverwriteExistingFile()
    {
        // Arrange
        var testFile = "existing.txt";
        var fullPath = Path.Combine(_testRoot, testFile);
        await File.WriteAllTextAsync(fullPath, "Old content");

        var newContent = "New content";
        var input = JsonSerializer.SerializeToElement(new { path = testFile, content = newContent });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Successfully wrote file:");
        var writtenContent = await File.ReadAllTextAsync(fullPath);
        writtenContent.Should().Be(newContent);
    }

    [Fact]
    public async Task Should_CreateBackupWhenOverwriting()
    {
        // Arrange
        var testFile = "backup-test.txt";
        var fullPath = Path.Combine(_testRoot, testFile);
        var originalContent = "Original content";
        await File.WriteAllTextAsync(fullPath, originalContent);

        var newContent = "New content";
        var input = JsonSerializer.SerializeToElement(new { path = testFile, content = newContent });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Successfully wrote file:");

        // Check that backup was created (in temp directory)
        var backupDir = Path.Combine(Path.GetTempPath(), "krutaka-backups");
        Directory.Exists(backupDir).Should().BeTrue();
        var backupFiles = Directory.GetFiles(backupDir, $"{testFile}.*.bak");
        backupFiles.Should().NotBeEmpty();
    }

    [Fact]
    public async Task Should_CreateParentDirectories()
    {
        // Arrange
        var testFile = "subdir/nested/file.txt";
        var content = "Nested content";
        var input = JsonSerializer.SerializeToElement(new { path = testFile, content });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Successfully wrote file:");

        var fullPath = Path.Combine(_testRoot, testFile);
        File.Exists(fullPath).Should().BeTrue();
        var writtenContent = await File.ReadAllTextAsync(fullPath);
        writtenContent.Should().Be(content);
    }

    [Fact]
    public async Task Should_WriteFileWithAbsolutePath()
    {
        // Arrange
        var testFile = Path.Combine(_testRoot, "absolute.txt");
        var content = "Absolute path test";
        var input = JsonSerializer.SerializeToElement(new { path = testFile, content });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Successfully wrote file:");
        File.Exists(testFile).Should().BeTrue();
        var writtenContent = await File.ReadAllTextAsync(testFile);
        writtenContent.Should().Be(content);
    }

    [Fact]
    public async Task Should_ReturnErrorForMissingPath()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { content = "test" });

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
        var input = JsonSerializer.SerializeToElement(new { path = "", content = "test" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Error:");
        result.Should().Contain("cannot be empty");
    }

    [Fact]
    public async Task Should_ReturnErrorForMissingContent()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { path = "test.txt" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Error:");
        result.Should().Contain("Missing required parameter 'content'");
    }

    [Fact]
    public async Task Should_BlockPathTraversal()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new { path = "../../../etc/passwd", content = "malicious" });

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
        var input = JsonSerializer.SerializeToElement(new { path = ".env", content = "API_KEY=secret" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Error:");
        result.Should().Contain("Security validation failed");
    }

    [Fact]
    public async Task Should_WriteEmptyContent()
    {
        // Arrange
        var testFile = "empty.txt";
        var input = JsonSerializer.SerializeToElement(new { path = testFile, content = "" });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Successfully wrote file:");

        var fullPath = Path.Combine(_testRoot, testFile);
        File.Exists(fullPath).Should().BeTrue();
        var writtenContent = await File.ReadAllTextAsync(fullPath);
        writtenContent.Should().BeEmpty();
    }

    [Fact]
    public async Task Should_WriteSpecialCharacters()
    {
        // Arrange
        var testFile = "special.txt";
        var content = "Special chars: <tag>, &amp;, \"quotes\", 'apostrophes', \n newlines";
        var input = JsonSerializer.SerializeToElement(new { path = testFile, content });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Successfully wrote file:");

        var fullPath = Path.Combine(_testRoot, testFile);
        var writtenContent = await File.ReadAllTextAsync(fullPath);
        writtenContent.Should().Be(content);
    }

    [Fact]
    public void Should_ThrowOnNullProjectRoot()
    {
        // Act & Assert
        var action = () => new WriteFileTool(null!);
        action.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Should_RequireApproval()
    {
        // This test verifies that the tool name matches the approval matrix in CommandPolicy
        var policy = new CommandPolicy();
        var requiresApproval = policy.IsApprovalRequired(_tool.Name);

        // Assert
        requiresApproval.Should().BeTrue("write_file is a destructive operation and must require human approval");
    }
}
