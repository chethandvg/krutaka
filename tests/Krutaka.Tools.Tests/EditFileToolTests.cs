using System.Text.Json;
using FluentAssertions;
using Krutaka.Tools;

namespace Krutaka.Tools.Tests;

internal sealed class EditFileToolTests : IDisposable
{
    private readonly string _testRoot;
    private readonly EditFileTool _tool;

    public EditFileToolTests()
    {
        // Use a unique directory for each test run
        var uniqueId = Guid.NewGuid().ToString("N")[..8];
        _testRoot = Path.Combine(Path.GetTempPath(), $"krutaka-editfile-test-{uniqueId}");
        Directory.CreateDirectory(_testRoot);
        _tool = new EditFileTool(_testRoot);
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
        _tool.Name.Should().Be("edit_file");
    }

    [Fact]
    public void Should_HaveDescriptionWithKeywords()
    {
        _tool.Description.Should().Contain("Edits");
        _tool.Description.Should().Contain("line range");
        _tool.Description.Should().Contain("backup");
        _tool.Description.Should().Contain("diff");
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

        properties.TryGetProperty("start_line", out var startLineProp).Should().BeTrue();
        startLineProp.GetProperty("type").GetString().Should().Be("integer");

        properties.TryGetProperty("end_line", out var endLineProp).Should().BeTrue();
        endLineProp.GetProperty("type").GetString().Should().Be("integer");

        var required = schema.GetProperty("required");
        required.ValueKind.Should().Be(JsonValueKind.Array);
        required.GetArrayLength().Should().Be(4);
    }

    [Fact]
    public async Task Should_ReplaceSingleLine()
    {
        // Arrange
        var testFile = "edit-single.txt";
        var fullPath = Path.Combine(_testRoot, testFile);
        var originalContent = "Line 1\nLine 2\nLine 3";
        await File.WriteAllTextAsync(fullPath, originalContent);

        var input = JsonSerializer.SerializeToElement(new
        {
            path = testFile,
            content = "Modified Line 2",
            start_line = 2,
            end_line = 2
        });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Successfully edited file:");
        result.Should().Contain("Diff:");

        var editedContent = await File.ReadAllTextAsync(fullPath);
        editedContent.Should().Be("Line 1\nModified Line 2\nLine 3");
    }

    [Fact]
    public async Task Should_ReplaceMultipleLines()
    {
        // Arrange
        var testFile = "edit-multiple.txt";
        var fullPath = Path.Combine(_testRoot, testFile);
        var originalContent = "Line 1\nLine 2\nLine 3\nLine 4\nLine 5";
        await File.WriteAllTextAsync(fullPath, originalContent);

        var input = JsonSerializer.SerializeToElement(new
        {
            path = testFile,
            content = "Modified Lines 2-4",
            start_line = 2,
            end_line = 4
        });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Successfully edited file:");
        result.Should().Contain("Diff:");

        var editedContent = await File.ReadAllTextAsync(fullPath);
        editedContent.Should().Be("Line 1\nModified Lines 2-4\nLine 5");
    }

    [Fact]
    public async Task Should_ReplaceFirstLine()
    {
        // Arrange
        var testFile = "edit-first.txt";
        var fullPath = Path.Combine(_testRoot, testFile);
        var originalContent = "Line 1\nLine 2\nLine 3";
        await File.WriteAllTextAsync(fullPath, originalContent);

        var input = JsonSerializer.SerializeToElement(new
        {
            path = testFile,
            content = "Modified Line 1",
            start_line = 1,
            end_line = 1
        });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Successfully edited file:");

        var editedContent = await File.ReadAllTextAsync(fullPath);
        editedContent.Should().Be("Modified Line 1\nLine 2\nLine 3");
    }

    [Fact]
    public async Task Should_ReplaceLastLine()
    {
        // Arrange
        var testFile = "edit-last.txt";
        var fullPath = Path.Combine(_testRoot, testFile);
        var originalContent = "Line 1\nLine 2\nLine 3";
        await File.WriteAllTextAsync(fullPath, originalContent);

        var input = JsonSerializer.SerializeToElement(new
        {
            path = testFile,
            content = "Modified Line 3",
            start_line = 3,
            end_line = 3
        });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Successfully edited file:");

        var editedContent = await File.ReadAllTextAsync(fullPath);
        editedContent.Should().Be("Line 1\nLine 2\nModified Line 3");
    }

    [Fact]
    public async Task Should_CreateBackupBeforeEditing()
    {
        // Arrange
        var testFile = "backup-test.txt";
        var fullPath = Path.Combine(_testRoot, testFile);
        var originalContent = "Original Line 1\nOriginal Line 2";
        await File.WriteAllTextAsync(fullPath, originalContent);

        var input = JsonSerializer.SerializeToElement(new
        {
            path = testFile,
            content = "Modified",
            start_line = 1,
            end_line = 1
        });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Successfully edited file:");

        // Check that backup was created
        var backupDir = Path.Combine(Path.GetTempPath(), "krutaka-backups");
        Directory.Exists(backupDir).Should().BeTrue();
        var backupFiles = Directory.GetFiles(backupDir, $"{testFile}.*.bak");
        backupFiles.Should().NotBeEmpty();
    }

    [Fact]
    public async Task Should_ReturnDiff()
    {
        // Arrange
        var testFile = "diff-test.txt";
        var fullPath = Path.Combine(_testRoot, testFile);
        var originalContent = "Line 1\nLine 2\nLine 3";
        await File.WriteAllTextAsync(fullPath, originalContent);

        var input = JsonSerializer.SerializeToElement(new
        {
            path = testFile,
            content = "Modified Line 2",
            start_line = 2,
            end_line = 2
        });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().Contain("Diff:");
        result.Should().Contain("-");  // Removed line indicator
        result.Should().Contain("+");  // Added line indicator
        result.Should().Contain("Line 2");  // Original content
        result.Should().Contain("Modified Line 2");  // New content
    }

    [Fact]
    public async Task Should_ReturnErrorForMissingPath()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new
        {
            content = "test",
            start_line = 1,
            end_line = 1
        });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Error:");
        result.Should().Contain("Missing required parameter 'path'");
    }

    [Fact]
    public async Task Should_ReturnErrorForMissingContent()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new
        {
            path = "test.txt",
            start_line = 1,
            end_line = 1
        });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Error:");
        result.Should().Contain("Missing required parameter 'content'");
    }

    [Fact]
    public async Task Should_ReturnErrorForMissingStartLine()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new
        {
            path = "test.txt",
            content = "test",
            end_line = 1
        });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Error:");
        result.Should().Contain("Missing required parameter 'start_line'");
    }

    [Fact]
    public async Task Should_ReturnErrorForMissingEndLine()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new
        {
            path = "test.txt",
            content = "test",
            start_line = 1
        });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Error:");
        result.Should().Contain("Missing required parameter 'end_line'");
    }

    [Fact]
    public async Task Should_ReturnErrorForNonExistentFile()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new
        {
            path = "nonexistent.txt",
            content = "test",
            start_line = 1,
            end_line = 1
        });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Error:");
        result.Should().Contain("File not found");
    }

    [Fact]
    public async Task Should_ReturnErrorForInvalidLineRange_StartLineTooSmall()
    {
        // Arrange
        var testFile = "invalid-range.txt";
        var fullPath = Path.Combine(_testRoot, testFile);
        await File.WriteAllTextAsync(fullPath, "Line 1");

        var input = JsonSerializer.SerializeToElement(new
        {
            path = testFile,
            content = "test",
            start_line = 0,
            end_line = 1
        });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Error:");
        result.Should().Contain("start_line must be >= 1");
    }

    [Fact]
    public async Task Should_ReturnErrorForInvalidLineRange_EndLineBeforeStartLine()
    {
        // Arrange
        var testFile = "invalid-range2.txt";
        var fullPath = Path.Combine(_testRoot, testFile);
        await File.WriteAllTextAsync(fullPath, "Line 1\nLine 2");

        var input = JsonSerializer.SerializeToElement(new
        {
            path = testFile,
            content = "test",
            start_line = 2,
            end_line = 1
        });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Error:");
        result.Should().Contain("end_line must be >= start_line");
    }

    [Fact]
    public async Task Should_ReturnErrorForLineRangeExceedingFileLength()
    {
        // Arrange
        var testFile = "short-file.txt";
        var fullPath = Path.Combine(_testRoot, testFile);
        await File.WriteAllTextAsync(fullPath, "Line 1\nLine 2");

        var input = JsonSerializer.SerializeToElement(new
        {
            path = testFile,
            content = "test",
            start_line = 3,
            end_line = 3
        });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Error:");
        result.Should().Contain("exceeds file length");
    }

    [Fact]
    public async Task Should_BlockPathTraversal()
    {
        // Arrange
        var input = JsonSerializer.SerializeToElement(new
        {
            path = "../../../etc/passwd",
            content = "malicious",
            start_line = 1,
            end_line = 1
        });

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
        var input = JsonSerializer.SerializeToElement(new
        {
            path = ".env",
            content = "API_KEY=secret",
            start_line = 1,
            end_line = 1
        });

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
        var testFile = "large.txt";
        var fullPath = Path.Combine(_testRoot, testFile);
        var largeContent = new string('x', (int)SafeFileOperations.MaxFileSizeBytes + 1);
        await File.WriteAllTextAsync(fullPath, largeContent);

        var input = JsonSerializer.SerializeToElement(new
        {
            path = testFile,
            content = "test",
            start_line = 1,
            end_line = 1
        });

        // Act
        var result = await _tool.ExecuteAsync(input, CancellationToken.None);

        // Assert
        result.Should().StartWith("Error:");
        result.Should().Contain("File size validation failed");
    }

    [Fact]
    public void Should_ThrowOnNullProjectRoot()
    {
        // Act & Assert
        var action = () => new EditFileTool(null!);
        action.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Should_RequireApproval()
    {
        // This test verifies that the tool name matches the approval matrix in CommandPolicy
        var policy = new CommandPolicy();
        var requiresApproval = policy.IsApprovalRequired(_tool.Name);

        // Assert
        requiresApproval.Should().BeTrue("edit_file is a destructive operation and must require human approval");
    }
}
