using FluentAssertions;
using Krutaka.Memory;

namespace Krutaka.Memory.Tests;

public sealed class MemoryFileServiceTests : IDisposable
{
    private readonly string _testRoot;
    private readonly string _memoryFilePath;
    private readonly MemoryFileService _service;

    public MemoryFileServiceTests()
    {
        // Use CI-safe test directory (avoids LocalAppData and reduces file lock issues)
        _testRoot = TestDirectoryHelper.GetTestDirectory("memoryfile-test");
        Directory.CreateDirectory(_testRoot);
        _memoryFilePath = Path.Combine(_testRoot, "MEMORY.md");
        _service = new MemoryFileService(_memoryFilePath);
    }

    public void Dispose()
    {
        _service.Dispose();
        TestDirectoryHelper.TryDeleteDirectory(_testRoot);
        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task Should_ReturnEmptyString_WhenFileDoesNotExist()
    {
        // Act
        var result = await _service.ReadMemoryAsync();

        // Assert
        result.Should().BeEmpty();
    }

    [Fact]
    public async Task Should_ReadExistingMemoryFile()
    {
        // Arrange
        var content = "## User Preferences\n- Prefers tabs over spaces\n";
        await File.WriteAllTextAsync(_memoryFilePath, content);

        // Act
        var result = await _service.ReadMemoryAsync();

        // Assert
        result.Should().Be(content);
    }

    [Fact]
    public async Task Should_AppendNewSection_WhenSectionDoesNotExist()
    {
        // Act
        var wasAdded = await _service.AppendToMemoryAsync("User Preferences", "Prefers dark mode");

        // Assert
        wasAdded.Should().BeTrue();
        var content = await File.ReadAllTextAsync(_memoryFilePath);
        content.Should().Contain("## User Preferences");
        content.Should().Contain("- Prefers dark mode");
    }

    [Fact]
    public async Task Should_AppendToExistingSection()
    {
        // Arrange
        await _service.AppendToMemoryAsync("Project Context", "Uses .NET 10");

        // Act
        var wasAdded = await _service.AppendToMemoryAsync("Project Context", "Targets Windows x64");

        // Assert
        wasAdded.Should().BeTrue();
        var content = await File.ReadAllTextAsync(_memoryFilePath);
        content.Should().Contain("## Project Context");
        content.Should().Contain("- Uses .NET 10");
        content.Should().Contain("- Targets Windows x64");
    }

    [Fact]
    public async Task Should_PreventDuplicates()
    {
        // Arrange
        await _service.AppendToMemoryAsync("Settings", "Max line length: 120");

        // Act
        var wasAdded = await _service.AppendToMemoryAsync("Settings", "Max line length: 120");

        // Assert
        wasAdded.Should().BeFalse();
        var content = await File.ReadAllTextAsync(_memoryFilePath);
        var occurrences = System.Text.RegularExpressions.Regex.Count(content, "Max line length: 120");
        occurrences.Should().Be(1);
    }

    [Fact]
    public async Task Should_PreventDuplicates_CaseInsensitive()
    {
        // Arrange
        await _service.AppendToMemoryAsync("Settings", "Use strict mode");

        // Act
        var wasAdded = await _service.AppendToMemoryAsync("Settings", "USE STRICT MODE");

        // Assert
        wasAdded.Should().BeFalse();
    }

    [Fact]
    public async Task Should_CreateDirectory_WhenItDoesNotExist()
    {
        // Arrange
        var newPath = Path.Combine(_testRoot, "nested", "dir", "MEMORY.md");
        using var service = new MemoryFileService(newPath);

        // Act
        await service.AppendToMemoryAsync("Test", "Value");

        // Assert
        File.Exists(newPath).Should().BeTrue();
    }

    [Fact]
    public async Task Should_UseAtomicWrites()
    {
        // Arrange
        await _service.AppendToMemoryAsync("Section1", "Value1");

        // Act
        var wasAdded = await _service.AppendToMemoryAsync("Section2", "Value2");

        // Assert
        wasAdded.Should().BeTrue();
        var tempFile = _memoryFilePath + ".tmp";
        File.Exists(tempFile).Should().BeFalse(); // Temp file should be moved, not left behind
        File.Exists(_memoryFilePath).Should().BeTrue();
    }

    [Fact]
    public async Task Should_ThrowArgumentException_WhenKeyIsEmpty()
    {
        // Act
        var act = async () => await _service.AppendToMemoryAsync("", "value");

        // Assert
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task Should_ThrowArgumentException_WhenValueIsEmpty()
    {
        // Act
        var act = async () => await _service.AppendToMemoryAsync("key", "");

        // Assert
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task Should_ThrowArgumentException_WhenPathIsEmpty()
    {
        // Act
        var act = () => new MemoryFileService("");

        // Assert
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public async Task Should_HandleMultipleSections()
    {
        // Arrange
        await _service.AppendToMemoryAsync("Section A", "Item 1");
        await _service.AppendToMemoryAsync("Section B", "Item 2");
        await _service.AppendToMemoryAsync("Section A", "Item 3");

        // Act
        var content = await File.ReadAllTextAsync(_memoryFilePath);

        // Assert
        content.Should().Contain("## Section A");
        content.Should().Contain("## Section B");
        content.Should().Contain("- Item 1");
        content.Should().Contain("- Item 2");
        content.Should().Contain("- Item 3");
    }

    [Fact]
    public async Task Should_SanitizeNewlines_InKey()
    {
        // Arrange - key with newlines should be sanitized
        await _service.AppendToMemoryAsync("Section\nWith\nNewlines", "Value");

        // Act
        var content = await File.ReadAllTextAsync(_memoryFilePath);

        // Assert
        content.Should().Contain("## Section With Newlines");
        content.Should().NotContain("\n\n"); // No double newlines in section header
    }

    [Fact]
    public async Task Should_SanitizeNewlines_InValue()
    {
        // Arrange - value with newlines should be sanitized
        await _service.AppendToMemoryAsync("Settings", "Value\nWith\nNewlines");

        // Act
        var content = await File.ReadAllTextAsync(_memoryFilePath);

        // Assert
        content.Should().Contain("- Value With Newlines");
        var lines = content.Split('\n');
        lines.Should().Contain(l => l.Trim() == "- Value With Newlines");
    }

    [Fact]
    public async Task Should_NotDetectSubstringAsDuplicate()
    {
        // Arrange - "tabs" should not match "Prefers tabs over spaces"
        await _service.AppendToMemoryAsync("Settings", "Prefers tabs over spaces");

        // Act - "tabs" alone should be added, not rejected as duplicate
        var wasAdded = await _service.AppendToMemoryAsync("Settings", "tabs");

        // Assert
        wasAdded.Should().BeTrue();
        var content = await File.ReadAllTextAsync(_memoryFilePath);
        content.Should().Contain("- Prefers tabs over spaces");
        content.Should().Contain("- tabs");
    }
}
