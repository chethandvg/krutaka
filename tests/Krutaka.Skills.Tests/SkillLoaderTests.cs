using FluentAssertions;
using Krutaka.Skills;

namespace Krutaka.Skills.Tests;

public class SkillLoaderTests : IDisposable
{
    private readonly string _testDirectory;
    private readonly SkillLoader _loader;

    public SkillLoaderTests()
    {
        // Use CI-safe test directory (avoids LocalAppData restrictions)
        _testDirectory = TestDirectoryHelper.GetTestDirectory("skill-tests");
        Directory.CreateDirectory(_testDirectory);
        _loader = new SkillLoader();
    }

    public void Dispose()
    {
        TestDirectoryHelper.TryDeleteDirectory(_testDirectory);
        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task Should_ParseValidYamlFrontmatter()
    {
        // Arrange
        var skillFile = Path.Combine(_testDirectory, "SKILL.md");
        var content = """
            ---
            name: test-skill
            description: A test skill for validation
            allowed-tools: read_file,write_file
            model: claude-sonnet-4
            version: 1.0.0
            ---
            
            # Test Skill
            
            This is the skill content.
            """;
        await File.WriteAllTextAsync(skillFile, content);

        // Act
        var (metadata, fullContent) = await _loader.LoadSkillAsync(skillFile);

        // Assert
        metadata.Name.Should().Be("test-skill");
        metadata.Description.Should().Be("A test skill for validation");
        metadata.AllowedTools.Should().NotBeNull();
        metadata.AllowedTools.Should().HaveCount(2);
        metadata.AllowedTools.Should().Contain("read_file");
        metadata.AllowedTools.Should().Contain("write_file");
        metadata.Model.Should().Be("claude-sonnet-4");
        metadata.Version.Should().Be("1.0.0");
        metadata.FilePath.Should().Be(skillFile);
        fullContent.Should().Be(content);
    }

    [Fact]
    public async Task Should_ParseYamlFrontmatter_WithMinimalFields()
    {
        // Arrange
        var skillFile = Path.Combine(_testDirectory, "SKILL.md");
        var content = """
            ---
            name: minimal-skill
            description: Minimal skill with only required fields
            ---
            
            # Minimal Skill
            """;
        await File.WriteAllTextAsync(skillFile, content);

        // Act
        var (metadata, _) = await _loader.LoadSkillAsync(skillFile);

        // Assert
        metadata.Name.Should().Be("minimal-skill");
        metadata.Description.Should().Be("Minimal skill with only required fields");
        metadata.AllowedTools.Should().BeNull();
        metadata.Model.Should().BeNull();
        metadata.Version.Should().BeNull();
    }

    [Fact]
    public async Task Should_ThrowException_WhenNameIsMissing()
    {
        // Arrange
        var skillFile = Path.Combine(_testDirectory, "SKILL.md");
        var content = """
            ---
            description: Skill without name
            ---
            
            # Test
            """;
        await File.WriteAllTextAsync(skillFile, content);

        // Act
        var act = async () => await _loader.LoadSkillAsync(skillFile);

        // Assert
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*missing required 'name' field*");
    }

    [Fact]
    public async Task Should_ThrowException_WhenDescriptionIsMissing()
    {
        // Arrange
        var skillFile = Path.Combine(_testDirectory, "SKILL.md");
        var content = """
            ---
            name: test-skill
            ---
            
            # Test
            """;
        await File.WriteAllTextAsync(skillFile, content);

        // Act
        var act = async () => await _loader.LoadSkillAsync(skillFile);

        // Assert
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*missing required 'description' field*");
    }

    [Fact]
    public async Task Should_ThrowException_WhenFrontmatterIsMissing()
    {
        // Arrange
        var skillFile = Path.Combine(_testDirectory, "SKILL.md");
        var content = """
            # Test Skill
            
            No frontmatter here.
            """;
        await File.WriteAllTextAsync(skillFile, content);

        // Act
        var act = async () => await _loader.LoadSkillAsync(skillFile);

        // Assert
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*missing YAML frontmatter*");
    }

    [Fact]
    public async Task Should_ThrowException_WhenFrontmatterIsNotClosed()
    {
        // Arrange
        var skillFile = Path.Combine(_testDirectory, "SKILL.md");
        var content = """
            ---
            name: test-skill
            description: Test
            
            # Missing closing delimiter
            """;
        await File.WriteAllTextAsync(skillFile, content);

        // Act
        var act = async () => await _loader.LoadSkillAsync(skillFile);

        // Assert
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*malformed YAML frontmatter*");
    }

    [Fact]
    public async Task Should_ThrowException_WhenYamlIsInvalid()
    {
        // Arrange
        var skillFile = Path.Combine(_testDirectory, "SKILL.md");
        var content = """
            ---
            name: test-skill
            description: [invalid yaml structure without closing bracket
            ---
            
            # Test
            """;
        await File.WriteAllTextAsync(skillFile, content);

        // Act
        var act = async () => await _loader.LoadSkillAsync(skillFile);

        // Assert
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*Failed to parse YAML frontmatter*");
    }

    [Fact]
    public async Task Should_ThrowException_WhenFileDoesNotExist()
    {
        // Arrange
        var nonExistentFile = Path.Combine(_testDirectory, "nonexistent.md");

        // Act
        var act = async () => await _loader.LoadSkillAsync(nonExistentFile);

        // Assert
        await act.Should().ThrowAsync<FileNotFoundException>();
    }

    [Fact]
    public async Task Should_SplitAllowedTools_CorrectlyWithSpaces()
    {
        // Arrange
        var skillFile = Path.Combine(_testDirectory, "SKILL.md");
        var content = """
            ---
            name: test-skill
            description: Test skill
            allowed-tools: read_file, write_file, search_files
            ---
            
            # Test
            """;
        await File.WriteAllTextAsync(skillFile, content);

        // Act
        var (metadata, _) = await _loader.LoadSkillAsync(skillFile);

        // Assert
        metadata.AllowedTools.Should().NotBeNull();
        metadata.AllowedTools.Should().HaveCount(3);
        metadata.AllowedTools.Should().Contain("read_file");
        metadata.AllowedTools.Should().Contain("write_file");
        metadata.AllowedTools.Should().Contain("search_files");
    }
}
