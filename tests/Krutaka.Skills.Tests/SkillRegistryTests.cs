using FluentAssertions;
using Krutaka.Skills;

namespace Krutaka.Skills.Tests;

public class SkillRegistryTests : IDisposable
{
    private readonly string _testDirectory;
    private readonly SkillLoader _loader;

    public SkillRegistryTests()
    {
        // Use CI-safe test directory (avoids LocalAppData restrictions)
        _testDirectory = TestDirectoryHelper.GetTestDirectory("registry-tests");
        Directory.CreateDirectory(_testDirectory);
        _loader = new SkillLoader();
    }

    public void Dispose()
    {
        TestDirectoryHelper.TryDeleteDirectory(_testDirectory);
        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task Should_LoadMetadata_FromSkillDirectory()
    {
        // Arrange
        var skillDir = Path.Combine(_testDirectory, "test-skill");
        Directory.CreateDirectory(skillDir);
        var skillFile = Path.Combine(skillDir, "SKILL.md");
        var content = """
            ---
            name: test-skill
            description: A test skill
            ---
            
            # Test Skill
            """;
        await File.WriteAllTextAsync(skillFile, content);

        var registry = new SkillRegistry(_loader, [_testDirectory]);

        // Act
        await registry.LoadMetadataAsync();
        var metadata = registry.GetSkillMetadata();

        // Assert
        metadata.Should().HaveCount(1);
        metadata[0].Name.Should().Be("test-skill");
        metadata[0].Description.Should().Be("A test skill");
    }

    [Fact]
    public async Task Should_LoadMultipleSkills_FromSameDirectory()
    {
        // Arrange
        var skill1Dir = Path.Combine(_testDirectory, "skill1");
        var skill2Dir = Path.Combine(_testDirectory, "skill2");
        Directory.CreateDirectory(skill1Dir);
        Directory.CreateDirectory(skill2Dir);

        await File.WriteAllTextAsync(Path.Combine(skill1Dir, "SKILL.md"), """
            ---
            name: skill-one
            description: First skill
            ---
            # Skill 1
            """);

        await File.WriteAllTextAsync(Path.Combine(skill2Dir, "SKILL.md"), """
            ---
            name: skill-two
            description: Second skill
            ---
            # Skill 2
            """);

        var registry = new SkillRegistry(_loader, [_testDirectory]);

        // Act
        await registry.LoadMetadataAsync();
        var metadata = registry.GetSkillMetadata();

        // Assert
        metadata.Should().HaveCount(2);
        metadata.Should().Contain(m => m.Name == "skill-one");
        metadata.Should().Contain(m => m.Name == "skill-two");
    }

    [Fact]
    public async Task Should_HandleNonExistentDirectory_Gracefully()
    {
        // Arrange
        var nonExistentDir = Path.Combine(_testDirectory, "nonexistent");
        var registry = new SkillRegistry(_loader, [nonExistentDir]);

        // Act
        await registry.LoadMetadataAsync();
        var metadata = registry.GetSkillMetadata();

        // Assert
        metadata.Should().BeEmpty();
    }

    [Fact]
    public async Task Should_SkipInvalidSkillFiles_AndContinueLoading()
    {
        // Arrange
        var validSkillDir = Path.Combine(_testDirectory, "valid-skill");
        var invalidSkillDir = Path.Combine(_testDirectory, "invalid-skill");
        Directory.CreateDirectory(validSkillDir);
        Directory.CreateDirectory(invalidSkillDir);

        // Valid skill
        await File.WriteAllTextAsync(Path.Combine(validSkillDir, "SKILL.md"), """
            ---
            name: valid-skill
            description: A valid skill
            ---
            # Valid
            """);

        // Invalid skill (missing name)
        await File.WriteAllTextAsync(Path.Combine(invalidSkillDir, "SKILL.md"), """
            ---
            description: Invalid skill
            ---
            # Invalid
            """);

        var registry = new SkillRegistry(_loader, [_testDirectory]);

        // Act
        await registry.LoadMetadataAsync();
        var metadata = registry.GetSkillMetadata();

        // Assert - should only load the valid skill
        metadata.Should().HaveCount(1);
        metadata[0].Name.Should().Be("valid-skill");
    }

    [Fact]
    public async Task Should_LoadFullContent_ForRegisteredSkill()
    {
        // Arrange
        var skillDir = Path.Combine(_testDirectory, "test-skill");
        Directory.CreateDirectory(skillDir);
        var skillFile = Path.Combine(skillDir, "SKILL.md");
        var content = """
            ---
            name: test-skill
            description: A test skill
            ---
            
            # Test Skill
            
            This is the full content.
            """;
        await File.WriteAllTextAsync(skillFile, content);

        var registry = new SkillRegistry(_loader, [_testDirectory]);
        await registry.LoadMetadataAsync();

        // Act
        var fullContent = await registry.LoadFullContentAsync("test-skill");

        // Assert
        fullContent.Should().Be(content);
    }

    [Fact]
    public async Task Should_ThrowKeyNotFoundException_WhenSkillNotFound()
    {
        // Arrange
        var registry = new SkillRegistry(_loader, [_testDirectory]);
        await registry.LoadMetadataAsync();

        // Act
        var act = async () => await registry.LoadFullContentAsync("nonexistent-skill");

        // Assert
        await act.Should().ThrowAsync<KeyNotFoundException>()
            .WithMessage("*Skill not found: nonexistent-skill*");
    }

    [Fact]
    public async Task Should_OnlyReturnMetadata_NotFullContent_InGetSkillMetadata()
    {
        // Arrange - This test validates the progressive disclosure pattern
        var skillDir = Path.Combine(_testDirectory, "test-skill");
        Directory.CreateDirectory(skillDir);
        var skillFile = Path.Combine(skillDir, "SKILL.md");
        var content = """
            ---
            name: test-skill
            description: A test skill
            allowed-tools: read_file,write_file
            model: claude-sonnet-4
            version: 1.0.0
            ---
            
            # Test Skill
            
            This is a very long content that should not be loaded
            during metadata retrieval for progressive disclosure.
            """;
        await File.WriteAllTextAsync(skillFile, content);

        var registry = new SkillRegistry(_loader, [_testDirectory]);
        await registry.LoadMetadataAsync();

        // Act
        var metadata = registry.GetSkillMetadata();

        // Assert - metadata contains only essential info, not the full content
        metadata.Should().HaveCount(1);
        metadata[0].Name.Should().Be("test-skill");
        metadata[0].Description.Should().Be("A test skill");
        metadata[0].AllowedTools.Should().NotBeNull();
        metadata[0].Model.Should().Be("claude-sonnet-4");
        metadata[0].Version.Should().Be("1.0.0");
        metadata[0].FilePath.Should().Be(skillFile);
        
        // The full content is NOT in the metadata - it must be loaded separately
        // This is the progressive disclosure pattern
    }

    [Fact]
    public async Task Should_ClearPreviousMetadata_WhenReloading()
    {
        // Arrange
        var skillDir = Path.Combine(_testDirectory, "test-skill");
        Directory.CreateDirectory(skillDir);
        var skillFile = Path.Combine(skillDir, "SKILL.md");
        
        await File.WriteAllTextAsync(skillFile, """
            ---
            name: test-skill
            description: First version
            ---
            # Test
            """);

        var registry = new SkillRegistry(_loader, [_testDirectory]);
        await registry.LoadMetadataAsync();
        
        // Modify the skill
        await File.WriteAllTextAsync(skillFile, """
            ---
            name: test-skill
            description: Updated version
            ---
            # Test
            """);

        // Act
        await registry.LoadMetadataAsync();
        var metadata = registry.GetSkillMetadata();

        // Assert
        metadata.Should().HaveCount(1);
        metadata[0].Description.Should().Be("Updated version");
    }
}
