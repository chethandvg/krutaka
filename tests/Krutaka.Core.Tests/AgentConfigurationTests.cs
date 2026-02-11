using System.Text.Json;
using FluentAssertions;

namespace Krutaka.Core.Tests;

internal class AgentConfigurationTests
{
    [Fact]
    public void AgentConfiguration_Should_HaveDefaultValues()
    {
        // Arrange & Act
        var config = new AgentConfiguration();

        // Assert
        config.ModelId.Should().Be("claude-4-sonnet-20250514");
        config.MaxTokens.Should().Be(8192);
        config.Temperature.Should().Be(0.7);
        config.RequireApprovalForWrite.Should().BeTrue();
        config.RequireApprovalForExecute.Should().BeTrue();
        config.AllowApprovalAlways.Should().BeTrue();
    }

    [Fact]
    public void AgentConfiguration_Should_ComputeConfigDirectoryPath()
    {
        // Arrange & Act
        var config = new AgentConfiguration();

        // Assert
        config.ConfigDirectoryPath.Should().EndWith(".krutaka");
        config.ConfigDirectoryPath.Should().Contain(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
    }

    [Fact]
    public void AgentConfiguration_Should_ComputeSessionDirectoryPath()
    {
        // Arrange & Act
        var config = new AgentConfiguration();

        // Assert
        config.SessionDirectoryPath.Should().EndWith(Path.Combine(".krutaka", "sessions"));
    }

    [Fact]
    public void AgentConfiguration_Should_ComputeSkillsDirectoryPath()
    {
        // Arrange & Act
        var config = new AgentConfiguration();

        // Assert
        config.SkillsDirectoryPath.Should().EndWith(Path.Combine(".krutaka", "skills"));
    }

    [Fact]
    public void AgentConfiguration_Should_UseCustomConfigDirectory()
    {
        // Arrange & Act
        var config = new AgentConfiguration(ConfigDirectory: "/custom/path");

        // Assert
        config.ConfigDirectoryPath.Should().Be("/custom/path");
        config.SessionDirectoryPath.Should().Be(Path.Combine("/custom/path", "sessions"));
        config.SkillsDirectoryPath.Should().Be(Path.Combine("/custom/path", "skills"));
    }

    [Fact]
    public void AgentConfiguration_Should_SerializeAndDeserialize()
    {
        // Arrange
        var original = new AgentConfiguration(
            ModelId: "claude-haiku-4-5-20250929",
            MaxTokens: 4096,
            Temperature: 0.5,
            RequireApprovalForWrite: false,
            ProjectRoot: "/test/project"
        );

        // Act
        var json = JsonSerializer.Serialize(original);
        var deserialized = JsonSerializer.Deserialize<AgentConfiguration>(json);

        // Assert
        deserialized.Should().NotBeNull();
        deserialized!.ModelId.Should().Be("claude-haiku-4-5-20250929");
        deserialized.MaxTokens.Should().Be(4096);
        deserialized.Temperature.Should().Be(0.5);
        deserialized.RequireApprovalForWrite.Should().BeFalse();
        deserialized.ProjectRoot.Should().Be("/test/project");
    }

    [Fact]
    public void AgentConfiguration_Should_NotSerializeComputedProperties()
    {
        // Arrange
        var config = new AgentConfiguration();

        // Act
        var json = JsonSerializer.Serialize(config);
        var jsonDoc = JsonDocument.Parse(json);

        // Assert - computed properties should not be in JSON
        jsonDoc.RootElement.TryGetProperty("ConfigDirectoryPath", out _).Should().BeFalse();
        jsonDoc.RootElement.TryGetProperty("SessionDirectoryPath", out _).Should().BeFalse();
        jsonDoc.RootElement.TryGetProperty("SkillsDirectoryPath", out _).Should().BeFalse();
    }
}
