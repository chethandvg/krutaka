using FluentAssertions;

namespace Krutaka.Core.Tests;

public class TelegramUserConfigTests
{
    [Fact]
    public void Constructor_Should_CreateWithMinimalParameters()
    {
        // Act
        var config = new TelegramUserConfig(12345678);

        // Assert
        config.UserId.Should().Be(12345678);
        config.Role.Should().Be(TelegramUserRole.User); // Default
        config.ProjectPath.Should().BeNull(); // Default
    }

    [Fact]
    public void Constructor_Should_CreateWithAllParameters()
    {
        // Act
        var config = new TelegramUserConfig(12345678, TelegramUserRole.Admin, "C:\\Projects\\MyApp");

        // Assert
        config.UserId.Should().Be(12345678);
        config.Role.Should().Be(TelegramUserRole.Admin);
        config.ProjectPath.Should().Be("C:\\Projects\\MyApp");
    }

    [Fact]
    public void RecordEquality_Should_WorkCorrectly()
    {
        // Arrange
        var config1 = new TelegramUserConfig(12345678, TelegramUserRole.Admin, "C:\\Projects\\App");
        var config2 = new TelegramUserConfig(12345678, TelegramUserRole.Admin, "C:\\Projects\\App");
        var config3 = new TelegramUserConfig(87654321, TelegramUserRole.User, null);

        // Assert
        config1.Should().Be(config2); // Same values = equal
        config1.Should().NotBe(config3); // Different values = not equal
    }

    [Fact]
    public void With_Should_CreateModifiedCopy()
    {
        // Arrange
        var original = new TelegramUserConfig(12345678, TelegramUserRole.User, null);

        // Act
        var modified = original with { Role = TelegramUserRole.Admin, ProjectPath = "C:\\Projects\\New" };

        // Assert
        modified.UserId.Should().Be(12345678); // Unchanged
        modified.Role.Should().Be(TelegramUserRole.Admin); // Changed
        modified.ProjectPath.Should().Be("C:\\Projects\\New"); // Changed
        original.Role.Should().Be(TelegramUserRole.User); // Original unchanged
    }
}
