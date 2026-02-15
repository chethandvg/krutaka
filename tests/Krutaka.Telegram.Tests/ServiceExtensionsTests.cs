using FluentAssertions;
using Krutaka.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Krutaka.Telegram.Tests;

public class ServiceExtensionsTests
{
    [Fact]
    public void AddTelegramBot_Should_RegisterTelegramSecurityConfig_WhenValidConfigurationProvided()
    {
        // Arrange
        var services = new ServiceCollection();
        var configuration = CreateValidConfiguration();

        // Act
        services.AddTelegramBot(configuration);
        var serviceProvider = services.BuildServiceProvider();

        // Assert
        var config = serviceProvider.GetService<TelegramSecurityConfig>();
        config.Should().NotBeNull();
        config!.AllowedUsers.Should().NotBeNullOrEmpty();
        config.AllowedUsers.Should().HaveCount(1);
        config.AllowedUsers[0].UserId.Should().Be(12345678);
    }

    [Fact]
    public void AddTelegramBot_Should_ThrowInvalidOperationException_WhenAllowedUsersIsEmpty()
    {
        // Arrange
        var services = new ServiceCollection();
        var configuration = CreateConfigurationWithEmptyUsers();

        // Act & Assert
        var exception = Assert.Throws<InvalidOperationException>(() =>
            services.AddTelegramBot(configuration));

        // The exception message varies based on whether AllowedUsers is missing entirely
        // (config binding error) or present but empty (validation error)
        exception.Message.Should().Contain("Telegram");
    }

    [Fact]
    public void AddTelegramBot_Should_ThrowInvalidOperationException_WhenConfigurationSectionIsMissing()
    {
        // Arrange
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder().Build();

        // Act & Assert
        var exception = Assert.Throws<InvalidOperationException>(() =>
            services.AddTelegramBot(configuration));

        exception.Message.Should().Contain("Telegram configuration section is missing or invalid");
    }

    [Fact]
    public void AddTelegramBot_Should_ResolveConfig_AfterRegistration()
    {
        // Arrange
        var services = new ServiceCollection();
        var configuration = CreateValidConfiguration();

        // Act
        services.AddTelegramBot(configuration);
        var serviceProvider = services.BuildServiceProvider();
        var config = serviceProvider.GetRequiredService<TelegramSecurityConfig>();

        // Assert
        config.Should().NotBeNull();
        config.MaxCommandsPerMinute.Should().Be(10);
        config.MaxTokensPerHour.Should().Be(100_000);
        config.RequireConfirmationForElevated.Should().BeTrue();
    }

    [Fact]
    public void AddTelegramBot_Should_ThrowArgumentNullException_WhenServicesIsNull()
    {
        // Arrange
        IServiceCollection? services = null;
        var configuration = CreateValidConfiguration();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            services!.AddTelegramBot(configuration));
    }

    [Fact]
    public void AddTelegramBot_Should_ThrowArgumentNullException_WhenConfigurationIsNull()
    {
        // Arrange
        var services = new ServiceCollection();
        IConfiguration? configuration = null;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() =>
            services.AddTelegramBot(configuration!));
    }

    private static IConfiguration CreateValidConfiguration()
    {
        var configData = new Dictionary<string, string?>
        {
            ["Telegram:AllowedUsers:0:UserId"] = "12345678",
            ["Telegram:AllowedUsers:0:Role"] = "Admin",
            ["Telegram:MaxCommandsPerMinute"] = "10",
            ["Telegram:MaxTokensPerHour"] = "100000",
            ["Telegram:MaxFailedAuthAttempts"] = "3",
            ["Telegram:RequireConfirmationForElevated"] = "true"
        };

        return new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();
    }

    private static IConfiguration CreateConfigurationWithEmptyUsers()
    {
        var configData = new Dictionary<string, string?>
        {
            ["Telegram:MaxCommandsPerMinute"] = "10",
            ["Telegram:MaxTokensPerHour"] = "100000"
        };

        return new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();
    }
}
