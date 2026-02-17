using FluentAssertions;
using Krutaka.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Krutaka.Console.Tests;

/// <summary>
/// Unit tests for dual-mode host configuration and service registration.
/// </summary>
public class DualModeHostTests
{
    [Fact]
    public void ResolveHostMode_WithNoConfiguration_DefaultsToConsole()
    {
        // Arrange
        var configuration = new ConfigurationBuilder().Build();
        string[] args = [];

        // Act
        var mode = HostModeConfigurator.ResolveMode(configuration, args);

        // Assert
        mode.Should().Be(HostMode.Console);
    }

    [Fact]
    public void ResolveHostMode_WithConfigConsole_ReturnsConsole()
    {
        // Arrange
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Mode"] = "Console"
            })
            .Build();
        string[] args = [];

        // Act
        var mode = HostModeConfigurator.ResolveMode(configuration, args);

        // Assert
        mode.Should().Be(HostMode.Console);
    }

    [Fact]
    public void ResolveHostMode_WithConfigTelegram_ReturnsTelegram()
    {
        // Arrange
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Mode"] = "Telegram"
            })
            .Build();
        string[] args = [];

        // Act
        var mode = HostModeConfigurator.ResolveMode(configuration, args);

        // Assert
        mode.Should().Be(HostMode.Telegram);
    }

    [Fact]
    public void ResolveHostMode_WithConfigBoth_ReturnsBoth()
    {
        // Arrange
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Mode"] = "Both"
            })
            .Build();
        string[] args = [];

        // Act
        var mode = HostModeConfigurator.ResolveMode(configuration, args);

        // Assert
        mode.Should().Be(HostMode.Both);
    }

    [Fact]
    public void ResolveHostMode_WithCliArgumentTelegram_OverridesConfig()
    {
        // Arrange
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Mode"] = "Console"
            })
            .Build();
        string[] args = ["--mode", "telegram"];

        // Act
        var mode = HostModeConfigurator.ResolveMode(configuration, args);

        // Assert
        mode.Should().Be(HostMode.Telegram);
    }

    [Fact]
    public void ResolveHostMode_WithCliArgumentBoth_OverridesConfig()
    {
        // Arrange
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Mode"] = "Console"
            })
            .Build();
        string[] args = ["--mode", "both"];

        // Act
        var mode = HostModeConfigurator.ResolveMode(configuration, args);

        // Assert
        mode.Should().Be(HostMode.Both);
    }

    [Fact]
    public void ResolveHostMode_WithCliArgumentConsole_OverridesConfig()
    {
        // Arrange
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Mode"] = "Telegram"
            })
            .Build();
        string[] args = ["--mode", "console"];

        // Act
        var mode = HostModeConfigurator.ResolveMode(configuration, args);

        // Assert
        mode.Should().Be(HostMode.Console);
    }

    [Fact]
    public void ResolveHostMode_WithInvalidConfigMode_ThrowsArgumentException()
    {
        // Arrange
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Mode"] = "InvalidMode"
            })
            .Build();
        string[] args = [];

        // Act
        var act = () => HostModeConfigurator.ResolveMode(configuration, args);

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithMessage("*InvalidMode*");
    }

    [Fact]
    public void ResolveHostMode_WithInvalidCliArgument_ThrowsArgumentException()
    {
        // Arrange
        var configuration = new ConfigurationBuilder().Build();
        string[] args = ["--mode", "invalid"];

        // Act
        var act = () => HostModeConfigurator.ResolveMode(configuration, args);

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithMessage("*invalid*");
    }

    [Fact]
    public void ResolveHostMode_IsCaseInsensitive_Config()
    {
        // Arrange
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Mode"] = "telegram" // lowercase
            })
            .Build();
        string[] args = [];

        // Act
        var mode = HostModeConfigurator.ResolveMode(configuration, args);

        // Assert
        mode.Should().Be(HostMode.Telegram);
    }

    [Fact]
    public void ResolveHostMode_IsCaseInsensitive_CliArgument()
    {
        // Arrange
        var configuration = new ConfigurationBuilder().Build();
        string[] args = ["--mode", "BOTH"]; // uppercase

        // Act
        var mode = HostModeConfigurator.ResolveMode(configuration, args);

        // Assert
        mode.Should().Be(HostMode.Both);
    }

    [Fact]
    public void ResolveHostMode_WithTrailingModeArgument_ThrowsArgumentException()
    {
        // Arrange
        var configuration = new ConfigurationBuilder().Build();
        string[] args = ["--mode"]; // No value after --mode

        // Act
        var act = () => HostModeConfigurator.ResolveMode(configuration, args);

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithMessage("*--mode argument requires a value*");
    }
}
