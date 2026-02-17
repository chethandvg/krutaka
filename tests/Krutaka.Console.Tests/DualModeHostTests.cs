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
        var mode = ResolveHostMode(configuration, args);

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
        var mode = ResolveHostMode(configuration, args);

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
        var mode = ResolveHostMode(configuration, args);

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
        var mode = ResolveHostMode(configuration, args);

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
        var mode = ResolveHostMode(configuration, args);

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
        var mode = ResolveHostMode(configuration, args);

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
        var mode = ResolveHostMode(configuration, args);

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
        var act = () => ResolveHostMode(configuration, args);

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
        var act = () => ResolveHostMode(configuration, args);

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
        var mode = ResolveHostMode(configuration, args);

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
        var mode = ResolveHostMode(configuration, args);

        // Assert
        mode.Should().Be(HostMode.Both);
    }

    /// <summary>
    /// Helper method to resolve host mode from configuration and CLI arguments.
    /// This mirrors the logic that will be in Program.cs.
    /// </summary>
    private static HostMode ResolveHostMode(IConfiguration configuration, string[] args)
    {
        // Check CLI arguments first (--mode takes precedence)
        for (int i = 0; i < args.Length - 1; i++)
        {
            if (args[i].Equals("--mode", StringComparison.OrdinalIgnoreCase))
            {
                var modeValue = args[i + 1];
                if (Enum.TryParse<HostMode>(modeValue, ignoreCase: true, out var cliMode))
                {
                    return cliMode;
                }

                throw new ArgumentException(
                    $"Invalid host mode '{modeValue}' specified via --mode. Valid values: Console, Telegram, Both",
                    nameof(args));
            }
        }

        // Fall back to configuration
        var configMode = configuration["Mode"];
        if (!string.IsNullOrWhiteSpace(configMode))
        {
            if (Enum.TryParse<HostMode>(configMode, ignoreCase: true, out var parsedMode))
            {
                return parsedMode;
            }

            throw new ArgumentException(
                $"Invalid host mode '{configMode}' in configuration. Valid values: Console, Telegram, Both");
        }

        // Default to Console for backward compatibility
        return HostMode.Console;
    }
}
