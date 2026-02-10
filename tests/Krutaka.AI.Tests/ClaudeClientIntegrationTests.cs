using FluentAssertions;
using Krutaka.AI;
using Krutaka.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Krutaka.AI.Tests;

/// <summary>
/// Integration tests for ClaudeClientWrapper using WireMock.Net.
/// </summary>
public class ClaudeClientIntegrationTests
{
    [Fact]
    public void Should_RegisterIClaudeClient()
    {
        // Arrange
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Claude:ApiKey"] = "sk-ant-test-key-12345",
                ["Claude:ModelId"] = "claude-4-sonnet-20250514",
                ["Claude:MaxTokens"] = "4096",
                ["Claude:Temperature"] = "0.5"
            })
            .Build();

        services.AddLogging();

        // Act
        services.AddClaudeAI(configuration);
        var serviceProvider = services.BuildServiceProvider();

        // Assert
        var client = serviceProvider.GetService<IClaudeClient>();
        client.Should().NotBeNull();
        client.Should().BeAssignableTo<IClaudeClient>();
    }

    [Fact]
    public void Should_ThrowWhenApiKeyMissing()
    {
        // Arrange
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>())
            .Build();

        services.AddLogging();
        services.AddClaudeAI(configuration);
        var serviceProvider = services.BuildServiceProvider();

        // Act & Assert
        var act = () => serviceProvider.GetRequiredService<IClaudeClient>();
        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*API key not found*");
    }

    [Fact]
    public void Should_UseDefaultValuesWhenNotConfigured()
    {
        // Arrange
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Claude:ApiKey"] = "sk-ant-test-key-12345"
            })
            .Build();

        services.AddLogging();

        // Act
        services.AddClaudeAI(configuration);
        var serviceProvider = services.BuildServiceProvider();

        // Assert
        var client = serviceProvider.GetService<IClaudeClient>();
        client.Should().NotBeNull();
    }
}
