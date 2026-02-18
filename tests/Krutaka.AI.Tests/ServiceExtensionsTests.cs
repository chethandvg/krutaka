using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;

namespace Krutaka.AI.Tests;

/// <summary>
/// Tests for Krutaka.AI service registration and configuration.
/// Validates Polly CircuitBreaker configuration constraint: SamplingDuration >= 2 * AttemptTimeout.
/// </summary>
public class ServiceExtensionsTests
{
    [Fact]
    public void AddClaudeAI_Should_ConfigurePollyWithValidSamplingDuration()
    {
        // Arrange - Create a service collection with required configuration
        var services = new ServiceCollection();
        
        // Create a minimal configuration with Claude API key
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Claude:ApiKey"] = "sk-ant-test-key-1234567890abcdefghijklmnopqrstuvwxyz",
                ["Claude:ModelId"] = "claude-3-5-sonnet-20241022",
                ["Claude:MaxTokens"] = "8192",
                ["Claude:Temperature"] = "0"
            })
            .Build();

        // Act - Register Claude client services (which includes Polly configuration)
        var action = () => ServiceExtensions.AddClaudeAI(services, configuration);

        // Assert - Should not throw during service registration
        // This validates that Polly configuration satisfies the constraint: SamplingDuration >= 2 * AttemptTimeout
        action.Should().NotThrow();

        // Build the service provider to ensure DI configuration is valid
        var serviceProvider = services.BuildServiceProvider();
        serviceProvider.Should().NotBeNull();
    }

    [Fact]
    public void AddClaudeAI_Should_RegisterHttpClientWithName()
    {
        // Arrange
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Claude:ApiKey"] = "sk-ant-test-key-1234567890abcdefghijklmnopqrstuvwxyz",
                ["Claude:ModelId"] = "claude-3-5-sonnet-20241022",
                ["Claude:MaxTokens"] = "8192",
                ["Claude:Temperature"] = "0"
            })
            .Build();

        // Act
        ServiceExtensions.AddClaudeAI(services, configuration);
        var serviceProvider = services.BuildServiceProvider();
        var httpClientFactory = serviceProvider.GetService<IHttpClientFactory>();

        // Assert
        httpClientFactory.Should().NotBeNull();
        
        // Verify that the named HttpClient can be created without errors
        var action = () => httpClientFactory!.CreateClient("AnthropicAPI");
        action.Should().NotThrow();
    }

    [Fact]
    public void AddClaudeAI_Should_ThrowArgumentNullException_WhenServicesIsNull()
    {
        // Arrange
        var configuration = new ConfigurationBuilder().Build();

        // Act
        var action = () => ServiceExtensions.AddClaudeAI(null!, configuration);

        // Assert
        action.Should().Throw<ArgumentNullException>()
            .WithParameterName("services");
    }

    [Fact]
    public void AddClaudeAI_Should_ThrowArgumentNullException_WhenConfigurationIsNull()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        var action = () => ServiceExtensions.AddClaudeAI(services, null!);

        // Assert
        action.Should().Throw<ArgumentNullException>()
            .WithParameterName("configuration");
    }
}
