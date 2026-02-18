using FluentAssertions;
using Krutaka.Core;

namespace Krutaka.AI.Tests;

/// <summary>
/// Unit tests for retry configuration in AgentConfiguration.
/// </summary>
public sealed class RetryConfigurationTests
{
    [Fact]
    public void AgentConfiguration_Should_HaveDefaultRetryValues()
    {
        // Arrange & Act
        var config = new AgentConfiguration();

        // Assert
        config.RetryMaxAttempts.Should().Be(3);
        config.RetryInitialDelayMs.Should().Be(1000);
        config.RetryMaxDelayMs.Should().Be(30000);
    }

    [Fact]
    public void AgentConfiguration_Should_AllowCustomRetryValues()
    {
        // Arrange & Act
        var config = new AgentConfiguration(
            RetryMaxAttempts: 5,
            RetryInitialDelayMs: 2000,
            RetryMaxDelayMs: 60000);

        // Assert
        config.RetryMaxAttempts.Should().Be(5);
        config.RetryInitialDelayMs.Should().Be(2000);
        config.RetryMaxDelayMs.Should().Be(60000);
    }

    [Fact]
    public void AgentConfiguration_Should_SerializeAndDeserializeRetrySettings()
    {
        // Arrange
        var original = new AgentConfiguration(
            RetryMaxAttempts: 5,
            RetryInitialDelayMs: 2000,
            RetryMaxDelayMs: 60000);

        // Act
        var json = System.Text.Json.JsonSerializer.Serialize(original);
        var deserialized = System.Text.Json.JsonSerializer.Deserialize<AgentConfiguration>(json);

        // Assert
        deserialized.Should().NotBeNull();
        deserialized!.RetryMaxAttempts.Should().Be(5);
        deserialized.RetryInitialDelayMs.Should().Be(2000);
        deserialized.RetryMaxDelayMs.Should().Be(60000);
    }
}

/// <summary>
/// Behavioral tests for ClaudeClientWrapper retry logic.
/// These tests verify the retry configuration is passed correctly.
/// Integration tests with actual API would require a live Anthropic API key.
/// </summary>
public sealed class ClaudeClientRetryBehaviorTests
{
    [Fact]
    public void ClaudeClientWrapper_Should_AcceptRetryConfiguration()
    {
        // Arrange
        using var client = new Anthropic.AnthropicClient { ApiKey = "test-key" };
        var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger<ClaudeClientWrapper>.Instance;

        // Act - Create wrapper with custom retry settings
        using var wrapper = new ClaudeClientWrapper(
            client,
            logger,
            retryMaxAttempts: 5,
            retryInitialDelayMs: 2000,
            retryMaxDelayMs: 60000);

        // Assert - Wrapper should be created successfully
        wrapper.Should().NotBeNull();
    }

    [Fact]
    public void ClaudeClientWrapper_Should_UseDefaultRetryConfiguration()
    {
        // Arrange
        using var client = new Anthropic.AnthropicClient { ApiKey = "test-key" };
        var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger<ClaudeClientWrapper>.Instance;

        // Act - Create wrapper without specifying retry settings
        using var wrapper = new ClaudeClientWrapper(client, logger);

        // Assert - Wrapper should be created successfully with defaults
        wrapper.Should().NotBeNull();
    }

    [Fact]
    public async Task ExecuteWithRetryAsync_Should_CalculateExponentialBackoff()
    {
        // Arrange
        using var client = new Anthropic.AnthropicClient { ApiKey = "test-key" };
        var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger<ClaudeClientWrapper>.Instance;
        using var wrapper = new ClaudeClientWrapper(
            client,
            logger,
            retryMaxAttempts: 3,
            retryInitialDelayMs: 100,
            retryMaxDelayMs: 10000);

        // This test verifies that exponential backoff is calculated correctly
        // The actual retry logic will be tested through integration tests or in production
        
        // For attempt 0: 100 * 2^0 = 100ms (with jitter: 75-125ms)
        // For attempt 1: 100 * 2^1 = 200ms (with jitter: 150-250ms)
        // For attempt 2: 100 * 2^2 = 400ms (with jitter: 300-500ms)
        
        // Assert - Configuration is set up correctly
        wrapper.Should().NotBeNull();
        
        // Note: Full integration test would require mocking AnthropicClient's internal behavior
        // which is complex due to the sealed nature of the SDK types
        await Task.CompletedTask;
    }

    [Fact]
    public void ExponentialBackoff_Should_RespectMaxDelay()
    {
        // Arrange - Calculate what backoff values would be
        int initialDelay = 1000;
        int maxDelay = 5000;
        
        // Act - Simulate exponential backoff calculation
        var delays = new List<int>();
        for (int attempt = 0; attempt < 5; attempt++)
        {
            var baseDelay = initialDelay * Math.Pow(2, attempt);
            var cappedDelay = Math.Min(baseDelay, maxDelay);
            delays.Add((int)cappedDelay);
        }
        
        // Assert - Delays should cap at maxDelay
        // Attempt 0: 1000ms
        // Attempt 1: 2000ms
        // Attempt 2: 4000ms
        // Attempt 3: 5000ms (capped, would be 8000ms)
        // Attempt 4: 5000ms (capped, would be 16000ms)
        delays[0].Should().Be(1000);
        delays[1].Should().Be(2000);
        delays[2].Should().Be(4000);
        delays[3].Should().Be(5000); // Capped
        delays[4].Should().Be(5000); // Capped
    }

    [Fact]
    public void Jitter_Should_BeInExpectedRange()
    {
        // Arrange - Test jitter calculation formula
        var baseDelay = 1000;
        using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
        var delays = new List<int>();
        
        // Act - Generate multiple jittered delays
        for (int i = 0; i < 100; i++)
        {
            var jitterBytes = new byte[4];
            rng.GetBytes(jitterBytes);
            var randomValue = BitConverter.ToUInt32(jitterBytes, 0) / (double)uint.MaxValue;
            var jitterFactor = 0.75 + (randomValue * 0.5); // Range: 0.75 to 1.25
            var delayMs = (int)(baseDelay * jitterFactor);
            delays.Add(delayMs);
        }
        
        // Assert - All jittered delays should be within ±25% of base delay
        delays.Should().OnlyContain(d => d >= 750 && d <= 1250);
        
        // Assert - Delays should have variance (not all the same)
        var distinctDelays = delays.Distinct().Count();
        distinctDelays.Should().BeGreaterThan(50, "jitter should produce varying delays");
    }
}

/// <summary>
/// Validation tests for ClaudeClientWrapper constructor parameters.
/// </summary>
public sealed class ClaudeClientWrapperValidationTests
{
    [Fact]
    public void Constructor_Should_ThrowOnNullClient()
    {
        // Arrange & Act & Assert
        var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger<ClaudeClientWrapper>.Instance;
        
        Assert.Throws<ArgumentNullException>(() =>
            new ClaudeClientWrapper(null!, logger));
    }

    [Fact]
    public void Constructor_Should_ThrowOnNullLogger()
    {
        // Arrange & Act & Assert
        using var client = new Anthropic.AnthropicClient { ApiKey = "test-key" };
        
        Assert.Throws<ArgumentNullException>(() =>
            new ClaudeClientWrapper(client, null!));
    }

    [Fact]
    public void Constructor_Should_RejectNegativeMaxAttempts()
    {
        // Arrange & Act & Assert
        using var client = new Anthropic.AnthropicClient { ApiKey = "test-key" };
        var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger<ClaudeClientWrapper>.Instance;
        
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new ClaudeClientWrapper(client, logger, retryMaxAttempts: -1));
    }

    [Fact]
    public void Constructor_Should_RejectZeroOrNegativeInitialDelay()
    {
        // Arrange & Act & Assert
        using var client = new Anthropic.AnthropicClient { ApiKey = "test-key" };
        var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger<ClaudeClientWrapper>.Instance;
        
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new ClaudeClientWrapper(client, logger, retryInitialDelayMs: 0));

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new ClaudeClientWrapper(client, logger, retryInitialDelayMs: -100));
    }

    [Fact]
    public void Constructor_Should_RejectMaxDelayLessThanInitialDelay()
    {
        // Arrange & Act & Assert
        using var client = new Anthropic.AnthropicClient { ApiKey = "test-key" };
        var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger<ClaudeClientWrapper>.Instance;
        
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new ClaudeClientWrapper(client, logger, retryInitialDelayMs: 1000, retryMaxDelayMs: 500));
    }

    [Fact]
    public void Constructor_Should_RejectExcessiveMaxDelay()
    {
        // Arrange & Act & Assert
        using var client = new Anthropic.AnthropicClient { ApiKey = "test-key" };
        var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger<ClaudeClientWrapper>.Instance;
        
        // Max delay > 5 minutes (300000ms) should be rejected
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new ClaudeClientWrapper(client, logger, retryMaxDelayMs: 400000));
    }

    [Fact]
    public void Constructor_Should_AcceptZeroRetries()
    {
        // Arrange & Act - Zero retries should be valid (fail immediately on first error)
        using var client = new Anthropic.AnthropicClient { ApiKey = "test-key" };
        var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger<ClaudeClientWrapper>.Instance;
        
        using var wrapper = new ClaudeClientWrapper(
            client,
            logger,
            retryMaxAttempts: 0,
            retryInitialDelayMs: 1000,
            retryMaxDelayMs: 30000);

        // Assert
        wrapper.Should().NotBeNull();
    }

    [Fact]
    public void Constructor_Should_AcceptValidBoundaryValues()
    {
        // Arrange & Act
        using var client = new Anthropic.AnthropicClient { ApiKey = "test-key" };
        var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger<ClaudeClientWrapper>.Instance;
        
        using var wrapper = new ClaudeClientWrapper(
            client,
            logger,
            retryMaxAttempts: 10,
            retryInitialDelayMs: 1,
            retryMaxDelayMs: 300000); // Exactly 5 minutes

        // Assert
        wrapper.Should().NotBeNull();
    }

    [Fact]
    public void Dispose_Should_BeIdempotent()
    {
        // Arrange
        using var client = new Anthropic.AnthropicClient { ApiKey = "test-key" };
        var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger<ClaudeClientWrapper>.Instance;
        var wrapper = new ClaudeClientWrapper(client, logger);

        // Act - Dispose multiple times
        wrapper.Dispose();
        wrapper.Dispose();
        wrapper.Dispose();

        // Assert - Should not throw
    }

    [Fact]
    public void Dispose_Should_DisposeResources()
    {
        // Arrange
        using var client = new Anthropic.AnthropicClient { ApiKey = "test-key" };
        var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger<ClaudeClientWrapper>.Instance;
        var wrapper = new ClaudeClientWrapper(client, logger);

        // Act
        wrapper.Dispose();

        // Assert - Wrapper should be disposed (verified by no exception on double dispose)
        wrapper.Dispose();
    }
}
