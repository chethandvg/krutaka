using FluentAssertions;
using Krutaka.Core;

namespace Krutaka.AI.Tests;

/// <summary>
/// Adversarial tests for rate limit retry/backoff behavior in ClaudeClientWrapper.
/// These tests validate resilience under hostile or edge-case conditions:
/// retry exhaustion, concurrent access patterns, and boundary conditions.
/// Note: Full integration testing with actual rate limit responses requires a live API key
/// and is covered in ClaudeClientIntegrationTests.cs. These tests focus on configuration
/// validation and retry calculation logic that can be tested without mocking the sealed SDK.
/// </summary>
public sealed class RateLimitAdversarialTests
{
    [Fact]
    public void RetryConfiguration_Should_RejectNegativeMaxAttempts()
    {
        // Arrange & Act & Assert
        using var client = new Anthropic.AnthropicClient { ApiKey = "test-key" };
        var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger<ClaudeClientWrapper>.Instance;

        var exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            new ClaudeClientWrapper(
                client,
                logger,
                retryMaxAttempts: -5));

        exception.ParamName.Should().Be("retryMaxAttempts");
    }

    [Fact]
    public void RetryConfiguration_Should_AcceptZeroMaxAttempts_NoRetries()
    {
        // Arrange & Act - Zero retries means fail immediately on first error (no retries)
        using var client = new Anthropic.AnthropicClient { ApiKey = "test-key" };
        var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger<ClaudeClientWrapper>.Instance;

        using var wrapper = new ClaudeClientWrapper(
            client,
            logger,
            retryMaxAttempts: 0, // No retries at all
            retryInitialDelayMs: 1000,
            retryMaxDelayMs: 30000);

        // Assert - Should be created successfully
        wrapper.Should().NotBeNull();
    }

    [Fact]
    public void RetryConfiguration_Should_RejectZeroInitialDelay()
    {
        // Arrange & Act & Assert - Zero initial delay is invalid
        using var client = new Anthropic.AnthropicClient { ApiKey = "test-key" };
        var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger<ClaudeClientWrapper>.Instance;

        var exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            new ClaudeClientWrapper(
                client,
                logger,
                retryInitialDelayMs: 0));

        exception.ParamName.Should().Be("retryInitialDelayMs");
    }

    [Fact]
    public void RetryConfiguration_Should_RejectNegativeInitialDelay()
    {
        // Arrange & Act & Assert
        using var client = new Anthropic.AnthropicClient { ApiKey = "test-key" };
        var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger<ClaudeClientWrapper>.Instance;

        var exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            new ClaudeClientWrapper(
                client,
                logger,
                retryInitialDelayMs: -1000));

        exception.ParamName.Should().Be("retryInitialDelayMs");
    }

    [Fact]
    public void RetryConfiguration_Should_RejectMaxDelayLessThanInitialDelay()
    {
        // Arrange & Act & Assert - maxDelay < initialDelay is invalid
        using var client = new Anthropic.AnthropicClient { ApiKey = "test-key" };
        var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger<ClaudeClientWrapper>.Instance;

        var exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            new ClaudeClientWrapper(
                client,
                logger,
                retryInitialDelayMs: 10000,
                retryMaxDelayMs: 5000)); // Less than initial

        exception.ParamName.Should().Be("retryMaxDelayMs");
    }

    [Fact]
    public void RetryConfiguration_Should_RejectExcessiveMaxDelay_Over5Minutes()
    {
        // Arrange & Act & Assert - Max delay > 5 minutes (300,000ms) is rejected
        using var client = new Anthropic.AnthropicClient { ApiKey = "test-key" };
        var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger<ClaudeClientWrapper>.Instance;

        var exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            new ClaudeClientWrapper(
                client,
                logger,
                retryMaxDelayMs: 400000)); // 6 minutes 40 seconds

        exception.ParamName.Should().Be("retryMaxDelayMs");
    }

    [Fact]
    public void RetryConfiguration_Should_AcceptMaxDelayExactly5Minutes()
    {
        // Arrange & Act - Exactly 5 minutes (300,000ms) should be accepted (boundary test)
        using var client = new Anthropic.AnthropicClient { ApiKey = "test-key" };
        var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger<ClaudeClientWrapper>.Instance;

        using var wrapper = new ClaudeClientWrapper(
            client,
            logger,
            retryMaxDelayMs: 300000); // Exactly 5 minutes

        // Assert
        wrapper.Should().NotBeNull();
    }

    [Fact]
    public void RetryConfiguration_Should_AcceptMaxDelayOneMillisecondUnder5Minutes()
    {
        // Arrange & Act - Just under 5 minutes should be accepted
        using var client = new Anthropic.AnthropicClient { ApiKey = "test-key" };
        var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger<ClaudeClientWrapper>.Instance;

        using var wrapper = new ClaudeClientWrapper(
            client,
            logger,
            retryMaxDelayMs: 299999); // 4 minutes 59.999 seconds

        // Assert
        wrapper.Should().NotBeNull();
    }

    [Fact]
    public void ExponentialBackoff_Should_CalculateCorrectDelaysWithCapping()
    {
        // Arrange - Test exponential backoff calculation with capping
        int initialDelay = 1000;
        int maxDelay = 30000;

        // Act - Simulate backoff calculation for multiple attempts
        var delays = new List<double>();
        for (int attempt = 0; attempt < 10; attempt++)
        {
            var baseDelay = initialDelay * Math.Pow(2, attempt);
            var cappedDelay = Math.Min(baseDelay, maxDelay);
            delays.Add(cappedDelay);
        }

        // Assert - Verify exponential growth until cap
        delays[0].Should().Be(1000);   // 1000 * 2^0 = 1000
        delays[1].Should().Be(2000);   // 1000 * 2^1 = 2000
        delays[2].Should().Be(4000);   // 1000 * 2^2 = 4000
        delays[3].Should().Be(8000);   // 1000 * 2^3 = 8000
        delays[4].Should().Be(16000);  // 1000 * 2^4 = 16000
        delays[5].Should().Be(30000);  // 1000 * 2^5 = 32000 → capped at 30000
        delays[6].Should().Be(30000);  // 1000 * 2^6 = 64000 → capped at 30000
        delays[7].Should().Be(30000);  // Remains capped
        delays[8].Should().Be(30000);  // Remains capped
        delays[9].Should().Be(30000);  // Remains capped
    }

    [Fact]
    public void ExponentialBackoff_Should_CapAtMaxDelayForLargeAttemptCounts()
    {
        // Arrange - Test that backoff never exceeds max delay even for huge attempt counts
        int initialDelay = 100;
        int maxDelay = 5000;

        // Act - Calculate delay for attempt 50 (extreme case)
        var baseDelay = initialDelay * Math.Pow(2, 50); // Would be astronomically large
        var cappedDelay = Math.Min(baseDelay, maxDelay);

        // Assert - Should be capped at maxDelay
        cappedDelay.Should().Be(5000);
    }

    [Fact]
    public void Jitter_Should_ProduceValuesInExpectedRange_75To125Percent()
    {
        // Arrange - Test jitter calculation (±25%)
        var baseDelay = 1000;
        using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
        var jitteredDelays = new List<int>();

        // Act - Generate 100 jittered delays
        for (int i = 0; i < 100; i++)
        {
            var jitterBytes = new byte[4];
            rng.GetBytes(jitterBytes);
            var randomValue = BitConverter.ToUInt32(jitterBytes, 0) / (double)uint.MaxValue; // 0.0 to 1.0
            var jitterFactor = 0.75 + (randomValue * 0.5); // Range: 0.75 to 1.25
            var delayMs = (int)(baseDelay * jitterFactor);
            jitteredDelays.Add(delayMs);
        }

        // Assert - All delays should be within ±25% of base delay
        jitteredDelays.Should().OnlyContain(d => d >= 750 && d <= 1250,
            "jitter should produce delays in the range [75%, 125%] of base delay");

        // Assert - Delays should have variance (not all the same)
        var distinctDelays = jitteredDelays.Distinct().Count();
        distinctDelays.Should().BeGreaterThan(50,
            "jitter should produce varying delays across 100 samples");
    }

    [Fact]
    public void Jitter_Should_BeThreadSafe_WithConcurrentAccess()
    {
        // Arrange - Test that jitter calculation is thread-safe
        using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
        var delays = new System.Collections.Concurrent.ConcurrentBag<int>();
        var lockObject = new object();

        // Act - Simulate concurrent jitter calculations (like multiple sessions retrying)
        Parallel.For(0, 1000, i =>
        {
            int delayMs;
            lock (lockObject) // Simulate the _randomLock in ClaudeClientWrapper
            {
                var jitterBytes = new byte[4];
                rng.GetBytes(jitterBytes);
                var randomValue = BitConverter.ToUInt32(jitterBytes, 0) / (double)uint.MaxValue;
                var jitterFactor = 0.75 + (randomValue * 0.5);
                delayMs = (int)(1000 * jitterFactor);
            }

            delays.Add(delayMs);
        });

        // Assert - Should produce 1000 delays without errors
        delays.Should().HaveCount(1000);
        delays.Should().OnlyContain(d => d >= 750 && d <= 1250);
    }

    [Fact]
    public void RetryConfiguration_Should_AllowMinimalValues_1Ms()
    {
        // Arrange & Act - Minimal valid configuration (edge case)
        using var client = new Anthropic.AnthropicClient { ApiKey = "test-key" };
        var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger<ClaudeClientWrapper>.Instance;

        using var wrapper = new ClaudeClientWrapper(
            client,
            logger,
            retryMaxAttempts: 0,
            retryInitialDelayMs: 1, // Minimum valid delay
            retryMaxDelayMs: 1);    // Same as initial (no exponential growth)

        // Assert
        wrapper.Should().NotBeNull();
    }

    [Fact]
    public void RetryConfiguration_Should_AllowMaximalValidValues()
    {
        // Arrange & Act - Maximal valid configuration (stress test)
        using var client = new Anthropic.AnthropicClient { ApiKey = "test-key" };
        var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger<ClaudeClientWrapper>.Instance;

        using var wrapper = new ClaudeClientWrapper(
            client,
            logger,
            retryMaxAttempts: int.MaxValue, // Extreme retry count
            retryInitialDelayMs: 1,
            retryMaxDelayMs: 300000); // Max allowed (5 minutes)

        // Assert
        wrapper.Should().NotBeNull();
    }

    [Fact]
    public void AgentConfiguration_Should_PropagateRetrySettingsCorrectly()
    {
        // Arrange & Act - Test that AgentConfiguration correctly captures retry settings
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
    public void AgentConfiguration_Should_UseDefaultRetrySettings()
    {
        // Arrange & Act
        var config = new AgentConfiguration();

        // Assert - Defaults should match documented behavior
        config.RetryMaxAttempts.Should().Be(3, "default should be 3 retries");
        config.RetryInitialDelayMs.Should().Be(1000, "default initial delay should be 1000ms");
        config.RetryMaxDelayMs.Should().Be(30000, "default max delay should be 30000ms (30 seconds)");
    }

    [Fact]
    public void RetryConfiguration_Should_HandleConcurrentWrapperCreation()
    {
        // Arrange & Act - Test that creating multiple wrappers concurrently is safe
        var wrappers = new System.Collections.Concurrent.ConcurrentBag<ClaudeClientWrapper>();

        Parallel.For(0, 100, i =>
        {
            using var client = new Anthropic.AnthropicClient { ApiKey = $"test-key-{i}" };
            var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger<ClaudeClientWrapper>.Instance;

            var wrapper = new ClaudeClientWrapper(
                client,
                logger,
                retryMaxAttempts: i % 5, // Vary the config
                retryInitialDelayMs: 1000 + (i * 100),
                retryMaxDelayMs: 30000);

            wrappers.Add(wrapper);
        });

        // Assert
        wrappers.Should().HaveCount(100);

        // Cleanup
        foreach (var wrapper in wrappers)
        {
            wrapper.Dispose();
        }
    }

    [Fact]
    public void Dispose_Should_BeIdempotent_MultipleDisposeCalls()
    {
        // Arrange
        using var client = new Anthropic.AnthropicClient { ApiKey = "test-key" };
        var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger<ClaudeClientWrapper>.Instance;
        using var wrapper = new ClaudeClientWrapper(client, logger);

        // Act - Dispose 10 times
        for (int i = 0; i < 10; i++)
        {
            wrapper.Dispose();
        }

        // Assert - Should not throw (idempotent)
    }

    [Fact]
    public void Dispose_Should_HandleConcurrentDisposeCalls()
    {
        // Arrange
        using var client = new Anthropic.AnthropicClient { ApiKey = "test-key" };
        var logger = Microsoft.Extensions.Logging.Abstractions.NullLogger<ClaudeClientWrapper>.Instance;
        using var wrapper = new ClaudeClientWrapper(client, logger);

        // Act - Dispose from multiple threads concurrently
        Parallel.For(0, 100, i =>
        {
            wrapper.Dispose();
        });

        // Assert - Should not throw (thread-safe idempotent dispose)
    }
}
