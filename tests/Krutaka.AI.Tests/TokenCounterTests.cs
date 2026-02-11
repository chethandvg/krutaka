using FluentAssertions;
using Krutaka.Core;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;

namespace Krutaka.AI.Tests;

/// <summary>
/// Unit tests for TokenCounter class.
/// </summary>
public sealed class TokenCounterTests
{
    private readonly IClaudeClient _mockClaudeClient;
    private readonly TokenCounter _tokenCounter;

    public TokenCounterTests()
    {
        _mockClaudeClient = Substitute.For<IClaudeClient>();
        _tokenCounter = new TokenCounter(
            _mockClaudeClient,
            NullLogger<TokenCounter>.Instance);
    }

    [Fact]
    public async Task CountTokensAsync_Should_CallClaudeClient()
    {
        // Arrange
        var messages = new List<object>
        {
            new { role = "user", content = "Hello" }
        };
        var systemPrompt = "You are a helpful assistant.";
        _mockClaudeClient.CountTokensAsync(Arg.Any<IEnumerable<object>>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(100));

        // Act
        var result = await _tokenCounter.CountTokensAsync(messages, systemPrompt);

        // Assert
        result.Should().Be(100);
        await _mockClaudeClient.Received(1).CountTokensAsync(
            Arg.Is<IEnumerable<object>>(m => m.Count() == 1),
            systemPrompt,
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CountTokensAsync_Should_UseCacheOnSecondCall()
    {
        // Arrange
        var messages = new List<object>
        {
            new { role = "user", content = "Hello" }
        };
        var systemPrompt = "You are a helpful assistant.";
        _mockClaudeClient.CountTokensAsync(Arg.Any<IEnumerable<object>>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(100));

        // Act - First call
        var result1 = await _tokenCounter.CountTokensAsync(messages, systemPrompt);

        // Act - Second call with same messages
        var result2 = await _tokenCounter.CountTokensAsync(messages, systemPrompt);

        // Assert
        result1.Should().Be(100);
        result2.Should().Be(100);

        // Client should be called only once (second call uses cache)
        await _mockClaudeClient.Received(1).CountTokensAsync(
            Arg.Any<IEnumerable<object>>(),
            Arg.Any<string>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CountTokensAsync_Should_CallClientForDifferentMessages()
    {
        // Arrange
        var messages1 = new List<object>
        {
            new { role = "user", content = "Hello" }
        };
        var messages2 = new List<object>
        {
            new { role = "user", content = "Goodbye" }
        };
        var systemPrompt = "You are a helpful assistant.";
        _mockClaudeClient.CountTokensAsync(Arg.Any<IEnumerable<object>>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(100), Task.FromResult(150));

        // Act
        var result1 = await _tokenCounter.CountTokensAsync(messages1, systemPrompt);
        var result2 = await _tokenCounter.CountTokensAsync(messages2, systemPrompt);

        // Assert
        result1.Should().Be(100);
        result2.Should().Be(150);

        // Client should be called twice for different messages
        await _mockClaudeClient.Received(2).CountTokensAsync(
            Arg.Any<IEnumerable<object>>(),
            Arg.Any<string>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CountTokensAsync_Should_ThrowIfMessagesIsNull()
    {
        // Arrange
        IReadOnlyList<object> messages = null!;
        var systemPrompt = "You are a helpful assistant.";

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentNullException>(
            async () => await _tokenCounter.CountTokensAsync(messages, systemPrompt));
    }

    [Fact]
    public async Task CountTokensAsync_Should_ThrowIfSystemPromptIsNull()
    {
        // Arrange
        var messages = new List<object>
        {
            new { role = "user", content = "Hello" }
        };
        string systemPrompt = null!;

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentNullException>(
            async () => await _tokenCounter.CountTokensAsync(messages, systemPrompt));
    }

    [Fact]
    public async Task CountTokensAsync_Should_EvictOldestEntriesWhenCacheIsFull()
    {
        // Arrange - Create counter with small cache size
        var smallCacheCounter = new TokenCounter(
            _mockClaudeClient,
            NullLogger<TokenCounter>.Instance,
            cacheMaxSize: 10);

        _mockClaudeClient.CountTokensAsync(Arg.Any<IEnumerable<object>>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(ci => Task.FromResult(100));

        var systemPrompt = "You are a helpful assistant.";

        // Act - Add 12 different messages (exceeds cache size of 10)
        for (int i = 0; i < 12; i++)
        {
            var messages = new List<object>
            {
                new { role = "user", content = $"Message {i}" }
            };
            await smallCacheCounter.CountTokensAsync(messages, systemPrompt);
        }

        // Assert - All 12 calls should have been made to the client (no caching for new entries)
        await _mockClaudeClient.Received(12).CountTokensAsync(
            Arg.Any<IEnumerable<object>>(),
            Arg.Any<string>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CountTokensAsync_Should_ExpireCacheEntriesAfterTimeout()
    {
        // Arrange - Create counter with 0 minute cache expiry (expires immediately)
        var shortExpiryCounter = new TokenCounter(
            _mockClaudeClient,
            NullLogger<TokenCounter>.Instance,
            cacheExpiryMinutes: 0);

        var messages = new List<object>
        {
            new { role = "user", content = "Hello" }
        };
        var systemPrompt = "You are a helpful assistant.";
        _mockClaudeClient.CountTokensAsync(Arg.Any<IEnumerable<object>>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(100));

        // Act - First call
        await shortExpiryCounter.CountTokensAsync(messages, systemPrompt);

        // Wait a tiny bit to ensure expiry
        await Task.Delay(10);

        // Act - Second call (should hit API due to expiry)
        await shortExpiryCounter.CountTokensAsync(messages, systemPrompt);

        // Assert - Should have called client twice (cache expired)
        await _mockClaudeClient.Received(2).CountTokensAsync(
            Arg.Any<IEnumerable<object>>(),
            Arg.Any<string>(),
            Arg.Any<CancellationToken>());
    }
}
