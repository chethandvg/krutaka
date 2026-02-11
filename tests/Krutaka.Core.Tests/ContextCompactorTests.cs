using FluentAssertions;
using Krutaka.Core;
using NSubstitute;

namespace Krutaka.Core.Tests;

/// <summary>
/// Unit tests for ContextCompactor class.
/// </summary>
public sealed class ContextCompactorTests
{
    private readonly IClaudeClient _mockClaudeClient;
    private readonly ContextCompactor _compactor;

    public ContextCompactorTests()
    {
        _mockClaudeClient = Substitute.For<IClaudeClient>();
        _compactor = new ContextCompactor(_mockClaudeClient);
    }

    [Fact]
    public void ShouldCompact_Should_ReturnTrue_WhenTokenCountExceedsThreshold()
    {
        // Arrange
        var tokenCount = 165_000; // Above 80% of 200K

        // Act
        var result = _compactor.ShouldCompact(tokenCount);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public void ShouldCompact_Should_ReturnFalse_WhenTokenCountBelowThreshold()
    {
        // Arrange
        var tokenCount = 150_000; // Below 80% of 200K (160K)

        // Act
        var result = _compactor.ShouldCompact(tokenCount);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public async Task CompactAsync_Should_PreserveLastSixMessages()
    {
        // Arrange
        var messages = CreateMessageList(10);
        var systemPrompt = "You are a helpful assistant.";
        var currentTokenCount = 165_000;

        // Mock the summarization response
        SetupMockForSummarization("This is a summary of the conversation.");

        // Mock token counting for compacted conversation
        _mockClaudeClient.CountTokensAsync(
            Arg.Is<IEnumerable<object>>(m => m.Count() == 8), // 2 summary messages + 6 kept messages
            systemPrompt,
            Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(80_000));

        // Act
        var result = await _compactor.CompactAsync(messages, systemPrompt, currentTokenCount);

        // Assert
        result.CompactedMessageCount.Should().Be(8); // 2 summary messages + 6 kept messages
        result.MessagesRemoved.Should().Be(4); // 10 - 6 kept = 4 summarized
        result.OriginalMessageCount.Should().Be(10);
        result.OriginalTokenCount.Should().Be(165_000);
        result.CompactedTokenCount.Should().Be(80_000);
        result.Summary.Should().Be("This is a summary of the conversation.");
    }

    [Fact]
    public async Task CompactAsync_Should_IncludeSummaryAndAcknowledgment()
    {
        // Arrange
        var messages = CreateMessageList(10);
        var systemPrompt = "You are a helpful assistant.";
        var currentTokenCount = 165_000;

        SetupMockForSummarization("Summary text");
        _mockClaudeClient.CountTokensAsync(Arg.Any<IEnumerable<object>>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(80_000));

        // Act
        var result = await _compactor.CompactAsync(messages, systemPrompt, currentTokenCount);

        // Assert
        result.CompactedMessages.Should().HaveCountGreaterThanOrEqualTo(2);

        // First message should be summary from user
        var firstMsg = result.CompactedMessages[0];
        GetMessageRole(firstMsg).Should().Be("user");
        GetMessageContent(firstMsg).Should().Contain("[Previous conversation summary]");
        GetMessageContent(firstMsg).Should().Contain("Summary text");

        // Second message should be acknowledgment from assistant
        var secondMsg = result.CompactedMessages[1];
        GetMessageRole(secondMsg).Should().Be("assistant");
        GetMessageContent(secondMsg).Should().Be("Understood. I have the context from our previous discussion.");
    }

    [Fact]
    public async Task CompactAsync_Should_ThrowIfMessagesIsNull()
    {
        // Arrange
        IReadOnlyList<object> messages = null!;
        var systemPrompt = "You are a helpful assistant.";

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentNullException>(
            async () => await _compactor.CompactAsync(messages, systemPrompt, 165_000));
    }

    [Fact]
    public async Task CompactAsync_Should_ThrowIfSystemPromptIsNull()
    {
        // Arrange
        var messages = CreateMessageList(10);
        string systemPrompt = null!;

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentNullException>(
            async () => await _compactor.CompactAsync(messages, systemPrompt, 165_000));
    }

    [Fact]
    public async Task CompactAsync_Should_CallClaudeForSummarization()
    {
        // Arrange
        var messages = CreateMessageList(10);
        var systemPrompt = "You are a helpful assistant.";
        var currentTokenCount = 165_000;

        SetupMockForSummarization("Summary");
        _mockClaudeClient.CountTokensAsync(Arg.Any<IEnumerable<object>>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(80_000));

        // Act
        await _compactor.CompactAsync(messages, systemPrompt, currentTokenCount);

        // Assert
        // Should have called SendMessageAsync for summarization
        _ = _mockClaudeClient.Received(1).SendMessageAsync(
            Arg.Is<IEnumerable<object>>(m => m.Count() == 1),
            Arg.Is<string>(s => s.Contains("helpful assistant")),
            Arg.Is<object?>(o => o == null),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task CompactAsync_Should_CountTokensOfCompactedConversation()
    {
        // Arrange
        var messages = CreateMessageList(10);
        var systemPrompt = "You are a helpful assistant.";
        var currentTokenCount = 165_000;

        SetupMockForSummarization("Summary");
        _mockClaudeClient.CountTokensAsync(Arg.Any<IEnumerable<object>>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(80_000));

        // Act
        await _compactor.CompactAsync(messages, systemPrompt, currentTokenCount);

        // Assert
        await _mockClaudeClient.Received(1).CountTokensAsync(
            Arg.Is<IEnumerable<object>>(m => m.Count() == 8),
            systemPrompt,
            Arg.Any<CancellationToken>());
    }

    [Theory]
    [InlineData(6, 6, 0)]   // 6 messages → no summarization (short-circuit), return original 6 messages, 0 removed
    [InlineData(8, 8, 2)]   // 8 messages → summarize 2, keep last 6 → 1 summary + 1 ack + 6 kept = 8 total, 2 removed
    [InlineData(20, 8, 14)] // 20 messages → summarize 14, keep last 6 → 1 summary + 1 ack + 6 kept = 8 total, 14 removed
    public async Task CompactAsync_Should_HandleDifferentMessageCounts(
        int inputMessageCount,
        int expectedCompactedCount,
        int expectedRemoved)
    {
        // Arrange
        var messages = CreateMessageList(inputMessageCount);
        var systemPrompt = "You are a helpful assistant.";
        var currentTokenCount = 165_000;

        SetupMockForSummarization("Summary");
        _mockClaudeClient.CountTokensAsync(Arg.Any<IEnumerable<object>>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(80_000));

        // Act
        var result = await _compactor.CompactAsync(messages, systemPrompt, currentTokenCount);

        // Assert
        result.CompactedMessageCount.Should().Be(expectedCompactedCount);
        result.MessagesRemoved.Should().Be(expectedRemoved);
    }

    private static List<object> CreateMessageList(int count)
    {
        var messages = new List<object>();
        for (int i = 0; i < count; i++)
        {
            var role = i % 2 == 0 ? "user" : "assistant";
            messages.Add(new { role, content = $"Message {i}" });
        }

        return messages;
    }

    private void SetupMockForSummarization(string summaryText)
    {
        var events = new List<AgentEvent>
        {
            new TextDelta(summaryText),
            new FinalResponse(summaryText, "end_turn")
        };

        _mockClaudeClient.SendMessageAsync(
            Arg.Any<IEnumerable<object>>(),
            Arg.Any<string>(),
            Arg.Any<object?>(),
            Arg.Any<CancellationToken>())
            .Returns(events.ToAsyncEnumerable());
    }

    private static string GetMessageRole(object message)
    {
        var roleProperty = message.GetType().GetProperty("role");
        return roleProperty?.GetValue(message)?.ToString() ?? string.Empty;
    }

    private static string GetMessageContent(object message)
    {
        var contentProperty = message.GetType().GetProperty("content");
        return contentProperty?.GetValue(message)?.ToString() ?? string.Empty;
    }
}

/// <summary>
/// Integration tests for ContextCompactor to verify compacted conversations are well-formed.
/// </summary>
public sealed class ContextCompactorIntegrationTests
{
    [Fact]
    public async Task CompactedConversation_Should_BeWellFormedForClaudeAPI()
    {
        // Arrange
        var mockClient = Substitute.For<IClaudeClient>();
        var compactor = new ContextCompactor(mockClient);

        // Create a realistic conversation
        var messages = new List<object>
        {
            new { role = "user", content = "What is the capital of France?" },
            new { role = "assistant", content = "The capital of France is Paris." },
            new { role = "user", content = "What about Germany?" },
            new { role = "assistant", content = "The capital of Germany is Berlin." },
            new { role = "user", content = "And Italy?" },
            new { role = "assistant", content = "The capital of Italy is Rome." },
            new { role = "user", content = "List all three." },
            new { role = "assistant", content = "France: Paris, Germany: Berlin, Italy: Rome." },
            new { role = "user", content = "What about Spain?" },
            new { role = "assistant", content = "The capital of Spain is Madrid." },
        };

        var systemPrompt = "You are a helpful geography assistant.";

        // Mock the summarization response
        var summaryEvents = new List<AgentEvent>
        {
            new TextDelta("User asked about capitals: France (Paris), Germany (Berlin), Italy (Rome)."),
            new FinalResponse("User asked about capitals: France (Paris), Germany (Berlin), Italy (Rome).", "end_turn")
        };
        mockClient.SendMessageAsync(Arg.Any<IEnumerable<object>>(), Arg.Any<string>(), Arg.Any<object?>(), Arg.Any<CancellationToken>())
            .Returns(summaryEvents.ToAsyncEnumerable());

        // Mock token counting
        mockClient.CountTokensAsync(Arg.Any<IEnumerable<object>>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(50_000));

        // Act
        var result = await compactor.CompactAsync(messages, systemPrompt, 165_000);

        // Assert - Verify structure
        result.CompactedMessages.Should().HaveCountGreaterThanOrEqualTo(2, "should have at least summary + acknowledgment");

        // Verify first message is a user message with summary
        var firstMessage = result.CompactedMessages[0];
        GetMessageRole(firstMessage).Should().Be("user");
        GetMessageContent(firstMessage).Should().Contain("[Previous conversation summary]");

        // Verify second message is assistant acknowledgment
        var secondMessage = result.CompactedMessages[1];
        GetMessageRole(secondMessage).Should().Be("assistant");
        GetMessageContent(secondMessage).Should().Be("Understood. I have the context from our previous discussion.");

        // Verify alternating roles (required by Claude API)
        for (int i = 0; i < result.CompactedMessages.Count - 1; i++)
        {
            var currentRole = GetMessageRole(result.CompactedMessages[i]);
            var nextRole = GetMessageRole(result.CompactedMessages[i + 1]);
            currentRole.Should().NotBe(nextRole, $"messages at index {i} and {i + 1} should have different roles");
        }

        // Verify first message is from user (Claude API requirement)
        GetMessageRole(result.CompactedMessages[0]).Should().Be("user");
    }

    private static string GetMessageRole(object message)
    {
        var roleProperty = message.GetType().GetProperty("role");
        return roleProperty?.GetValue(message)?.ToString() ?? string.Empty;
    }

    private static string GetMessageContent(object message)
    {
        var contentProperty = message.GetType().GetProperty("content");
        return contentProperty?.GetValue(message)?.ToString() ?? string.Empty;
    }
}

/// <summary>
/// Extension methods for creating async enumerables from collections.
/// </summary>
internal static class AsyncEnumerableExtensions
{
    public static async IAsyncEnumerable<T> ToAsyncEnumerable<T>(this IEnumerable<T> source)
    {
        foreach (var item in source)
        {
            yield return item;
        }

        await Task.CompletedTask;
    }
}
