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

    [Fact]
    public void ExceedsHardLimit_Should_ReturnTrue_WhenOverMax()
    {
        // The default maxTokens is 200,000
        _compactor.ExceedsHardLimit(210_000).Should().BeTrue();
    }

    [Fact]
    public void ExceedsHardLimit_Should_ReturnFalse_WhenUnderMax()
    {
        _compactor.ExceedsHardLimit(190_000).Should().BeFalse();
    }

    [Fact]
    public void ExceedsHardLimit_Should_ReturnFalse_WhenExactlyAtMax()
    {
        _compactor.ExceedsHardLimit(200_000).Should().BeFalse();
    }

    [Fact]
    public void MaxTokens_Should_ReturnConfiguredValue()
    {
        _compactor.MaxTokens.Should().Be(200_000);

        var customCompactor = new ContextCompactor(_mockClaudeClient, maxTokens: 100_000);
        customCompactor.MaxTokens.Should().Be(100_000);
    }

    [Fact]
    public async Task PreCompactionFlush_Should_CallMemoryWriterWithExtractedContent()
    {
        // Arrange
        var messages = CreateMessageList(10);
        var systemPrompt = "You are a helpful assistant.";
        var currentTokenCount = 165_000;

        // Mock memory writer to capture the content
        string? capturedContent = null;
        Func<string, CancellationToken, Task> memoryWriter = (content, ct) =>
        {
            capturedContent = content;
            return Task.CompletedTask;
        };

        var compactorWithMemory = new ContextCompactor(
            _mockClaudeClient,
            maxTokens: 200_000,
            compactionThreshold: 0.80,
            messagesToKeep: 6,
            memoryWriter: memoryWriter);

        // Mock the memory extraction response
        var extractionEvents = new List<AgentEvent>
        {
            new TextDelta("## Session Context (auto-saved)\n- User asked about file operations\n- Created file at /path/to/file.txt"),
            new FinalResponse("## Session Context (auto-saved)\n- User asked about file operations\n- Created file at /path/to/file.txt", "end_turn")
        };

        // Setup mock to return extraction for first call, then summary for second call
        var callCount = 0;
        _mockClaudeClient.SendMessageAsync(
            Arg.Any<IEnumerable<object>>(),
            Arg.Any<string>(),
            Arg.Any<object?>(),
            Arg.Any<CancellationToken>())
            .Returns(callInfo =>
            {
                callCount++;
                if (callCount == 1)
                {
                    // First call: memory extraction
                    return extractionEvents.ToAsyncEnumerable();
                }
                else
                {
                    // Second call: summarization
                    var summaryEvents = new List<AgentEvent>
                    {
                        new TextDelta("Summary of conversation"),
                        new FinalResponse("Summary of conversation", "end_turn")
                    };
                    return summaryEvents.ToAsyncEnumerable();
                }
            });

        _mockClaudeClient.CountTokensAsync(Arg.Any<IEnumerable<object>>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(80_000));

        // Act
        await compactorWithMemory.CompactAsync(messages, systemPrompt, currentTokenCount);

        // Assert
        capturedContent.Should().NotBeNull();
        capturedContent.Should().Contain("Session Context (auto-saved)");
        capturedContent.Should().Contain("User asked about file operations");
    }

    [Fact]
    public async Task PreCompactionFlush_Should_SkipWhenDelegateIsNull()
    {
        // Arrange
        var messages = CreateMessageList(10);
        var systemPrompt = "You are a helpful assistant.";
        var currentTokenCount = 165_000;

        var compactorWithoutMemory = new ContextCompactor(
            _mockClaudeClient,
            maxTokens: 200_000,
            compactionThreshold: 0.80,
            messagesToKeep: 6,
            memoryWriter: null);

        SetupMockForSummarization("Summary text");
        _mockClaudeClient.CountTokensAsync(Arg.Any<IEnumerable<object>>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(80_000));

        // Act
        var result = await compactorWithoutMemory.CompactAsync(messages, systemPrompt, currentTokenCount);

        // Assert
        result.Should().NotBeNull();
        result.Summary.Should().Be("Summary text");

        // Should have called SendMessageAsync only once (for summarization, not for extraction)
        _ = _mockClaudeClient.Received(1).SendMessageAsync(
            Arg.Any<IEnumerable<object>>(),
            Arg.Any<string>(),
            Arg.Any<object?>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task PreCompactionFlush_Should_WrapContentInUntrustedTags()
    {
        // Arrange
        var messages = CreateMessageList(10);
        var systemPrompt = "You are a helpful assistant.";
        var currentTokenCount = 165_000;

        // Track the extraction request to verify untrusted_content wrapping
        IEnumerable<object>? extractionRequest = null;
        var callCount = 0;

        _mockClaudeClient.SendMessageAsync(
            Arg.Any<IEnumerable<object>>(),
            Arg.Any<string>(),
            Arg.Any<object?>(),
            Arg.Any<CancellationToken>())
            .Returns(callInfo =>
            {
                callCount++;
                if (callCount == 1)
                {
                    // Capture the extraction request
                    extractionRequest = callInfo.Arg<IEnumerable<object>>();

                    var extractionEvents = new List<AgentEvent>
                    {
                        new TextDelta("## Session Context (auto-saved)\n- Some context"),
                        new FinalResponse("## Session Context (auto-saved)\n- Some context", "end_turn")
                    };
                    return extractionEvents.ToAsyncEnumerable();
                }
                else
                {
                    var summaryEvents = new List<AgentEvent>
                    {
                        new TextDelta("Summary"),
                        new FinalResponse("Summary", "end_turn")
                    };
                    return summaryEvents.ToAsyncEnumerable();
                }
            });

        _mockClaudeClient.CountTokensAsync(Arg.Any<IEnumerable<object>>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(80_000));

        Func<string, CancellationToken, Task> memoryWriter = (content, ct) => Task.CompletedTask;

        var compactorWithMemory = new ContextCompactor(
            _mockClaudeClient,
            maxTokens: 200_000,
            memoryWriter: memoryWriter);

        // Act
        await compactorWithMemory.CompactAsync(messages, systemPrompt, currentTokenCount);

        // Assert
        extractionRequest.Should().NotBeNull();
        var firstMessage = extractionRequest!.First();
        var content = GetMessageContent(firstMessage);
        content.Should().Contain("<untrusted_content>");
        content.Should().Contain("</untrusted_content>");
        content.Should().Contain("<conversation_to_extract>");
        content.Should().Contain("</conversation_to_extract>");
    }

    [Fact]
    public async Task PreCompactionFlush_Should_ContinueOnFailure()
    {
        // Arrange
        var messages = CreateMessageList(10);
        var systemPrompt = "You are a helpful assistant.";
        var currentTokenCount = 165_000;

        // Memory writer that throws an exception
        Func<string, CancellationToken, Task> faultyMemoryWriter = (content, ct) =>
        {
            throw new InvalidOperationException("Memory write failed");
        };

        var compactorWithFaultyMemory = new ContextCompactor(
            _mockClaudeClient,
            maxTokens: 200_000,
            memoryWriter: faultyMemoryWriter);

        // Mock extraction response (will succeed, but writing will fail)
        var callCount = 0;
        _mockClaudeClient.SendMessageAsync(
            Arg.Any<IEnumerable<object>>(),
            Arg.Any<string>(),
            Arg.Any<object?>(),
            Arg.Any<CancellationToken>())
            .Returns(callInfo =>
            {
                callCount++;
                if (callCount == 1)
                {
                    var extractionEvents = new List<AgentEvent>
                    {
                        new TextDelta("## Session Context (auto-saved)\n- Some context"),
                        new FinalResponse("## Session Context (auto-saved)\n- Some context", "end_turn")
                    };
                    return extractionEvents.ToAsyncEnumerable();
                }
                else
                {
                    var summaryEvents = new List<AgentEvent>
                    {
                        new TextDelta("Summary"),
                        new FinalResponse("Summary", "end_turn")
                    };
                    return summaryEvents.ToAsyncEnumerable();
                }
            });

        _mockClaudeClient.CountTokensAsync(Arg.Any<IEnumerable<object>>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(80_000));

        // Act & Assert - should not throw, compaction should proceed
        var result = await compactorWithFaultyMemory.CompactAsync(messages, systemPrompt, currentTokenCount);

        result.Should().NotBeNull();
        result.Summary.Should().Be("Summary");
        result.CompactedMessages.Should().NotBeEmpty();
    }

    [Fact]
    public async Task PreCompactionFlush_Should_SkipWhenNoMessagesToSummarize()
    {
        // Arrange
        var messages = CreateMessageList(4); // Less than messagesToKeep (6)
        var systemPrompt = "You are a helpful assistant.";
        var currentTokenCount = 165_000;

        var memoryWriterCalled = false;
        Func<string, CancellationToken, Task> memoryWriter = (content, ct) =>
        {
            memoryWriterCalled = true;
            return Task.CompletedTask;
        };

        var compactorWithMemory = new ContextCompactor(
            _mockClaudeClient,
            maxTokens: 200_000,
            memoryWriter: memoryWriter);

        // Act
        var result = await compactorWithMemory.CompactAsync(messages, systemPrompt, currentTokenCount);

        // Assert
        result.Should().NotBeNull();
        result.CompactedMessages.Should().HaveCount(4); // No compaction performed
        memoryWriterCalled.Should().BeFalse(); // Memory writer should not be called
    }

    [Fact]
    public async Task TruncateToFitAsync_Should_DropOldestMessagesUntilUnderLimit()
    {
        // Arrange
        var messages = CreateMessageList(10);
        var systemPrompt = "You are a helpful assistant.";

        // First call: still over limit (10 messages → 210K)
        // Second call: still over limit (8 messages → 205K)
        // Third call: under limit (6 messages → 150K)
        var callCount = 0;
        _mockClaudeClient.CountTokensAsync(
            Arg.Any<IEnumerable<object>>(),
            Arg.Any<string>(),
            Arg.Any<CancellationToken>())
            .Returns(callInfo =>
            {
                callCount++;
                return callCount switch
                {
                    1 => Task.FromResult(210_000),
                    2 => Task.FromResult(205_000),
                    _ => Task.FromResult(150_000)
                };
            });

        // Act
        var result = await _compactor.TruncateToFitAsync(messages, systemPrompt);

        // Assert — should have dropped 4 messages (2 pairs) from the front
        result.Should().HaveCount(6);
    }

    [Fact]
    public async Task TruncateToFitAsync_Should_ReturnImmediately_WhenAlreadyUnderLimit()
    {
        // Arrange
        var messages = CreateMessageList(8);
        var systemPrompt = "You are a helpful assistant.";

        _mockClaudeClient.CountTokensAsync(
            Arg.Any<IEnumerable<object>>(),
            Arg.Any<string>(),
            Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(150_000));

        // Act
        var result = await _compactor.TruncateToFitAsync(messages, systemPrompt);

        // Assert — no truncation needed
        result.Should().HaveCount(8);
    }

    [Fact]
    public async Task TruncateToFitAsync_Should_StopAtMinimumTwoMessages()
    {
        // Arrange
        var messages = CreateMessageList(10);
        var systemPrompt = "You are a helpful assistant.";

        // Always over limit — should stop at 2 messages
        _mockClaudeClient.CountTokensAsync(
            Arg.Any<IEnumerable<object>>(),
            Arg.Any<string>(),
            Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(250_000));

        // Act
        var result = await _compactor.TruncateToFitAsync(messages, systemPrompt);

        // Assert — should never go below 2 messages
        result.Should().HaveCount(2);
    }

    [Fact]
    public async Task TruncateToFitAsync_Should_DropOrphanedToolResultAfterTruncation()
    {
        // Arrange — simulate a conversation where truncation leaves a tool_result at front:
        // [user, assistant(tool_use), user(tool_result), assistant, user, assistant, user, assistant]
        // After dropping first 2 → [user(tool_result), assistant, user, assistant, user, assistant]
        // The orphaned tool_result should be dropped too → [user, assistant, user, assistant]
        var messages = new List<object>
        {
            new { role = "user", content = "Do something" },
            new { role = "assistant", content = new object[] {
                new { type = "text", text = "I'll search" },
                new { type = "tool_use", id = "toolu_001", name = "search", input = "{}" }
            }},
            new { role = "user", content = new object[] {
                new { type = "tool_result", tool_use_id = "toolu_001", content = "results" }
            }},
            new { role = "assistant", content = "Here are the results." },
            new { role = "user", content = "Thanks" },
            new { role = "assistant", content = "You're welcome." },
            new { role = "user", content = "One more question" },
            new { role = "assistant", content = "Sure, ask away." },
        };
        var systemPrompt = "You are a helpful assistant.";

        // First call (8 msgs): over limit → drop 2 → leaves tool_result at front → drop 2 more
        // Second call (4 msgs): under limit
        var callCount = 0;
        _mockClaudeClient.CountTokensAsync(
            Arg.Any<IEnumerable<object>>(),
            Arg.Any<string>(),
            Arg.Any<CancellationToken>())
            .Returns(callInfo =>
            {
                callCount++;
                return callCount switch
                {
                    1 => Task.FromResult(210_000),
                    _ => Task.FromResult(150_000)
                };
            });

        // Act
        var result = await _compactor.TruncateToFitAsync(messages, systemPrompt);

        // Assert — the orphaned tool_result + its assistant response should be dropped
        result.Should().HaveCount(4);
        // First message should be a clean user message, not a tool_result
        var firstRole = result[0].GetType().GetProperty("role")?.GetValue(result[0])?.ToString();
        firstRole.Should().Be("user");
        var firstContent = result[0].GetType().GetProperty("content")?.GetValue(result[0]);
        firstContent.Should().BeOfType<string>(); // Not an array with tool_result blocks
    }

    [Fact]
    public async Task CompactAsync_Should_IncludeToolUseWhenKeptMessagesStartWithToolResult()
    {
        // Arrange — create a conversation where the last 6 messages start with tool_result
        // Messages: [user, assistant, user, assistant(tool_use), user(tool_result), assistant,
        //            user, assistant, user, assistant]
        // Keep last 6: [user(tool_result), assistant, user, assistant, user, assistant]
        // → Should pull assistant(tool_use) into kept set
        var messages = new List<object>
        {
            new { role = "user", content = "Start" },
            new { role = "assistant", content = "OK" },
            new { role = "user", content = "Search for something" },
            new { role = "assistant", content = new object[] {
                new { type = "text", text = "Searching" },
                new { type = "tool_use", id = "toolu_002", name = "search", input = "{}" }
            }},
            new { role = "user", content = new object[] {
                new { type = "tool_result", tool_use_id = "toolu_002", content = "found it" }
            }},
            new { role = "assistant", content = "Found results." },
            new { role = "user", content = "Great" },
            new { role = "assistant", content = "Anything else?" },
            new { role = "user", content = "No thanks" },
            new { role = "assistant", content = "Goodbye!" },
        };
        var systemPrompt = "You are a helpful assistant.";

        SetupMockForSummarization("Summary of early conversation.");
        _mockClaudeClient.CountTokensAsync(Arg.Any<IEnumerable<object>>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(80_000));

        // Act
        var result = await _compactor.CompactAsync(messages, systemPrompt, 165_000);

        // Assert — the kept messages should include the tool_use assistant message
        // Compacted: [summary(user), ack(assistant), assistant(tool_use), user(tool_result), ...]
        // First message should be summary
        var first = result.CompactedMessages[0];
        GetMessageRole(first).Should().Be("user");
        GetMessageContent(first).Should().Contain("[Previous conversation summary]");

        // The compacted conversation should NOT have any orphaned tool_result
        // (i.e., every tool_result should have a preceding tool_use)
        for (int i = 0; i < result.CompactedMessages.Count; i++)
        {
            var msg = result.CompactedMessages[i];
            var role = GetMessageRole(msg);
            var contentProp = msg.GetType().GetProperty("content")?.GetValue(msg);

            if (role == "user" && contentProp is System.Collections.IEnumerable blocks and not string)
            {
                // This is a user message with complex content — check for tool_result
                foreach (var block in blocks)
                {
                    var typeVal = block.GetType().GetProperty("type")?.GetValue(block)?.ToString();
                    if (typeVal == "tool_result")
                    {
                        // Must have a preceding assistant message (i-1) with tool_use
                        i.Should().BeGreaterThan(0, "tool_result must not be the first message");
                        var prevRole = GetMessageRole(result.CompactedMessages[i - 1]);
                        prevRole.Should().Be("assistant", "message before tool_result must be assistant");
                    }
                }
            }
        }
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
