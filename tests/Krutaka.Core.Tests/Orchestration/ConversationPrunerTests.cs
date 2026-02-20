#pragma warning disable CA2007 // Do not directly await a Task in tests
using System.Text.Json;
using FluentAssertions;
using Krutaka.Core;

namespace Krutaka.Core.Tests;

/// <summary>
/// Unit tests for conversation pruning functionality in AgentOrchestrator.
/// Tests the PruneOldToolResults method via reflection to validate immutability,
/// turn counting, and tool result pruning logic.
/// </summary>
public sealed class ConversationPrunerTests
{
    [Fact]
    public void PruneOldToolResults_Should_PruneToolResultsOlderThanThreshold()
    {
        // Arrange
        var messages = new List<object>
        {
            // Turn 0 - Old turn with large tool result (should be pruned)
            CreateUserMessage("Task 1"),
            CreateAssistantMessage("Working on task 1", [CreateToolCall("tool_01", "read_file", "{}")]),
            CreateUserMessageWithToolResults([CreateToolResult("tool_01", new string('x', 2000), isError: false)]),
            
            // Turn 1 - Recent turn (should NOT be pruned)
            CreateUserMessage("Task 2"),
            CreateAssistantMessage("Working on task 2", [CreateToolCall("tool_02", "read_file", "{}")]),
            CreateUserMessageWithToolResults([CreateToolResult("tool_02", new string('y', 2000), isError: false)]),
        };

        // Act - current turn = 2 (2 user prompts in history), prune after 1 turn, min 1000 chars
        // Turn 0 age = 2 - 0 = 2, which is > 1, so it should be pruned
        // Turn 1 age = 2 - 1 = 1, which is NOT > 1, so it should NOT be pruned
        var pruned = InvokePruneOldToolResults(messages, currentTurnIndex: 2, pruneAfterTurns: 1, pruneMinChars: 1000);

        // Assert - Turn 0 result should be pruned, Turn 1 should not
        var turn0Result = GetToolResultContent(pruned, messageIndex: 2);
        turn0Result.Should().StartWith("[Previous tool result truncated");
        turn0Result.Should().Contain("2,000 chars");

        var turn1Result = GetToolResultContent(pruned, messageIndex: 5);
        turn1Result.Should().Be(new string('y', 2000)); // Unchanged
    }

    [Fact]
    public void PruneOldToolResults_Should_NotPruneToolResultsWithinThreshold()
    {
        // Arrange
        var messages = new List<object>
        {
            CreateUserMessage("Recent task"),
            CreateAssistantMessage("Working", [CreateToolCall("tool_01", "read_file", "{}")]),
            CreateUserMessageWithToolResults([CreateToolResult("tool_01", new string('x', 2000), isError: false)]),
        };

        // Act - current turn = 1, prune after 6 turns (default)
        var pruned = InvokePruneOldToolResults(messages, currentTurnIndex: 1, pruneAfterTurns: 6, pruneMinChars: 1000);

        // Assert - Should not be pruned (age = 0)
        var result = GetToolResultContent(pruned, messageIndex: 2);
        result.Should().Be(new string('x', 2000)); // Unchanged
    }

    [Fact]
    public void PruneOldToolResults_Should_NotPruneSmallToolResults()
    {
        // Arrange
        var messages = new List<object>
        {
            // Old turn with small result (< 1000 chars)
            CreateUserMessage("Task 1"),
            CreateAssistantMessage("Working", [CreateToolCall("tool_01", "read_file", "{}")]),
            CreateUserMessageWithToolResults([CreateToolResult("tool_01", new string('x', 500), isError: false)]),
        };

        // Act - current turn = 1, prune after 0 turns (everything old), but min 1000 chars
        var pruned = InvokePruneOldToolResults(messages, currentTurnIndex: 1, pruneAfterTurns: 0, pruneMinChars: 1000);

        // Assert - Should not be pruned (too small)
        var result = GetToolResultContent(pruned, messageIndex: 2);
        result.Should().Be(new string('x', 500)); // Unchanged
    }

    [Fact]
    public void PruneOldToolResults_Should_PruneErrorResultsWithErrorMessage()
    {
        // Arrange
        var messages = new List<object>
        {
            // Old turn with error result
            CreateUserMessage("Failed task"),
            CreateAssistantMessage("Trying", [CreateToolCall("tool_01", "run_command", "{}")]),
            CreateUserMessageWithToolResults([CreateToolResult("tool_01", new string('e', 2000), isError: true)]),
        };

        // Act - current turn = 1, prune after 0 turns
        var pruned = InvokePruneOldToolResults(messages, currentTurnIndex: 1, pruneAfterTurns: 0, pruneMinChars: 1000);

        // Assert - Error result should have error-specific message
        var result = GetToolResultContent(pruned, messageIndex: 2);
        result.Should().StartWith("[Previous tool error truncated");
        result.Should().Contain("2,000 chars");
        result.Should().Contain("1 turn ago");
    }

    [Fact]
    public void PruneOldToolResults_Should_ReturnNewList()
    {
        // Arrange
        var messages = new List<object>
        {
            CreateUserMessage("Task"),
            CreateAssistantMessage("Working", [CreateToolCall("tool_01", "read_file", "{}")]),
            CreateUserMessageWithToolResults([CreateToolResult("tool_01", new string('x', 2000), isError: false)]),
        };

        // Act
        var pruned = InvokePruneOldToolResults(messages, currentTurnIndex: 1, pruneAfterTurns: 0, pruneMinChars: 1000);

        // Assert - Should return a different list instance
        pruned.Should().NotBeSameAs(messages);
        
        // Original list should be unmodified
        var originalResult = GetToolResultContent(messages, messageIndex: 2);
        originalResult.Should().Be(new string('x', 2000)); // Still has original content
    }

    [Fact]
    public void PruneOldToolResults_Should_NotModifyMessagesWithoutToolResults()
    {
        // Arrange
        var messages = new List<object>
        {
            CreateUserMessage("Simple user message"),
            CreateAssistantMessage("Simple assistant response", []),
        };

        // Act
        var pruned = InvokePruneOldToolResults(messages, currentTurnIndex: 1, pruneAfterTurns: 0, pruneMinChars: 1000);

        // Assert - Messages should be unchanged
        pruned.Should().HaveCount(2);
        var userMsg = JsonSerializer.Serialize(pruned[0]);
        userMsg.Should().Contain("Simple user message");
    }

    [Fact]
    public void PruneOldToolResults_Should_CalculateTurnAgeCorrectly()
    {
        // Arrange - 4 user prompts in history
        var messages = new List<object>
        {
            // Turn 0
            CreateUserMessage("Task 0"),
            // Turn 1
            CreateUserMessage("Task 1"),
            // Turn 2
            CreateUserMessage("Task 2"),
            // Turn 3 with tool result
            CreateUserMessage("Task 3"),
            CreateAssistantMessage("Working", [CreateToolCall("tool_01", "read_file", "{}")]),
            CreateUserMessageWithToolResults([CreateToolResult("tool_01", new string('x', 2000), isError: false)]),
        };

        // Act - current turn = 4 (4 user prompts), prune after 2 turns
        // Turn 3 age = 4 - 3 = 1, which is NOT > 2, so it should NOT be pruned
        // But let's use turn 0 instead which should be pruned
        // Turn 0 age = 4 - 0 = 4, which is > 2, so it WOULD be pruned if it had a tool result
        
        // Actually, the tool result is associated with turn 3
        // Turn 3 age = 4 - 3 = 1, which is NOT > 2
        // So this test needs adjustment. Let's make currentTurnIndex larger.
        var pruned = InvokePruneOldToolResults(messages, currentTurnIndex: 7, pruneAfterTurns: 2, pruneMinChars: 1000);

        // Assert - Turn 3 result should be pruned (age = 7 - 3 = 4 turns, which is > 2)
        var result = GetToolResultContent(pruned, messageIndex: 5);
        result.Should().StartWith("[Previous tool result truncated");
    }

    [Fact]
    public void PruneOldToolResults_Should_HandleMultipleToolResultsInOneMessage()
    {
        // Arrange
        var messages = new List<object>
        {
            CreateUserMessage("Multi-tool task"),
            CreateAssistantMessage("Working", [
                CreateToolCall("tool_01", "read_file", "{}"),
                CreateToolCall("tool_02", "read_file", "{}")
            ]),
            CreateUserMessageWithToolResults([
                CreateToolResult("tool_01", new string('x', 2000), isError: false),
                CreateToolResult("tool_02", new string('y', 500), isError: false), // Small result
            ]),
        };

        // Act - prune after 0 turns
        var pruned = InvokePruneOldToolResults(messages, currentTurnIndex: 1, pruneAfterTurns: 0, pruneMinChars: 1000);

        // Assert - Large result pruned, small result kept
        var prunedMessage = pruned[2];
        var json = JsonSerializer.Serialize(prunedMessage);
        json.Should().Contain("[Previous tool result truncated"); // First result pruned
        json.Should().Contain(new string('y', 500)); // Second result unchanged
    }

    [Fact]
    public void PruneOldToolResults_Should_PreserveToolUseIdInPrunedResults()
    {
        // Arrange
        var messages = new List<object>
        {
            CreateUserMessage("Task"),
            CreateAssistantMessage("Working", [CreateToolCall("tool_123", "read_file", "{}")]),
            CreateUserMessageWithToolResults([CreateToolResult("tool_123", new string('x', 2000), isError: false)]),
        };

        // Act
        var pruned = InvokePruneOldToolResults(messages, currentTurnIndex: 1, pruneAfterTurns: 0, pruneMinChars: 1000);

        // Assert - tool_use_id should be preserved
        var json = JsonSerializer.Serialize(pruned[2]);
        json.Should().Contain("\"tool_use_id\":\"tool_123\"");
    }

    [Fact]
    public void PruneOldToolResults_Should_PreserveIsErrorFlagInPrunedResults()
    {
        // Arrange
        var messages = new List<object>
        {
            CreateUserMessage("Task"),
            CreateAssistantMessage("Working", [CreateToolCall("tool_01", "run_command", "{}")]),
            CreateUserMessageWithToolResults([CreateToolResult("tool_01", new string('e', 2000), isError: true)]),
        };

        // Act
        var pruned = InvokePruneOldToolResults(messages, currentTurnIndex: 1, pruneAfterTurns: 0, pruneMinChars: 1000);

        // Assert - is_error should still be true
        var json = JsonSerializer.Serialize(pruned[2]);
        json.Should().Contain("\"is_error\":true");
    }

    [Fact]
    public void PruneOldToolResults_Should_PreserveAnonymousObjectTypeForSmallToolResults()
    {
        // Arrange - small tool result that should not be pruned
        var messages = new List<object>
        {
            CreateUserMessage("Task"),
            CreateAssistantMessage("Working", [CreateToolCall("tool_01", "read_file", "{}")]),
            CreateUserMessageWithToolResults([CreateToolResult("tool_01", "small content", isError: false)]),
        };

        // Act - prune after 0 turns, but content is too small
        var pruned = InvokePruneOldToolResults(messages, currentTurnIndex: 1, pruneAfterTurns: 0, pruneMinChars: 1000);

        // Assert - verify the result is an anonymous object with type property accessible via reflection
        var prunedMessage = pruned[2];
        var json = JsonSerializer.Serialize(prunedMessage);
        using var doc = JsonDocument.Parse(json);
        var content = doc.RootElement.GetProperty("content");
        
        foreach (var block in content.EnumerateArray())
        {
            // Verify we can access type property
            block.TryGetProperty("type", out var type).Should().BeTrue();
            type.GetString().Should().Be("tool_result");
            
            // Verify tool_use_id is preserved
            block.TryGetProperty("tool_use_id", out var toolUseId).Should().BeTrue();
            toolUseId.GetString().Should().Be("tool_01");
            
            // Verify content is preserved
            block.TryGetProperty("content", out var contentProp).Should().BeTrue();
            contentProp.GetString().Should().Be("small content");
        }

        // Verify the pruned message can be serialized back to an object with reflectable properties
        // This test ensures the block is not a JsonElement which would lose type information
        var messageType = prunedMessage.GetType();
        var contentProperty = messageType.GetProperty("content");
        contentProperty.Should().NotBeNull();
        
        var contentValue = contentProperty!.GetValue(prunedMessage);
        contentValue.Should().NotBeNull();
        
        // The content should be an enumerable of anonymous objects
        if (contentValue is System.Collections.IEnumerable enumerable)
        {
            var firstBlock = enumerable.Cast<object>().First();
            var firstBlockType = firstBlock.GetType();
            
            // Verify we can reflect on the type property (not JsonElement)
            var typeProperty = firstBlockType.GetProperty("type");
            typeProperty.Should().NotBeNull("block should have reflectable type property");
            typeProperty!.GetValue(firstBlock).Should().Be("tool_result");
        }
    }

    [Fact]
    public void PruneOldToolResults_Should_PreserveTextBlocksWithReflectableType()
    {
        // Arrange - message with text block and tool result
        var messages = new List<object>
        {
            CreateUserMessage("Task"),
            CreateAssistantMessage("Thinking...", [CreateToolCall("tool_01", "read_file", "{}")]),
            CreateUserMessageWithToolResults([CreateToolResult("tool_01", "small", isError: false)]),
        };

        // Act
        var pruned = InvokePruneOldToolResults(messages, currentTurnIndex: 1, pruneAfterTurns: 0, pruneMinChars: 1000);

        // Assert - verify assistant message text block is preserved with reflectable type
        var assistantMessage = pruned[1];
        var messageType = assistantMessage.GetType();
        var contentProperty = messageType.GetProperty("content");
        
        var contentValue = contentProperty!.GetValue(assistantMessage);
        if (contentValue is System.Collections.IEnumerable enumerable)
        {
            var textBlock = enumerable.Cast<object>().First();
            var textBlockType = textBlock.GetType();
            
            // Verify text block has reflectable type property
            var typeProperty = textBlockType.GetProperty("type");
            typeProperty.Should().NotBeNull("text block should have reflectable type property");
            typeProperty!.GetValue(textBlock).Should().Be("text");
            
            // Verify text property is accessible
            var textProperty = textBlockType.GetProperty("text");
            textProperty.Should().NotBeNull();
            textProperty!.GetValue(textBlock).Should().Be("Thinking...");
        }
    }

    // Helper methods

    private static List<object> InvokePruneOldToolResults(
        List<object> messages,
        int currentTurnIndex,
        int pruneAfterTurns,
        int pruneMinChars)
    {
        // Use reflection to invoke the private static PruneOldToolResults method
        var method = typeof(AgentOrchestrator).GetMethod(
            "PruneOldToolResults",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);

        method.Should().NotBeNull("PruneOldToolResults method should exist");

        var result = method!.Invoke(null, [messages, currentTurnIndex, pruneAfterTurns, pruneMinChars]);
        return (List<object>)result!;
    }

    private static object CreateUserMessage(string text)
    {
        return new
        {
            role = "user",
            content = text
        };
    }

    private static object CreateAssistantMessage(string text, List<object> toolCalls)
    {
        var contentBlocks = new List<object>();

        if (!string.IsNullOrEmpty(text))
        {
            contentBlocks.Add(new { type = "text", text });
        }

        contentBlocks.AddRange(toolCalls);

        return new
        {
            role = "assistant",
            content = contentBlocks
        };
    }

    private static object CreateToolCall(string id, string name, string input)
    {
        return new
        {
            type = "tool_use",
            id,
            name,
            input = JsonSerializer.Deserialize<JsonElement>(input)
        };
    }

    private static object CreateUserMessageWithToolResults(List<object> toolResults)
    {
        return new
        {
            role = "user",
            content = toolResults
        };
    }

    private static object CreateToolResult(string toolUseId, string content, bool isError)
    {
        return new
        {
            type = "tool_result",
            tool_use_id = toolUseId,
            content,
            is_error = isError
        };
    }

    private static string GetToolResultContent(List<object> messages, int messageIndex)
    {
        var message = messages[messageIndex];
        var json = JsonSerializer.Serialize(message);
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        // Get content array
        var content = root.GetProperty("content");
        
        // Find first tool_result block
        foreach (var block in content.EnumerateArray())
        {
            if (block.TryGetProperty("type", out var type) && type.GetString() == "tool_result")
            {
                return block.GetProperty("content").GetString()!;
            }
        }

        throw new InvalidOperationException("No tool_result found in message");
    }

    // ============================================================================
    // ADVERSARIAL TESTS - Edge cases and boundary conditions for pruning
    // ============================================================================

    [Fact]
    public void PruneOldToolResults_Should_HandleEmptyConversation_NoCrash()
    {
        // Arrange - empty conversation (edge case)
        var messages = new List<object>();

        // Act - should not crash with empty list
        var pruned = InvokePruneOldToolResults(messages, currentTurnIndex: 0, pruneAfterTurns: 6, pruneMinChars: 1000);

        // Assert
        pruned.Should().NotBeNull();
        pruned.Should().BeEmpty();
    }

    [Fact]
    public void PruneOldToolResults_Should_PruneConversationWithOnlyToolResultMessages()
    {
        // Arrange - conversation with only tool_result messages (unusual but valid)
        var messages = new List<object>
        {
            CreateUserMessageWithToolResults([CreateToolResult("tool_01", new string('x', 2000), isError: false)]),
            CreateUserMessageWithToolResults([CreateToolResult("tool_02", new string('y', 2000), isError: false)]),
            CreateUserMessageWithToolResults([CreateToolResult("tool_03", new string('z', 2000), isError: false)]),
        };

        // Act - prune after 0 turns (all results are "old")
        var pruned = InvokePruneOldToolResults(messages, currentTurnIndex: 3, pruneAfterTurns: 0, pruneMinChars: 1000);

        // Assert - All tool results should be pruned (no user prompts to associate with turns)
        // Note: Since there are no user prompts, currentTurnIndex doesn't map to these messages
        // The pruner should handle this gracefully
        pruned.Should().HaveCount(3);

        // All tool results should be pruned since they're larger than min chars
        var result1 = GetToolResultContent(pruned, messageIndex: 0);
        result1.Should().StartWith("[Previous tool result truncated");

        var result2 = GetToolResultContent(pruned, messageIndex: 1);
        result2.Should().StartWith("[Previous tool result truncated");

        var result3 = GetToolResultContent(pruned, messageIndex: 2);
        result3.Should().StartWith("[Previous tool result truncated");
    }

    [Fact]
    public void PruneOldToolResults_Should_NotPruneToolResultAtExactlyMinCharsThreshold()
    {
        // Arrange - tool result with exactly min chars (boundary test)
        var messages = new List<object>
        {
            CreateUserMessage("Task"),
            CreateAssistantMessage("Working", [CreateToolCall("tool_01", "read_file", "{}")]),
            CreateUserMessageWithToolResults([CreateToolResult("tool_01", new string('x', 1000), isError: false)]), // Exactly 1000 chars
        };

        // Act - prune after 0 turns, min 1000 chars
        var pruned = InvokePruneOldToolResults(messages, currentTurnIndex: 1, pruneAfterTurns: 0, pruneMinChars: 1000);

        // Assert - Should NOT be pruned (exactly at boundary)
        var result = GetToolResultContent(pruned, messageIndex: 2);
        result.Should().Be(new string('x', 1000), "result at exactly min chars should NOT be pruned");
    }

    [Fact]
    public void PruneOldToolResults_Should_PruneToolResultWithMinCharsPlusOne()
    {
        // Arrange - tool result with min chars + 1 (just over threshold)
        var messages = new List<object>
        {
            CreateUserMessage("Task"),
            CreateAssistantMessage("Working", [CreateToolCall("tool_01", "read_file", "{}")]),
            CreateUserMessageWithToolResults([CreateToolResult("tool_01", new string('x', 1001), isError: false)]), // 1001 chars
        };

        // Act - prune after 0 turns, min 1000 chars
        var pruned = InvokePruneOldToolResults(messages, currentTurnIndex: 1, pruneAfterTurns: 0, pruneMinChars: 1000);

        // Assert - Should be pruned (over threshold by 1 char)
        var result = GetToolResultContent(pruned, messageIndex: 2);
        result.Should().StartWith("[Previous tool result truncated", "result with min chars + 1 should be pruned");
        result.Should().Contain("1,001 chars");
    }

    [Fact]
    public void PruneOldToolResults_Should_PruneOnlyToolResultInMixedContentBlocks()
    {
        // Arrange - user message with mixed content: text + tool_result
        var messages = new List<object>
        {
            CreateUserMessage("Initial task"),
            CreateAssistantMessage("Working", [CreateToolCall("tool_01", "read_file", "{}")]),
            // User message with both text and tool_result
            new
            {
                role = "user",
                content = new object[]
                {
                    new { type = "text", text = "Here's some user commentary" },
                    new { type = "tool_result", tool_use_id = "tool_01", content = new string('x', 2000), is_error = false }
                }
            }
        };

        // Act - prune after 0 turns
        var pruned = InvokePruneOldToolResults(messages, currentTurnIndex: 1, pruneAfterTurns: 0, pruneMinChars: 1000);

        // Assert - Only tool_result should be pruned, text should be preserved
        var prunedMessage = pruned[2];
        var json = JsonSerializer.Serialize(prunedMessage);
        using var doc = JsonDocument.Parse(json);
        var content = doc.RootElement.GetProperty("content");

        content.GetArrayLength().Should().Be(2, "should have both text and tool_result blocks");

        // Verify text block is unchanged
        var textBlock = content[0];
        textBlock.GetProperty("type").GetString().Should().Be("text");
        textBlock.GetProperty("text").GetString().Should().Be("Here's some user commentary");

        // Verify tool_result is pruned
        var toolResultBlock = content[1];
        toolResultBlock.GetProperty("type").GetString().Should().Be("tool_result");
        toolResultBlock.GetProperty("content").GetString().Should().StartWith("[Previous tool result truncated");
    }

    [Fact]
    public void PruneOldToolResults_Should_HandleMessageWithNoContentProperty()
    {
        // Arrange - edge case: message without content property (should not crash)
        var messages = new List<object>
        {
            new { role = "user" }, // No content property
        };

        // Act - should handle gracefully without crashing
        var pruned = InvokePruneOldToolResults(messages, currentTurnIndex: 0, pruneAfterTurns: 6, pruneMinChars: 1000);

        // Assert
        pruned.Should().HaveCount(1);
    }

    [Fact]
    public void PruneOldToolResults_Should_HandleMultipleToolResultsWithMixedSizes()
    {
        // Arrange - multiple tool results, some below threshold, some above
        var messages = new List<object>
        {
            CreateUserMessage("Multi-tool task"),
            CreateAssistantMessage("Working", [
                CreateToolCall("tool_01", "read_file", "{}"),
                CreateToolCall("tool_02", "read_file", "{}"),
                CreateToolCall("tool_03", "read_file", "{}")
            ]),
            CreateUserMessageWithToolResults([
                CreateToolResult("tool_01", new string('x', 500), isError: false),  // Small (< 1000)
                CreateToolResult("tool_02", new string('y', 2000), isError: false), // Large (> 1000)
                CreateToolResult("tool_03", new string('z', 999), isError: false),  // Just under threshold
            ]),
        };

        // Act - prune after 0 turns
        var pruned = InvokePruneOldToolResults(messages, currentTurnIndex: 1, pruneAfterTurns: 0, pruneMinChars: 1000);

        // Assert - Only tool_02 (2000 chars) should be pruned
        var json = JsonSerializer.Serialize(pruned[2]);

        json.Should().Contain(new string('x', 500), "small result should be preserved");
        json.Should().Contain("[Previous tool result truncated", "large result should be pruned");
        json.Should().Contain(new string('z', 999), "result just under threshold should be preserved");
    }

    [Fact]
    public void PruneOldToolResults_Should_PreserveStructureForZeroLengthToolResult()
    {
        // Arrange - tool result with zero-length content (edge case)
        var messages = new List<object>
        {
            CreateUserMessage("Task"),
            CreateAssistantMessage("Working", [CreateToolCall("tool_01", "test_tool", "{}")]),
            CreateUserMessageWithToolResults([CreateToolResult("tool_01", "", isError: false)]), // Empty content
        };

        // Act
        var pruned = InvokePruneOldToolResults(messages, currentTurnIndex: 1, pruneAfterTurns: 0, pruneMinChars: 1000);

        // Assert - Should not prune empty content (below threshold)
        var result = GetToolResultContent(pruned, messageIndex: 2);
        result.Should().BeEmpty("zero-length content should be preserved");
    }

    [Fact]
    public void PruneOldToolResults_Should_HandleVeryLargeToolResult_10MB()
    {
        // Arrange - extremely large tool result (10MB - stress test)
        var largeContent = new string('x', 10 * 1024 * 1024); // 10 MB
        var messages = new List<object>
        {
            CreateUserMessage("Task"),
            CreateAssistantMessage("Working", [CreateToolCall("tool_01", "read_file", "{}")]),
            CreateUserMessageWithToolResults([CreateToolResult("tool_01", largeContent, isError: false)]),
        };

        // Act - prune after 0 turns
        var pruned = InvokePruneOldToolResults(messages, currentTurnIndex: 1, pruneAfterTurns: 0, pruneMinChars: 1000);

        // Assert - Should be pruned with correct size notation
        var result = GetToolResultContent(pruned, messageIndex: 2);
        result.Should().StartWith("[Previous tool result truncated");
        result.Should().Contain("10,485,760 chars", "should show correct size in truncation message");

        // Verify pruned message is much smaller than original
        var prunedJson = JsonSerializer.Serialize(pruned[2]);
        prunedJson.Length.Should().BeLessThan(500, "pruned message should be compact");
    }
}
