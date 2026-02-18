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
        result.Should().Contain("1 turns ago");
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
}
