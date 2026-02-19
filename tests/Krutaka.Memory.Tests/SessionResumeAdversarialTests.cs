using System.Text.Json;
using FluentAssertions;
using Krutaka.Core;
using Krutaka.Memory;

namespace Krutaka.Memory.Tests;

/// <summary>
/// Adversarial tests for session resume with orphaned tool_use blocks.
/// These tests validate resilience under hostile or edge-case conditions:
/// mass orphan scenarios, worst-case interleaving, deeply nested inputs,
/// duplicate ID detection, and fallback parsing for malformed tool inputs.
/// </summary>
public sealed class SessionResumeAdversarialTests : IDisposable
{
    private readonly string _testRoot;
    private readonly string _projectPath;

    public SessionResumeAdversarialTests()
    {
        _testRoot = TestDirectoryHelper.GetTestDirectory("session-resume-adversarial-test");
        _projectPath = Path.Combine(_testRoot, "test-project");
        Directory.CreateDirectory(_projectPath);
    }

    public void Dispose()
    {
        TestDirectoryHelper.TryDeleteDirectory(_testRoot);
        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task Should_HandleMassOrphanScenario_With100OrphanedToolUseBlocks()
    {
        // Arrange - session with 100+ orphaned tool_use blocks (extreme stress test)
        var sessionId = Guid.NewGuid();
        using var store = new SessionStore(_projectPath, sessionId, _testRoot);

        await store.AppendAsync(new SessionEvent(
            Type: "user",
            Role: "user",
            Content: "Execute 100 operations",
            Timestamp: DateTimeOffset.UtcNow));

        await store.AppendAsync(new SessionEvent(
            Type: "assistant",
            Role: "assistant",
            Content: "I'll execute all 100 operations for you.",
            Timestamp: DateTimeOffset.UtcNow.AddSeconds(1)));

        // Create 100 orphaned tool_use blocks
        for (int i = 0; i < 100; i++)
        {
            await store.AppendAsync(new SessionEvent(
                Type: "tool_use",
                Role: "assistant",
                Content: $$$"""{"operation": "op_{{{i}}}"}""",
                Timestamp: DateTimeOffset.UtcNow.AddSeconds(2 + i),
                ToolName: "execute_operation",
                ToolUseId: $"toolu_mass_orphan_{i:D3}"));
        }

        // Act - reconstruct messages (should inject 100 synthetic tool_result blocks)
        var messages = await store.ReconstructMessagesAsync();

        // Assert
        // Should have: initial user, assistant with 100 tool_use, synthetic user with 100 tool_result
        messages.Should().HaveCount(3);

        // Verify assistant message has 100 tool_use blocks (plus text block)
        var assistantMsg = JsonSerializer.Serialize(messages[1]);
        var assistantDoc = JsonDocument.Parse(assistantMsg);
        var assistantContent = assistantDoc.RootElement.GetProperty("content");
        assistantContent.GetArrayLength().Should().Be(101); // text + 100x tool_use

        // Verify synthetic user message has 100 tool_result blocks
        var syntheticUserMsg = JsonSerializer.Serialize(messages[2]);
        var syntheticUserDoc = JsonDocument.Parse(syntheticUserMsg);
        var userContent = syntheticUserDoc.RootElement.GetProperty("content");
        userContent.GetArrayLength().Should().Be(100); // 100x tool_result

        // Verify all tool_result blocks are marked as errors
        foreach (var toolResult in userContent.EnumerateArray())
        {
            toolResult.GetProperty("type").GetString().Should().Be("tool_result");
            toolResult.GetProperty("is_error").GetBoolean().Should().BeTrue();
            toolResult.GetProperty("content").GetString().Should().Contain("interrupted");
        }

        // Verify all tool_use_id values are unique
        var toolUseIds = new HashSet<string>();
        foreach (var toolResult in userContent.EnumerateArray())
        {
            var toolUseId = toolResult.GetProperty("tool_use_id").GetString()!;
            toolUseIds.Add(toolUseId).Should().BeTrue($"tool_use_id {toolUseId} should be unique");
        }

        toolUseIds.Should().HaveCount(100);
    }

    [Fact]
    public async Task Should_HandleWorstCase_EveryAssistantMessageHasOrphanedToolUse()
    {
        // Arrange - every assistant message in the conversation has orphaned tool_use
        var sessionId = Guid.NewGuid();
        using var store = new SessionStore(_projectPath, sessionId, _testRoot);

        // Create 10 turns, each with orphaned tool_use
        for (int turn = 0; turn < 10; turn++)
        {
            await store.AppendAsync(new SessionEvent(
                Type: "user",
                Role: "user",
                Content: $"Task {turn}",
                Timestamp: DateTimeOffset.UtcNow.AddSeconds(turn * 3)));

            await store.AppendAsync(new SessionEvent(
                Type: "assistant",
                Role: "assistant",
                Content: $"Executing task {turn}",
                Timestamp: DateTimeOffset.UtcNow.AddSeconds(turn * 3 + 1)));

            await store.AppendAsync(new SessionEvent(
                Type: "tool_use",
                Role: "assistant",
                Content: $$$"""{"task": "task_{{{turn}}}"}""",
                Timestamp: DateTimeOffset.UtcNow.AddSeconds(turn * 3 + 2),
                ToolName: "execute_task",
                ToolUseId: $"toolu_worst_case_{turn:D2}"));
        }

        // Act
        var messages = await store.ReconstructMessagesAsync();

        // Assert - The reconstruction consolidates messages:
        // Turn 0: user "Task 0"
        // Turn 0: assistant "Executing task 0" + tool_use
        // Turn 1: user "Task 1" + synthetic tool_result for toolu_worst_case_00
        // Turn 1: assistant "Executing task 1" + tool_use
        // Turn 2: user "Task 2" + synthetic tool_result for toolu_worst_case_01
        // ...
        // Turn 9: assistant "Executing task 9" + tool_use
        // Final: synthetic user with tool_result for toolu_worst_case_09
        //
        // Total: 10 user messages (9 with tool_result augmentation) + 10 assistant messages + 1 final synthetic user = 21
        messages.Should().HaveCount(21);

        // Verify all synthetic tool_results are present and correct
        var foundResults = new HashSet<string>();
        foreach (var message in messages)
        {
            var json = JsonSerializer.Serialize(message);
            var doc = JsonDocument.Parse(json);
            var role = doc.RootElement.GetProperty("role").GetString();

            if (role == "user" && doc.RootElement.TryGetProperty("content", out var content))
            {
                if (content.ValueKind == JsonValueKind.Array)
                {
                    foreach (var block in content.EnumerateArray())
                    {
                        if (block.TryGetProperty("type", out var type) && type.GetString() == "tool_result")
                        {
                            var toolUseId = block.GetProperty("tool_use_id").GetString()!;
                            var isError = block.GetProperty("is_error").GetBoolean();
                            isError.Should().BeTrue("synthetic tool_results should be marked as errors");
                            foundResults.Add(toolUseId);
                        }
                    }
                }
            }
        }

        // Verify all 10 orphaned tool_use blocks got synthetic tool_results
        foundResults.Should().HaveCount(10);
        for (int i = 0; i < 10; i++)
        {
            foundResults.Should().Contain($"toolu_worst_case_{i:D2}");
        }
    }

    [Fact]
    public async Task Should_HandleInterleavedValidAndOrphanedToolUse()
    {
        // Arrange - mix of valid tool_use (with tool_result) and orphaned tool_use
        var sessionId = Guid.NewGuid();
        using var store = new SessionStore(_projectPath, sessionId, _testRoot);

        // Turn 1: Valid tool_use with tool_result
        await store.AppendAsync(new SessionEvent(
            Type: "user",
            Role: "user",
            Content: "Valid operation",
            Timestamp: DateTimeOffset.UtcNow));

        await store.AppendAsync(new SessionEvent(
            Type: "tool_use",
            Role: "assistant",
            Content: """{"op": "valid"}""",
            Timestamp: DateTimeOffset.UtcNow.AddSeconds(1),
            ToolName: "test_tool",
            ToolUseId: "toolu_valid_001"));

        await store.AppendAsync(new SessionEvent(
            Type: "tool_result",
            Role: "user",
            Content: "Success",
            Timestamp: DateTimeOffset.UtcNow.AddSeconds(2),
            ToolUseId: "toolu_valid_001"));

        // Turn 2: Orphaned tool_use
        await store.AppendAsync(new SessionEvent(
            Type: "user",
            Role: "user",
            Content: "Orphaned operation",
            Timestamp: DateTimeOffset.UtcNow.AddSeconds(3)));

        await store.AppendAsync(new SessionEvent(
            Type: "tool_use",
            Role: "assistant",
            Content: """{"op": "orphaned"}""",
            Timestamp: DateTimeOffset.UtcNow.AddSeconds(4),
            ToolName: "test_tool",
            ToolUseId: "toolu_orphaned_001"));

        // Turn 3: Another valid tool_use with tool_result
        await store.AppendAsync(new SessionEvent(
            Type: "user",
            Role: "user",
            Content: "Another valid operation",
            Timestamp: DateTimeOffset.UtcNow.AddSeconds(5)));

        await store.AppendAsync(new SessionEvent(
            Type: "tool_use",
            Role: "assistant",
            Content: """{"op": "valid2"}""",
            Timestamp: DateTimeOffset.UtcNow.AddSeconds(6),
            ToolName: "test_tool",
            ToolUseId: "toolu_valid_002"));

        await store.AppendAsync(new SessionEvent(
            Type: "tool_result",
            Role: "user",
            Content: "Success again",
            Timestamp: DateTimeOffset.UtcNow.AddSeconds(7),
            ToolUseId: "toolu_valid_002"));

        // Act
        var messages = await store.ReconstructMessagesAsync();

        // Assert - Reconstruction consolidates messages:
        // Message 0: user "Valid operation"
        // Message 1: assistant with tool_use "toolu_valid_001"
        // Message 2: user with tool_result "toolu_valid_001" (valid) + text "Orphaned operation"
        // Message 3: assistant with tool_use "toolu_orphaned_001"
        // Message 4: user with text "Another valid operation" + synthetic tool_result "toolu_orphaned_001"
        // Message 5: assistant with tool_use "toolu_valid_002"
        // Message 6: user with tool_result "toolu_valid_002" (valid)
        //
        // Total: 7 messages
        messages.Should().HaveCount(7);

        // Verify message 2 has the valid tool_result + next user text
        var msg2 = JsonSerializer.Serialize(messages[2]);
        var doc2 = JsonDocument.Parse(msg2);
        var content2 = doc2.RootElement.GetProperty("content");
        content2.GetArrayLength().Should().Be(2);
        content2[0].GetProperty("type").GetString().Should().Be("tool_result");
        content2[0].GetProperty("tool_use_id").GetString().Should().Be("toolu_valid_001");
        content2[0].GetProperty("is_error").GetBoolean().Should().BeFalse();
        content2[1].GetProperty("type").GetString().Should().Be("text");
        content2[1].GetProperty("text").GetString().Should().Be("Orphaned operation");

        // Verify message 4 has the text + synthetic tool_result for orphaned tool_use
        var msg4 = JsonSerializer.Serialize(messages[4]);
        var doc4 = JsonDocument.Parse(msg4);
        var content4 = doc4.RootElement.GetProperty("content");
        content4.GetArrayLength().Should().BeGreaterOrEqualTo(2);

        bool foundText = false;
        bool foundSyntheticResult = false;
        foreach (var block in content4.EnumerateArray())
        {
            if (block.TryGetProperty("type", out var type))
            {
                if (type.GetString() == "text" && block.GetProperty("text").GetString() == "Another valid operation")
                {
                    foundText = true;
                }

                if (type.GetString() == "tool_result")
                {
                    var toolUseId = block.GetProperty("tool_use_id").GetString();
                    if (toolUseId == "toolu_orphaned_001")
                    {
                        foundSyntheticResult = true;
                        block.GetProperty("is_error").GetBoolean().Should().BeTrue();
                    }
                }
            }
        }

        foundText.Should().BeTrue("message 4 should contain the 'Another valid operation' text");
        foundSyntheticResult.Should().BeTrue("message 4 should contain synthetic tool_result for toolu_orphaned_001");

        // Verify message 6 has the valid tool_result for toolu_valid_002
        var msg6 = JsonSerializer.Serialize(messages[6]);
        var doc6 = JsonDocument.Parse(msg6);
        var content6 = doc6.RootElement.GetProperty("content");
        content6[0].GetProperty("tool_use_id").GetString().Should().Be("toolu_valid_002");
        content6[0].GetProperty("is_error").GetBoolean().Should().BeFalse();
    }

    [Fact]
    public async Task Should_HandleDeeplyNestedToolUseInputJson()
    {
        // Arrange - tool_use with deeply nested JSON input
        var sessionId = Guid.NewGuid();
        using var store = new SessionStore(_projectPath, sessionId, _testRoot);

        await store.AppendAsync(new SessionEvent(
            Type: "user",
            Role: "user",
            Content: "Complex nested operation",
            Timestamp: DateTimeOffset.UtcNow));

        // Create deeply nested JSON (10 levels deep)
        var nestedJson = """
        {
            "level1": {
                "level2": {
                    "level3": {
                        "level4": {
                            "level5": {
                                "level6": {
                                    "level7": {
                                        "level8": {
                                            "level9": {
                                                "level10": "deep value",
                                                "array": [1, 2, {"nested": "object"}]
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        """;

        await store.AppendAsync(new SessionEvent(
            Type: "tool_use",
            Role: "assistant",
            Content: nestedJson,
            Timestamp: DateTimeOffset.UtcNow.AddSeconds(1),
            ToolName: "complex_tool",
            ToolUseId: "toolu_nested_001"));

        // Act
        var messages = await store.ReconstructMessagesAsync();

        // Assert - Should successfully parse deeply nested JSON
        messages.Should().HaveCount(3);

        var assistantMsg = JsonSerializer.Serialize(messages[1]);
        var assistantDoc = JsonDocument.Parse(assistantMsg);
        var content = assistantDoc.RootElement.GetProperty("content");
        var toolUse = content[0];
        toolUse.GetProperty("type").GetString().Should().Be("tool_use");

        // Verify input is a proper JSON object (not a string)
        var input = toolUse.GetProperty("input");
        input.ValueKind.Should().Be(JsonValueKind.Object);

        // Navigate to deep value
        var deepValue = input
            .GetProperty("level1")
            .GetProperty("level2")
            .GetProperty("level3")
            .GetProperty("level4")
            .GetProperty("level5")
            .GetProperty("level6")
            .GetProperty("level7")
            .GetProperty("level8")
            .GetProperty("level9")
            .GetProperty("level10")
            .GetString();
        deepValue.Should().Be("deep value");

        // Verify synthetic tool_result was injected
        var userMsg = JsonSerializer.Serialize(messages[2]);
        var userDoc = JsonDocument.Parse(userMsg);
        var userContent = userDoc.RootElement.GetProperty("content");
        userContent[0].GetProperty("tool_use_id").GetString().Should().Be("toolu_nested_001");
    }

    [Fact]
    public async Task Should_EnsureUniquenessOfSyntheticToolResultIds()
    {
        // Arrange - multiple orphaned tool_use blocks to test duplicate ID prevention
        var sessionId = Guid.NewGuid();
        using var store = new SessionStore(_projectPath, sessionId, _testRoot);

        await store.AppendAsync(new SessionEvent(
            Type: "user",
            Role: "user",
            Content: "Multi-tool task",
            Timestamp: DateTimeOffset.UtcNow));

        await store.AppendAsync(new SessionEvent(
            Type: "assistant",
            Role: "assistant",
            Content: "Executing multiple tools",
            Timestamp: DateTimeOffset.UtcNow.AddSeconds(1)));

        // Create 50 orphaned tool_use blocks
        for (int i = 0; i < 50; i++)
        {
            await store.AppendAsync(new SessionEvent(
                Type: "tool_use",
                Role: "assistant",
                Content: $$$"""{"index": {{{i}}}}""",
                Timestamp: DateTimeOffset.UtcNow.AddSeconds(2 + i),
                ToolName: "test_tool",
                ToolUseId: $"toolu_unique_{i:D3}"));
        }

        // Act
        var messages = await store.ReconstructMessagesAsync();

        // Assert - Verify all synthetic tool_result IDs are unique
        var syntheticUserMsg = JsonSerializer.Serialize(messages[2]);
        var syntheticUserDoc = JsonDocument.Parse(syntheticUserMsg);
        var userContent = syntheticUserDoc.RootElement.GetProperty("content");

        var toolUseIds = new HashSet<string>();
        foreach (var toolResult in userContent.EnumerateArray())
        {
            var toolUseId = toolResult.GetProperty("tool_use_id").GetString()!;
            toolUseIds.Add(toolUseId).Should().BeTrue(
                $"tool_use_id {toolUseId} should be unique - no duplicates allowed");
        }

        toolUseIds.Should().HaveCount(50, "all 50 tool_result blocks should have unique IDs");
    }

    [Fact]
    public async Task Should_HandleEmptyContentArraysInAssistantMessages()
    {
        // Arrange - assistant message with empty content array (edge case)
        var sessionId = Guid.NewGuid();
        using var store = new SessionStore(_projectPath, sessionId, _testRoot);

        await store.AppendAsync(new SessionEvent(
            Type: "user",
            Role: "user",
            Content: "Test empty content",
            Timestamp: DateTimeOffset.UtcNow));

        // Note: SessionStore.AppendAsync doesn't allow creating empty content arrays directly
        // through the normal flow, but we can test the reconstruction handles it gracefully
        // by creating a minimal assistant message followed by orphaned tool_use
        await store.AppendAsync(new SessionEvent(
            Type: "tool_use",
            Role: "assistant",
            Content: """{"test": "data"}""",
            Timestamp: DateTimeOffset.UtcNow.AddSeconds(1),
            ToolName: "test_tool",
            ToolUseId: "toolu_empty_content_001"));

        // Act - Should handle gracefully even if content reconstruction creates unusual structures
        var messages = await store.ReconstructMessagesAsync();

        // Assert - Should not crash and should inject synthetic tool_result
        messages.Should().HaveCount(3);

        var userMsg = JsonSerializer.Serialize(messages[2]);
        var userDoc = JsonDocument.Parse(userMsg);
        var content = userDoc.RootElement.GetProperty("content");
        content[0].GetProperty("tool_use_id").GetString().Should().Be("toolu_empty_content_001");
        content[0].GetProperty("is_error").GetBoolean().Should().BeTrue();
    }

    [Fact]
    public async Task Should_HandleToolUseInputAsRawString_FallbackToParseToolInput()
    {
        // Arrange - tool_use input stored as raw string (tests ParseToolInput fallback)
        var sessionId = Guid.NewGuid();
        using var store = new SessionStore(_projectPath, sessionId, _testRoot);

        await store.AppendAsync(new SessionEvent(
            Type: "user",
            Role: "user",
            Content: "Test string input",
            Timestamp: DateTimeOffset.UtcNow));

        // Store input as raw string (not pre-parsed JSON)
        await store.AppendAsync(new SessionEvent(
            Type: "tool_use",
            Role: "assistant",
            Content: """{"command": "test", "args": ["arg1", "arg2"]}""",
            Timestamp: DateTimeOffset.UtcNow.AddSeconds(1),
            ToolName: "run_shell",
            ToolUseId: "toolu_string_input_001"));

        // Act
        var messages = await store.ReconstructMessagesAsync();

        // Assert - ParseToolInput should convert string to JsonElement
        messages.Should().HaveCount(3);

        var assistantMsg = JsonSerializer.Serialize(messages[1]);
        var assistantDoc = JsonDocument.Parse(assistantMsg);
        var content = assistantDoc.RootElement.GetProperty("content");
        var toolUse = content[0];

        // Input should be a proper JSON object, not a double-escaped string
        var input = toolUse.GetProperty("input");
        input.ValueKind.Should().Be(JsonValueKind.Object, "ParseToolInput should convert string to JsonElement");
        input.GetProperty("command").GetString().Should().Be("test");
        input.GetProperty("args").GetArrayLength().Should().Be(2);
        input.GetProperty("args")[0].GetString().Should().Be("arg1");

        // Verify synthetic tool_result was injected
        var userMsg = JsonSerializer.Serialize(messages[2]);
        var userDoc = JsonDocument.Parse(userMsg);
        userDoc.RootElement.GetProperty("role").GetString().Should().Be("user");
        var userContent = userDoc.RootElement.GetProperty("content");
        userContent[0].GetProperty("tool_use_id").GetString().Should().Be("toolu_string_input_001");
    }
}
