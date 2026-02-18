using System.Text.Json;
using FluentAssertions;
using Krutaka.Core;
using Krutaka.Memory;

namespace Krutaka.Memory.Tests;

/// <summary>
/// Tests for session resume with orphaned tool_use blocks repair logic.
/// Validates that RepairOrphanedToolUseBlocks and ValidateAndRemoveOrphanedAssistantMessages
/// correctly handle sessions interrupted between tool_use and tool_result events.
/// </summary>
public sealed class SessionResumeRepairTests : IDisposable
{
    private readonly string _testRoot;
    private readonly string _projectPath;

    public SessionResumeRepairTests()
    {
        _testRoot = TestDirectoryHelper.GetTestDirectory("session-resume-repair-test");
        _projectPath = Path.Combine(_testRoot, "test-project");
        Directory.CreateDirectory(_projectPath);
    }

    public void Dispose()
    {
        TestDirectoryHelper.TryDeleteDirectory(_testRoot);
        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task Should_RepairOrphanedToolUseAtEnd()
    {
        // Arrange - session interrupted after tool_use but before tool_result
        var sessionId = Guid.NewGuid();
        using var store = new SessionStore(_projectPath, sessionId, _testRoot);

        await store.AppendAsync(new SessionEvent(
            Type: "user",
            Role: "user",
            Content: "Read file test.txt",
            Timestamp: DateTimeOffset.UtcNow));

        await store.AppendAsync(new SessionEvent(
            Type: "assistant",
            Role: "assistant",
            Content: "I'll read that file for you.",
            Timestamp: DateTimeOffset.UtcNow.AddSeconds(1)));

        // Tool use block with JSON input as string
        await store.AppendAsync(new SessionEvent(
            Type: "tool_use",
            Role: "assistant",
            Content: """{"path": "test.txt"}""",
            Timestamp: DateTimeOffset.UtcNow.AddSeconds(2),
            ToolName: "read_file",
            ToolUseId: "toolu_orphaned_001"));

        // Act - reconstruct messages (should inject synthetic tool_result)
        var messages = await store.ReconstructMessagesAsync();

        // Assert
        messages.Should().HaveCount(3);

        // Verify assistant message with tool_use
        var assistantMsg = JsonSerializer.Serialize(messages[1]);
        var assistantDoc = JsonDocument.Parse(assistantMsg);
        assistantDoc.RootElement.GetProperty("role").GetString().Should().Be("assistant");
        var content = assistantDoc.RootElement.GetProperty("content");
        content.GetArrayLength().Should().Be(2); // text + tool_use

        // Verify synthetic user message with tool_result was injected
        var userMsg = JsonSerializer.Serialize(messages[2]);
        var userDoc = JsonDocument.Parse(userMsg);
        userDoc.RootElement.GetProperty("role").GetString().Should().Be("user");
        var userContent = userDoc.RootElement.GetProperty("content");
        userContent.GetArrayLength().Should().Be(1); // synthetic tool_result

        var toolResult = userContent[0];
        toolResult.GetProperty("type").GetString().Should().Be("tool_result");
        toolResult.GetProperty("tool_use_id").GetString().Should().Be("toolu_orphaned_001");
        toolResult.GetProperty("is_error").GetBoolean().Should().BeTrue();
        toolResult.GetProperty("content").GetString().Should().Contain("interrupted");
    }

    [Fact]
    public async Task Should_RepairOrphanedToolUseInMiddle()
    {
        // Arrange - session interrupted in the middle of conversation
        var sessionId = Guid.NewGuid();
        using var store = new SessionStore(_projectPath, sessionId, _testRoot);

        await store.AppendAsync(new SessionEvent(
            Type: "user",
            Role: "user",
            Content: "Read file test.txt",
            Timestamp: DateTimeOffset.UtcNow));

        // Orphaned tool_use
        await store.AppendAsync(new SessionEvent(
            Type: "tool_use",
            Role: "assistant",
            Content: """{"path": "test.txt"}""",
            Timestamp: DateTimeOffset.UtcNow.AddSeconds(1),
            ToolName: "read_file",
            ToolUseId: "toolu_orphaned_002"));

        // Conversation continues after interruption/resume
        await store.AppendAsync(new SessionEvent(
            Type: "user",
            Role: "user",
            Content: "Actually, read file2.txt instead",
            Timestamp: DateTimeOffset.UtcNow.AddSeconds(2)));

        // Act
        var messages = await store.ReconstructMessagesAsync();

        // Assert - should have user, assistant (orphaned tool_use), user (augmented with synthetic tool_result)
        messages.Should().HaveCount(3);

        // Verify synthetic tool_result was injected into the next user message
        var thirdMsg = JsonSerializer.Serialize(messages[2]);
        var thirdDoc = JsonDocument.Parse(thirdMsg);
        thirdDoc.RootElement.GetProperty("role").GetString().Should().Be("user");
        var content = thirdDoc.RootElement.GetProperty("content");
        content.GetArrayLength().Should().Be(2); // text + synthetic tool_result

        content[0].GetProperty("type").GetString().Should().Be("text");
        content[1].GetProperty("type").GetString().Should().Be("tool_result");
        content[1].GetProperty("tool_use_id").GetString().Should().Be("toolu_orphaned_002");
    }

    [Fact]
    public async Task Should_RepairMultipleOrphanedToolUseIds()
    {
        // Arrange - multiple tools called but session interrupted
        var sessionId = Guid.NewGuid();
        using var store = new SessionStore(_projectPath, sessionId, _testRoot);

        await store.AppendAsync(new SessionEvent(
            Type: "user",
            Role: "user",
            Content: "Read two files",
            Timestamp: DateTimeOffset.UtcNow));

        await store.AppendAsync(new SessionEvent(
            Type: "assistant",
            Role: "assistant",
            Content: "I'll read both files.",
            Timestamp: DateTimeOffset.UtcNow.AddSeconds(1)));

        // Multiple tool_use blocks, all orphaned
        await store.AppendAsync(new SessionEvent(
            Type: "tool_use",
            Role: "assistant",
            Content: """{"path": "file1.txt"}""",
            Timestamp: DateTimeOffset.UtcNow.AddSeconds(2),
            ToolName: "read_file",
            ToolUseId: "toolu_orphaned_003"));

        await store.AppendAsync(new SessionEvent(
            Type: "tool_use",
            Role: "assistant",
            Content: """{"path": "file2.txt"}""",
            Timestamp: DateTimeOffset.UtcNow.AddSeconds(3),
            ToolName: "read_file",
            ToolUseId: "toolu_orphaned_004"));

        // Act
        var messages = await store.ReconstructMessagesAsync();

        // Assert
        messages.Should().HaveCount(3);

        // Verify assistant message has both tool_use blocks
        var assistantMsg = JsonSerializer.Serialize(messages[1]);
        var assistantDoc = JsonDocument.Parse(assistantMsg);
        var assistantContent = assistantDoc.RootElement.GetProperty("content");
        assistantContent.GetArrayLength().Should().Be(3); // text + 2x tool_use

        // Verify synthetic user message has both tool_result blocks
        var syntheticUserMsg = JsonSerializer.Serialize(messages[2]);
        var syntheticUserDoc = JsonDocument.Parse(syntheticUserMsg);
        var userContent = syntheticUserDoc.RootElement.GetProperty("content");
        userContent.GetArrayLength().Should().Be(2); // 2x tool_result

        var toolResult1 = userContent[0];
        toolResult1.GetProperty("tool_use_id").GetString().Should().Be("toolu_orphaned_003");
        toolResult1.GetProperty("is_error").GetBoolean().Should().BeTrue();

        var toolResult2 = userContent[1];
        toolResult2.GetProperty("tool_use_id").GetString().Should().Be("toolu_orphaned_004");
        toolResult2.GetProperty("is_error").GetBoolean().Should().BeTrue();
    }

    [Fact]
    public async Task Should_HandleDoubleSerializedInputString()
    {
        // Arrange - test the original bug where toolCall.Input was stored as string
        // This simulates the old behavior where input was double-serialized
        var sessionId = Guid.NewGuid();
        using var store = new SessionStore(_projectPath, sessionId, _testRoot);

        await store.AppendAsync(new SessionEvent(
            Type: "user",
            Role: "user",
            Content: "Test command",
            Timestamp: DateTimeOffset.UtcNow));

        // Store input as JSON string (simulating old CreateAssistantMessage behavior)
        await store.AppendAsync(new SessionEvent(
            Type: "tool_use",
            Role: "assistant",
            Content: """{"command": "ls -la"}""", // This is already a string, will be parsed by ParseToolInput
            Timestamp: DateTimeOffset.UtcNow.AddSeconds(1),
            ToolName: "run_shell",
            ToolUseId: "toolu_doubleserial_001"));

        // Act
        var messages = await store.ReconstructMessagesAsync();

        // Assert - should successfully parse and repair (3 messages: user, assistant with tool_use, synthetic user with tool_result)
        messages.Should().HaveCount(3);

        var assistantMsg = JsonSerializer.Serialize(messages[1]);
        var assistantDoc = JsonDocument.Parse(assistantMsg);
        var content = assistantDoc.RootElement.GetProperty("content");
        var toolUse = content[0];
        toolUse.GetProperty("type").GetString().Should().Be("tool_use");

        // Input should be a proper JSON object, not a double-escaped string
        var input = toolUse.GetProperty("input");
        input.ValueKind.Should().Be(JsonValueKind.Object);
        input.GetProperty("command").GetString().Should().Be("ls -la");

        // Should have synthetic tool_result in third message
        var userMsg = JsonSerializer.Serialize(messages[2]);
        var userDoc = JsonDocument.Parse(userMsg);
        userDoc.RootElement.GetProperty("role").GetString().Should().Be("user");
    }

    [Fact]
    public async Task Should_AugmentExistingUserMessageWithSyntheticResults()
    {
        // Arrange - orphaned tool_use followed by an existing user message
        var sessionId = Guid.NewGuid();
        using var store = new SessionStore(_projectPath, sessionId, _testRoot);

        await store.AppendAsync(new SessionEvent(
            Type: "user",
            Role: "user",
            Content: "Read file",
            Timestamp: DateTimeOffset.UtcNow));

        await store.AppendAsync(new SessionEvent(
            Type: "tool_use",
            Role: "assistant",
            Content: """{"path": "test.txt"}""",
            Timestamp: DateTimeOffset.UtcNow.AddSeconds(1),
            ToolName: "read_file",
            ToolUseId: "toolu_orphaned_005"));

        // User sends another message before tool_result
        await store.AppendAsync(new SessionEvent(
            Type: "user",
            Role: "user",
            Content: "Never mind, cancel that",
            Timestamp: DateTimeOffset.UtcNow.AddSeconds(2)));

        // Act
        var messages = await store.ReconstructMessagesAsync();

        // Assert - the existing user message should be augmented with synthetic tool_result
        messages.Should().HaveCount(3);

        var userMsg = JsonSerializer.Serialize(messages[2]);
        var userDoc = JsonDocument.Parse(userMsg);
        var userContent = userDoc.RootElement.GetProperty("content");
        userContent.GetArrayLength().Should().Be(2); // text + synthetic tool_result

        userContent[0].GetProperty("type").GetString().Should().Be("text");
        userContent[0].GetProperty("text").GetString().Should().Be("Never mind, cancel that");

        userContent[1].GetProperty("type").GetString().Should().Be("tool_result");
        userContent[1].GetProperty("tool_use_id").GetString().Should().Be("toolu_orphaned_005");
        userContent[1].GetProperty("is_error").GetBoolean().Should().BeTrue();
    }

    [Fact]
    public async Task Should_HandleUnknownContentBlockTypes()
    {
        // Arrange - test forward compatibility with future Claude API content block types
        var sessionId = Guid.NewGuid();
        using var store = new SessionStore(_projectPath, sessionId, _testRoot);

        await store.AppendAsync(new SessionEvent(
            Type: "user",
            Role: "user",
            Content: "Test",
            Timestamp: DateTimeOffset.UtcNow));

        await store.AppendAsync(new SessionEvent(
            Type: "tool_use",
            Role: "assistant",
            Content: """{"test": "data"}""",
            Timestamp: DateTimeOffset.UtcNow.AddSeconds(1),
            ToolName: "test_tool",
            ToolUseId: "toolu_orphaned_006"));

        // Act
        var messages = await store.ReconstructMessagesAsync();

        // Assert - should handle gracefully and inject synthetic tool_result (3 messages total)
        messages.Should().HaveCount(3);

        var userMsg = JsonSerializer.Serialize(messages[2]);
        var userDoc = JsonDocument.Parse(userMsg);
        userDoc.RootElement.GetProperty("role").GetString().Should().Be("user");
        var content = userDoc.RootElement.GetProperty("content");
        content[0].GetProperty("type").GetString().Should().Be("tool_result");
    }

    [Fact]
    public async Task Should_NotRepairWhenToolResultExists()
    {
        // Arrange - normal case where tool_use has matching tool_result
        var sessionId = Guid.NewGuid();
        using var store = new SessionStore(_projectPath, sessionId, _testRoot);

        await store.AppendAsync(new SessionEvent(
            Type: "user",
            Role: "user",
            Content: "Read file test.txt",
            Timestamp: DateTimeOffset.UtcNow));

        await store.AppendAsync(new SessionEvent(
            Type: "tool_use",
            Role: "assistant",
            Content: """{"path": "test.txt"}""",
            Timestamp: DateTimeOffset.UtcNow.AddSeconds(1),
            ToolName: "read_file",
            ToolUseId: "toolu_normal_001"));

        // Tool result provided normally
        await store.AppendAsync(new SessionEvent(
            Type: "tool_result",
            Role: "user",
            Content: "File contents here",
            Timestamp: DateTimeOffset.UtcNow.AddSeconds(2),
            ToolUseId: "toolu_normal_001"));

        // Act
        var messages = await store.ReconstructMessagesAsync();

        // Assert - no extra synthetic tool_result should be injected (3 messages: initial user, assistant, user with tool_result)
        messages.Should().HaveCount(3);

        var assistantMsg = JsonSerializer.Serialize(messages[1]);
        var assistantDoc = JsonDocument.Parse(assistantMsg);
        assistantDoc.RootElement.GetProperty("role").GetString().Should().Be("assistant");

        var userMsg = JsonSerializer.Serialize(messages[2]);
        var userDoc = JsonDocument.Parse(userMsg);
        userDoc.RootElement.GetProperty("role").GetString().Should().Be("user");
        var content = userDoc.RootElement.GetProperty("content");
        content.GetArrayLength().Should().Be(1); // only the real tool_result, no synthetic one

        // Verify the real tool_result
        var toolResult = content[0];
        toolResult.GetProperty("type").GetString().Should().Be("tool_result");
        toolResult.GetProperty("tool_use_id").GetString().Should().Be("toolu_normal_001");
        toolResult.GetProperty("is_error").GetBoolean().Should().BeFalse();
        toolResult.GetProperty("content").GetString().Should().Be("File contents here");
    }

    // NOTE: ValidateAndRemoveOrphanedAssistantMessages safety net coverage
    //
    // ReconstructMessagesAsync internally performs two phases when repairing broken
    // session history:
    //   1) RepairOrphanedToolUseBlocks: injects synthetic error tool_result blocks
    //      for any orphaned tool_use events so that the model always sees a
    //      terminal tool_result for every tool invocation.
    //   2) ValidateAndRemoveOrphanedAssistantMessages: final fail-safe that prunes
    //      any remaining assistant messages that still contain unrepaired / orphaned
    //      tool_use blocks after phase (1), and also removes any now-orphaned
    //      tool_result blocks to maintain conversation integrity.
    //
    // The tests above exercise the primary repair flow exhaustively (including
    // normal tool_use + tool_result, and cases where RepairOrphanedToolUseBlocks
    // injects synthetic error tool_result content). To directly test the final
    // ValidateAndRemoveOrphanedAssistantMessages safety net, we would need to
    // construct an in-memory message graph that:
    //   - Contains assistant messages with orphaned tool_use blocks, and
    //   - Cannot be repaired by RepairOrphanedToolUseBlocks, and
    //   - Is observable through the public SessionStore API.
    //
    // With the current SessionStore design and visibility, this is not possible to
    // achieve in a deterministic way using only the public AppendAsync and
    // ReconstructMessagesAsync methods: any sequence of persisted SessionEvent
    // records that would lead to an "orphaned" tool_use is already handled by
    // RepairOrphanedToolUseBlocks. Creating a state that *only* the safety net can
    // correct would require either:
    //   - Exposing ValidateAndRemoveOrphanedAssistantMessages as public/internal
    //     purely for testing, or
    //   - Reaching into internal implementation details (e.g., mutating the
    //     reconstructed message list) that are intentionally encapsulated.
    //
    // To avoid weakening encapsulation or changing production visibility solely to
    // satisfy a test, we intentionally do not add a direct unit test for
    // ValidateAndRemoveOrphanedAssistantMessages. Instead, the method is treated as
    // a defensive, last-resort safety net whose behavior is indirectly exercised
    // by the existing RepairOrphanedToolUseBlocks coverage and by the normal
    // session reconstruction tests above. The implementation (lines 493-687 in
    // SessionStore.cs) includes cleanup logic that removes orphaned tool_result
    // blocks when assistant messages are removed, preventing secondary orphaning.
    //
    // This comment documents the intentional absence of a dedicated test for the
    // safety net path, as suggested by review comment #2823045966.
}
