using System.Text.Json;
using FluentAssertions;
using Krutaka.Core;
using Krutaka.Memory;

namespace Krutaka.Memory.Tests;

public sealed class SessionStoreTests : IDisposable
{
    private readonly string _testRoot;
    private readonly string _projectPath;

    public SessionStoreTests()
    {
        // Use CI-safe test directory (avoids LocalAppData and reduces file lock issues)
        _testRoot = TestDirectoryHelper.GetTestDirectory("session-test");
        _projectPath = Path.Combine(_testRoot, "test-project");
        Directory.CreateDirectory(_projectPath);
    }

    public void Dispose()
    {
        TestDirectoryHelper.TryDeleteDirectory(_testRoot);
        GC.SuppressFinalize(this);
    }

    [Fact]
    public void Should_CreateSessionDirectoryAutomatically()
    {
        // Arrange & Act
        var sessionId = Guid.NewGuid();
        using var store = new SessionStore(_projectPath, sessionId, _testRoot);

        // Assert
        var encodedPath = SessionStore.EncodeProjectPath(_projectPath);
        var sessionDir = Path.Combine(_testRoot, "sessions", encodedPath);

        Directory.Exists(sessionDir).Should().BeTrue();
    }

    [Fact]
    public async Task Should_AppendAndLoadEvents()
    {
        // Arrange
        var sessionId = Guid.NewGuid();
        using var store = new SessionStore(_projectPath, sessionId, _testRoot);

        var event1 = new SessionEvent(
            Type: "user",
            Role: "user",
            Content: "Hello, Claude!",
            Timestamp: DateTimeOffset.UtcNow);

        var event2 = new SessionEvent(
            Type: "assistant",
            Role: "assistant",
            Content: "Hello! How can I help you?",
            Timestamp: DateTimeOffset.UtcNow.AddSeconds(1));

        // Act
        await store.AppendAsync(event1);
        await store.AppendAsync(event2);

        var loadedEvents = new List<SessionEvent>();
        await foreach (var evt in store.LoadAsync())
        {
            loadedEvents.Add(evt);
        }

        // Assert
        loadedEvents.Should().HaveCount(2);
        loadedEvents[0].Type.Should().Be("user");
        loadedEvents[0].Content.Should().Be("Hello, Claude!");
        loadedEvents[1].Type.Should().Be("assistant");
        loadedEvents[1].Content.Should().Be("Hello! How can I help you?");
    }

    [Fact]
    public async Task Should_HandleEmptySession()
    {
        // Arrange
        var sessionId = Guid.NewGuid();
        using var store = new SessionStore(_projectPath, sessionId, _testRoot);

        // Act
        var loadedEvents = new List<SessionEvent>();
        await foreach (var evt in store.LoadAsync())
        {
            loadedEvents.Add(evt);
        }

        // Assert
        loadedEvents.Should().BeEmpty();
    }

    [Fact]
    public async Task Should_RoundTripSerializeComplexEvent()
    {
        // Arrange
        var sessionId = Guid.NewGuid();
        using var store = new SessionStore(_projectPath, sessionId, _testRoot);

        var toolEvent = new SessionEvent(
            Type: "tool_use",
            Role: "assistant",
            Content: """{"path": "/tmp/test.txt", "content": "data"}""",
            Timestamp: DateTimeOffset.UtcNow,
            ToolName: "write_file",
            ToolUseId: "toolu_123abc",
            IsMeta: false);

        // Act
        await store.AppendAsync(toolEvent);

        var loadedEvents = new List<SessionEvent>();
        await foreach (var evt in store.LoadAsync())
        {
            loadedEvents.Add(evt);
        }

        // Assert
        loadedEvents.Should().HaveCount(1);
        var loaded = loadedEvents[0];
        loaded.Type.Should().Be("tool_use");
        loaded.Role.Should().Be("assistant");
        loaded.Content.Should().Be("""{"path": "/tmp/test.txt", "content": "data"}""");
        loaded.ToolName.Should().Be("write_file");
        loaded.ToolUseId.Should().Be("toolu_123abc");
        loaded.IsMeta.Should().BeFalse();
    }

    [Fact]
    public async Task Should_ReconstructMessagesFromEvents()
    {
        // Arrange
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
            Content: "I will read that file for you.",
            Timestamp: DateTimeOffset.UtcNow.AddSeconds(1)));

        // Act
        var messages = await store.ReconstructMessagesAsync();

        // Assert
        messages.Should().HaveCount(2);

        // Check first message (user)
        var userMsg = JsonSerializer.Serialize(messages[0]);
        userMsg.Should().Contain("\"role\":\"user\"");
        userMsg.Should().Contain("Read file test.txt");

        // Check second message (assistant)
        var assistantMsg = JsonSerializer.Serialize(messages[1]);
        assistantMsg.Should().Contain("\"role\":\"assistant\"");
        assistantMsg.Should().Contain("I will read that file for you");
    }

    [Fact]
    public async Task Should_SkipMetadataEventsInReconstruction()
    {
        // Arrange
        var sessionId = Guid.NewGuid();
        using var store = new SessionStore(_projectPath, sessionId, _testRoot);

        await store.AppendAsync(new SessionEvent(
            Type: "user",
            Role: "user",
            Content: "Test message",
            Timestamp: DateTimeOffset.UtcNow));

        await store.AppendAsync(new SessionEvent(
            Type: "system",
            Role: null,
            Content: "Internal metadata",
            Timestamp: DateTimeOffset.UtcNow.AddSeconds(1),
            IsMeta: true));

        // Act
        var messages = await store.ReconstructMessagesAsync();

        // Assert
        messages.Should().HaveCount(1);
    }

    [Fact]
    public async Task Should_SaveAndVerifyMetadata()
    {
        // Arrange
        var sessionId = Guid.NewGuid();
        using var store = new SessionStore(_projectPath, sessionId, _testRoot);

        // Act
        await store.SaveMetadataAsync(_projectPath, "claude-sonnet-4-5-20250929");

        // Assert
        var encodedPath = SessionStore.EncodeProjectPath(_projectPath);
        var metadataPath = Path.Combine(
            _testRoot,
            "sessions",
            encodedPath,
            $"{sessionId}.meta.json");

        File.Exists(metadataPath).Should().BeTrue();

        var metadataJson = await File.ReadAllTextAsync(metadataPath);
        metadataJson.Should().Contain("started_at");
        metadataJson.Should().Contain("project_path");
        metadataJson.Should().Contain("model");
        metadataJson.Should().Contain("claude-sonnet-4-5-20250929");
    }

    [Theory]
    [InlineData("/Users/dev/myproject", "Users-dev-myproject")]
    [InlineData("C:\\Users\\dev\\myproject", "C-Users-dev-myproject")]
    [InlineData("/tmp/test", "tmp-test")]
    [InlineData("C:/projects/app", "C-projects-app")]
    public void Should_EncodeProjectPathCorrectly(string input, string expected)
    {
        // Act
        var encoded = SessionStore.EncodeProjectPath(input);

        // Assert
        encoded.Should().Be(expected);
    }

    [Theory]
    [InlineData("/")]
    [InlineData("\\")]
    [InlineData(":-:")]
    public void Should_EncodePaths_WithOnlySpecialCharacters(string input)
    {
        // Act
        var encoded = SessionStore.EncodeProjectPath(input);

        // Assert - when path is only special chars, should return "root"
        encoded.Should().Be("root");
    }

    [Fact]
    public void Should_ThrowOnNullOrEmptyProjectPath()
    {
        // Act & Assert
        var action = () => new SessionStore("", Guid.NewGuid());
        action.Should().Throw<ArgumentException>();

        var action2 = () => new SessionStore(null!, Guid.NewGuid());
        action2.Should().Throw<ArgumentException>();
    }

    [Fact]
    public async Task Should_ThrowOnNullEvent()
    {
        // Arrange
        using var store = new SessionStore(_projectPath, Guid.NewGuid(), _testRoot);

        // Act & Assert
        var action = async () => await store.AppendAsync(null!);
        await action.Should().ThrowAsync<ArgumentNullException>();
    }

    [Fact]
    public async Task Should_HandleConcurrentWrites()
    {
        // Arrange
        var sessionId = Guid.NewGuid();
        using var store = new SessionStore(_projectPath, sessionId, _testRoot);

        // Act - Write 10 events concurrently
        var tasks = Enumerable.Range(1, 10).Select(i =>
            store.AppendAsync(new SessionEvent(
                Type: "user",
                Role: "user",
                Content: $"Message {i}",
                Timestamp: DateTimeOffset.UtcNow)));

        await Task.WhenAll(tasks);

        // Assert
        var loadedEvents = new List<SessionEvent>();
        await foreach (var evt in store.LoadAsync())
        {
            loadedEvents.Add(evt);
        }

        loadedEvents.Should().HaveCount(10);
    }

    [Fact]
    public async Task Should_PreserveEventOrder()
    {
        // Arrange
        var sessionId = Guid.NewGuid();
        using var store = new SessionStore(_projectPath, sessionId, _testRoot);

        var events = new[]
        {
            new SessionEvent("user", "user", "First", DateTimeOffset.UtcNow),
            new SessionEvent("assistant", "assistant", "Second", DateTimeOffset.UtcNow.AddSeconds(1)),
            new SessionEvent("user", "user", "Third", DateTimeOffset.UtcNow.AddSeconds(2))
        };

        // Act
        foreach (var evt in events)
        {
            await store.AppendAsync(evt);
        }

        var loadedEvents = new List<SessionEvent>();
        await foreach (var evt in store.LoadAsync())
        {
            loadedEvents.Add(evt);
        }

        // Assert
        loadedEvents.Should().HaveCount(3);
        loadedEvents[0].Content.Should().Be("First");
        loadedEvents[1].Content.Should().Be("Second");
        loadedEvents[2].Content.Should().Be("Third");
    }

    [Fact]
    public async Task Should_GroupAssistantTextAndToolUseInSingleMessage()
    {
        // Arrange — assistant text followed by tool_use should be one message
        var sessionId = Guid.NewGuid();
        using var store = new SessionStore(_projectPath, sessionId, _testRoot);

        await store.AppendAsync(new SessionEvent("user", "user", "Read file test.txt", DateTimeOffset.UtcNow));
        await store.AppendAsync(new SessionEvent("assistant", "assistant", "I will read that file.", DateTimeOffset.UtcNow.AddSeconds(1)));
        await store.AppendAsync(new SessionEvent("tool_use", "assistant", """{"path":"test.txt"}""", DateTimeOffset.UtcNow.AddSeconds(2), "read_file", "toolu_001"));
        await store.AppendAsync(new SessionEvent("tool_result", "user", "file contents here", DateTimeOffset.UtcNow.AddSeconds(3), "read_file", "toolu_001"));

        // Act
        var messages = await store.ReconstructMessagesAsync();

        // Assert — should be 3 messages: user, assistant(text+tool_use), user(tool_result)
        messages.Should().HaveCount(3);

        var userMsg = JsonSerializer.Serialize(messages[0]);
        userMsg.Should().Contain("\"role\":\"user\"");
        userMsg.Should().Contain("Read file test.txt");

        // Assistant message should have both text and tool_use content blocks
        var assistantMsg = JsonSerializer.Serialize(messages[1]);
        assistantMsg.Should().Contain("\"role\":\"assistant\"");
        assistantMsg.Should().Contain("\"type\":\"text\"");
        assistantMsg.Should().Contain("I will read that file.");
        assistantMsg.Should().Contain("\"type\":\"tool_use\"");
        assistantMsg.Should().Contain("toolu_001");
        assistantMsg.Should().Contain("read_file");

        // Tool result message
        var toolResultMsg = JsonSerializer.Serialize(messages[2]);
        toolResultMsg.Should().Contain("\"role\":\"user\"");
        toolResultMsg.Should().Contain("\"type\":\"tool_result\"");
        toolResultMsg.Should().Contain("toolu_001");
        toolResultMsg.Should().Contain("file contents here");
    }

    [Fact]
    public async Task Should_GroupMultipleToolResultsInSingleUserMessage()
    {
        // Arrange — two tool_use followed by two tool_result
        var sessionId = Guid.NewGuid();
        using var store = new SessionStore(_projectPath, sessionId, _testRoot);

        await store.AppendAsync(new SessionEvent("user", "user", "Read two files", DateTimeOffset.UtcNow));
        await store.AppendAsync(new SessionEvent("tool_use", "assistant", """{"path":"a.txt"}""", DateTimeOffset.UtcNow.AddSeconds(1), "read_file", "toolu_A"));
        await store.AppendAsync(new SessionEvent("tool_use", "assistant", """{"path":"b.txt"}""", DateTimeOffset.UtcNow.AddSeconds(2), "read_file", "toolu_B"));
        await store.AppendAsync(new SessionEvent("tool_result", "user", "contents A", DateTimeOffset.UtcNow.AddSeconds(3), "read_file", "toolu_A"));
        await store.AppendAsync(new SessionEvent("tool_result", "user", "contents B", DateTimeOffset.UtcNow.AddSeconds(4), "read_file", "toolu_B"));

        // Act
        var messages = await store.ReconstructMessagesAsync();

        // Assert — 3 messages: user, assistant(2 tool_use), user(2 tool_result)
        messages.Should().HaveCount(3);

        var assistantMsg = JsonSerializer.Serialize(messages[1]);
        assistantMsg.Should().Contain("toolu_A");
        assistantMsg.Should().Contain("toolu_B");

        var toolResultMsg = JsonSerializer.Serialize(messages[2]);
        toolResultMsg.Should().Contain("toolu_A");
        toolResultMsg.Should().Contain("toolu_B");
    }

    [Fact]
    public async Task Should_ParseToolInputAsJsonObject()
    {
        // Arrange
        var sessionId = Guid.NewGuid();
        using var store = new SessionStore(_projectPath, sessionId, _testRoot);

        await store.AppendAsync(new SessionEvent("user", "user", "test", DateTimeOffset.UtcNow));
        await store.AppendAsync(new SessionEvent("tool_use", "assistant", """{"path":"/tmp/test.txt","content":"hello"}""", DateTimeOffset.UtcNow.AddSeconds(1), "write_file", "toolu_X"));
        await store.AppendAsync(new SessionEvent("tool_result", "user", "ok", DateTimeOffset.UtcNow.AddSeconds(2), "write_file", "toolu_X"));

        // Act
        var messages = await store.ReconstructMessagesAsync();

        // Assert — input should be serialized as a JSON object (not a string)
        var assistantMsg = JsonSerializer.Serialize(messages[1]);
        // The input field should contain the parsed JSON object, not a stringified version
        assistantMsg.Should().Contain("\"input\":{\"path\":\"/tmp/test.txt\",\"content\":\"hello\"}");
    }

    [Fact]
    public async Task Should_HandleToolErrorWithIsErrorFlag()
    {
        // Arrange
        var sessionId = Guid.NewGuid();
        using var store = new SessionStore(_projectPath, sessionId, _testRoot);

        await store.AppendAsync(new SessionEvent("user", "user", "do something", DateTimeOffset.UtcNow));
        await store.AppendAsync(new SessionEvent("tool_use", "assistant", "{}", DateTimeOffset.UtcNow.AddSeconds(1), "run_command", "toolu_E"));
        await store.AppendAsync(new SessionEvent("tool_error", "user", "command failed", DateTimeOffset.UtcNow.AddSeconds(2), "run_command", "toolu_E"));

        // Act
        var messages = await store.ReconstructMessagesAsync();

        // Assert
        messages.Should().HaveCount(3);

        var errorMsg = JsonSerializer.Serialize(messages[2]);
        errorMsg.Should().Contain("\"type\":\"tool_result\"");
        errorMsg.Should().Contain("\"is_error\":true");
        errorMsg.Should().Contain("command failed");
    }

    [Fact]
    public async Task Should_ProduceContentArrayForAllMessages()
    {
        // Arrange — even simple text messages should use content arrays
        var sessionId = Guid.NewGuid();
        using var store = new SessionStore(_projectPath, sessionId, _testRoot);

        await store.AppendAsync(new SessionEvent("user", "user", "Hello", DateTimeOffset.UtcNow));
        await store.AppendAsync(new SessionEvent("assistant", "assistant", "Hi there", DateTimeOffset.UtcNow.AddSeconds(1)));

        // Act
        var messages = await store.ReconstructMessagesAsync();

        // Assert — both messages should have content as arrays with type field
        messages.Should().HaveCount(2);

        var userMsg = JsonSerializer.Serialize(messages[0]);
        userMsg.Should().Contain("\"content\":[{\"type\":\"text\"");

        var assistantMsg = JsonSerializer.Serialize(messages[1]);
        assistantMsg.Should().Contain("\"content\":[{\"type\":\"text\"");
    }

    [Fact]
    public async Task Should_InjectSyntheticToolResultForOrphanedToolUse()
    {
        // Arrange — simulate session interrupted between tool_use and tool_result
        var sessionId = Guid.NewGuid();
        using var store = new SessionStore(_projectPath, sessionId, _testRoot);

        await store.AppendAsync(new SessionEvent("user", "user", "Read a file", DateTimeOffset.UtcNow));
        await store.AppendAsync(new SessionEvent("assistant", "assistant", "I'll read it", DateTimeOffset.UtcNow.AddSeconds(1)));
        await store.AppendAsync(new SessionEvent("tool_use", "assistant", """{"path":"test.txt"}""", DateTimeOffset.UtcNow.AddSeconds(2), "read_file", "toolu_orphaned"));
        // Session interrupted here - no tool_result saved

        // Act
        var messages = await store.ReconstructMessagesAsync();

        // Assert — should have 3 messages: user, assistant(text+tool_use), synthetic user(tool_result)
        messages.Should().HaveCount(3);

        var assistantMsg = JsonSerializer.Serialize(messages[1]);
        assistantMsg.Should().Contain("\"role\":\"assistant\"");
        assistantMsg.Should().Contain("toolu_orphaned");

        // Synthetic tool_result message should be injected
        var syntheticMsg = JsonSerializer.Serialize(messages[2]);
        syntheticMsg.Should().Contain("\"role\":\"user\"");
        syntheticMsg.Should().Contain("\"type\":\"tool_result\"");
        syntheticMsg.Should().Contain("\"tool_use_id\":\"toolu_orphaned\"");
        syntheticMsg.Should().Contain("Session was interrupted");
        syntheticMsg.Should().Contain("\"is_error\":true");
    }

    [Fact]
    public async Task Should_InjectSyntheticToolResultsForMultipleOrphanedToolUses()
    {
        // Arrange — multiple orphaned tool_use blocks
        var sessionId = Guid.NewGuid();
        using var store = new SessionStore(_projectPath, sessionId, _testRoot);

        await store.AppendAsync(new SessionEvent("user", "user", "Read two files", DateTimeOffset.UtcNow));
        await store.AppendAsync(new SessionEvent("tool_use", "assistant", """{"path":"a.txt"}""", DateTimeOffset.UtcNow.AddSeconds(1), "read_file", "toolu_A"));
        await store.AppendAsync(new SessionEvent("tool_use", "assistant", """{"path":"b.txt"}""", DateTimeOffset.UtcNow.AddSeconds(2), "read_file", "toolu_B"));
        // Session interrupted - no tool_results

        // Act
        var messages = await store.ReconstructMessagesAsync();

        // Assert — should inject a single user message with both tool_results
        messages.Should().HaveCount(3);

        var syntheticMsg = JsonSerializer.Serialize(messages[2]);
        syntheticMsg.Should().Contain("\"role\":\"user\"");
        syntheticMsg.Should().Contain("toolu_A");
        syntheticMsg.Should().Contain("toolu_B");
        syntheticMsg.Should().Contain("Session was interrupted");
    }

    [Fact]
    public async Task Should_NotInjectSyntheticToolResultWhenToolResultExists()
    {
        // Arrange — complete tool_use and tool_result pair
        var sessionId = Guid.NewGuid();
        using var store = new SessionStore(_projectPath, sessionId, _testRoot);

        await store.AppendAsync(new SessionEvent("user", "user", "Read file", DateTimeOffset.UtcNow));
        await store.AppendAsync(new SessionEvent("tool_use", "assistant", """{"path":"test.txt"}""", DateTimeOffset.UtcNow.AddSeconds(1), "read_file", "toolu_complete"));
        await store.AppendAsync(new SessionEvent("tool_result", "user", "file contents", DateTimeOffset.UtcNow.AddSeconds(2), "read_file", "toolu_complete"));

        // Act
        var messages = await store.ReconstructMessagesAsync();

        // Assert — should NOT inject synthetic message (3 messages: user, assistant, user)
        messages.Should().HaveCount(3);

        var toolResultMsg = JsonSerializer.Serialize(messages[2]);
        toolResultMsg.Should().Contain("file contents");
        toolResultMsg.Should().NotContain("Session was interrupted");
    }

    [Fact]
    public async Task Should_AugmentExistingUserMessageWhenPartialToolResultsExist()
    {
        // Arrange — multiple tool_use blocks, only some tool_results persisted before crash
        var sessionId = Guid.NewGuid();
        using var store = new SessionStore(_projectPath, sessionId, _testRoot);

        await store.AppendAsync(new SessionEvent("user", "user", "Read three files", DateTimeOffset.UtcNow));
        await store.AppendAsync(new SessionEvent("tool_use", "assistant", """{"path":"a.txt"}""", DateTimeOffset.UtcNow.AddSeconds(1), "read_file", "toolu_A"));
        await store.AppendAsync(new SessionEvent("tool_use", "assistant", """{"path":"b.txt"}""", DateTimeOffset.UtcNow.AddSeconds(2), "read_file", "toolu_B"));
        await store.AppendAsync(new SessionEvent("tool_use", "assistant", """{"path":"c.txt"}""", DateTimeOffset.UtcNow.AddSeconds(3), "read_file", "toolu_C"));
        // Only toolu_A completed before crash
        await store.AppendAsync(new SessionEvent("tool_result", "user", "contents A", DateTimeOffset.UtcNow.AddSeconds(4), "read_file", "toolu_A"));

        // Act
        var messages = await store.ReconstructMessagesAsync();

        // Assert — should be 3 messages: user, assistant(3 tool_use), user(1 existing + 2 synthetic tool_result)
        messages.Should().HaveCount(3);

        var userMsg = JsonSerializer.Serialize(messages[2]);
        userMsg.Should().Contain("\"role\":\"user\"");
        // Should have all three tool_results in the same message
        userMsg.Should().Contain("toolu_A");
        userMsg.Should().Contain("toolu_B");
        userMsg.Should().Contain("toolu_C");
        userMsg.Should().Contain("contents A"); // Existing result
        userMsg.Should().Contain("Session was interrupted"); // Synthetic results
    }

    [Fact]
    public async Task Should_PersistCompactionEventWithMetadata()
    {
        // Arrange
        var sessionId = Guid.NewGuid();
        using var store = new SessionStore(_projectPath, sessionId, _testRoot);

        var compactionEvent = new SessionEvent(
            Type: "compaction",
            Role: null,
            Content: "Compacted old messages to save tokens...",
            Timestamp: DateTimeOffset.UtcNow,
            TokensBefore: 150000,
            TokensAfter: 80000,
            MessagesRemoved: 25);

        // Act
        await store.AppendAsync(compactionEvent);

        var loadedEvents = new List<SessionEvent>();
        await foreach (var evt in store.LoadAsync())
        {
            loadedEvents.Add(evt);
        }

        // Assert
        loadedEvents.Should().HaveCount(1);
        var loaded = loadedEvents[0];
        loaded.Type.Should().Be("compaction");
        loaded.Role.Should().BeNull();
        loaded.Content.Should().Be("Compacted old messages to save tokens...");
        loaded.TokensBefore.Should().Be(150000);
        loaded.TokensAfter.Should().Be(80000);
        loaded.MessagesRemoved.Should().Be(25);
    }

    [Fact]
    public async Task Should_SkipCompactionEventsInReconstruction()
    {
        // Arrange
        var sessionId = Guid.NewGuid();
        using var store = new SessionStore(_projectPath, sessionId, _testRoot);

        // Add a user message
        await store.AppendAsync(new SessionEvent(
            Type: "user",
            Role: "user",
            Content: "Hello",
            Timestamp: DateTimeOffset.UtcNow));

        // Add a compaction event (should be skipped)
        await store.AppendAsync(new SessionEvent(
            Type: "compaction",
            Role: null,
            Content: "Compacted conversation",
            Timestamp: DateTimeOffset.UtcNow.AddSeconds(1),
            TokensBefore: 100000,
            TokensAfter: 50000,
            MessagesRemoved: 10));

        // Add an assistant message
        await store.AppendAsync(new SessionEvent(
            Type: "assistant",
            Role: "assistant",
            Content: "Hi there!",
            Timestamp: DateTimeOffset.UtcNow.AddSeconds(2)));

        // Act
        var messages = await store.ReconstructMessagesAsync();

        // Assert
        // Should only have 2 messages (user and assistant), compaction event skipped
        messages.Should().HaveCount(2);

        var userMsg = JsonSerializer.Serialize(messages[0]);
        userMsg.Should().Contain("\"role\":\"user\"");
        userMsg.Should().Contain("Hello");

        var assistantMsg = JsonSerializer.Serialize(messages[1]);
        assistantMsg.Should().Contain("\"role\":\"assistant\"");
        assistantMsg.Should().Contain("Hi there!");
    }

    [Fact]
    public async Task Should_LoadCompactionEventsForInspection()
    {
        // Arrange
        var sessionId = Guid.NewGuid();
        using var store = new SessionStore(_projectPath, sessionId, _testRoot);

        // Add multiple events including compaction
        await store.AppendAsync(new SessionEvent(
            Type: "user",
            Role: "user",
            Content: "First message",
            Timestamp: DateTimeOffset.UtcNow));

        await store.AppendAsync(new SessionEvent(
            Type: "compaction",
            Role: null,
            Content: "First compaction",
            Timestamp: DateTimeOffset.UtcNow.AddSeconds(1),
            TokensBefore: 100000,
            TokensAfter: 50000,
            MessagesRemoved: 10));

        await store.AppendAsync(new SessionEvent(
            Type: "assistant",
            Role: "assistant",
            Content: "Response",
            Timestamp: DateTimeOffset.UtcNow.AddSeconds(2)));

        await store.AppendAsync(new SessionEvent(
            Type: "compaction",
            Role: null,
            Content: "Second compaction",
            Timestamp: DateTimeOffset.UtcNow.AddSeconds(3),
            TokensBefore: 120000,
            TokensAfter: 60000,
            MessagesRemoved: 15));

        // Act
        var loadedEvents = new List<SessionEvent>();
        await foreach (var evt in store.LoadAsync())
        {
            loadedEvents.Add(evt);
        }

        // Assert
        // All events should be loaded (4 total)
        loadedEvents.Should().HaveCount(4);

        // Verify compaction events are present
        var compactionEvents = loadedEvents.Where(e => e.Type == "compaction").ToList();
        compactionEvents.Should().HaveCount(2);

        compactionEvents[0].Content.Should().Be("First compaction");
        compactionEvents[0].TokensBefore.Should().Be(100000);
        compactionEvents[0].TokensAfter.Should().Be(50000);
        compactionEvents[0].MessagesRemoved.Should().Be(10);

        compactionEvents[1].Content.Should().Be("Second compaction");
        compactionEvents[1].TokensBefore.Should().Be(120000);
        compactionEvents[1].TokensAfter.Should().Be(60000);
        compactionEvents[1].MessagesRemoved.Should().Be(15);
    }

    [Fact]
    public async Task Should_ReconstructMessagesCorrectlyWithMixedEventsIncludingCompaction()
    {
        // Arrange
        var sessionId = Guid.NewGuid();
        using var store = new SessionStore(_projectPath, sessionId, _testRoot);

        // Simulate a conversation with multiple compactions
        await store.AppendAsync(new SessionEvent(
            Type: "user",
            Role: "user",
            Content: "First user message",
            Timestamp: DateTimeOffset.UtcNow));

        await store.AppendAsync(new SessionEvent(
            Type: "assistant",
            Role: "assistant",
            Content: "First assistant response",
            Timestamp: DateTimeOffset.UtcNow.AddSeconds(1)));

        // First compaction
        await store.AppendAsync(new SessionEvent(
            Type: "compaction",
            Role: null,
            Content: "Compacted early messages",
            Timestamp: DateTimeOffset.UtcNow.AddSeconds(2),
            TokensBefore: 80000,
            TokensAfter: 40000,
            MessagesRemoved: 5));

        await store.AppendAsync(new SessionEvent(
            Type: "user",
            Role: "user",
            Content: "Second user message",
            Timestamp: DateTimeOffset.UtcNow.AddSeconds(3)));

        await store.AppendAsync(new SessionEvent(
            Type: "tool_use",
            Role: "assistant",
            Content: """{"path": "test.txt"}""",
            Timestamp: DateTimeOffset.UtcNow.AddSeconds(4),
            ToolName: "read_file",
            ToolUseId: "toolu_123"));

        await store.AppendAsync(new SessionEvent(
            Type: "tool_result",
            Role: "user",
            Content: "file contents",
            Timestamp: DateTimeOffset.UtcNow.AddSeconds(5),
            ToolName: "read_file",
            ToolUseId: "toolu_123"));

        // Second compaction
        await store.AppendAsync(new SessionEvent(
            Type: "compaction",
            Role: null,
            Content: "Compacted more messages",
            Timestamp: DateTimeOffset.UtcNow.AddSeconds(6),
            TokensBefore: 120000,
            TokensAfter: 60000,
            MessagesRemoved: 8));

        await store.AppendAsync(new SessionEvent(
            Type: "assistant",
            Role: "assistant",
            Content: "Final response",
            Timestamp: DateTimeOffset.UtcNow.AddSeconds(7)));

        // Act
        var messages = await store.ReconstructMessagesAsync();

        // Assert
        // Should have 6 messages: user, assistant, user, assistant(tool_use), user(tool_result), assistant
        // Compaction events should be completely skipped
        messages.Should().HaveCount(6);

        var msg0 = JsonSerializer.Serialize(messages[0]);
        msg0.Should().Contain("\"role\":\"user\"");
        msg0.Should().Contain("First user message");

        var msg1 = JsonSerializer.Serialize(messages[1]);
        msg1.Should().Contain("\"role\":\"assistant\"");
        msg1.Should().Contain("First assistant response");

        var msg2 = JsonSerializer.Serialize(messages[2]);
        msg2.Should().Contain("\"role\":\"user\"");
        msg2.Should().Contain("Second user message");

        var msg3 = JsonSerializer.Serialize(messages[3]);
        msg3.Should().Contain("\"role\":\"assistant\"");
        msg3.Should().Contain("tool_use");
        msg3.Should().Contain("read_file");
        msg3.Should().Contain("toolu_123");

        var msg4 = JsonSerializer.Serialize(messages[4]);
        msg4.Should().Contain("\"role\":\"user\"");
        msg4.Should().Contain("tool_result");
        msg4.Should().Contain("file contents");
        msg4.Should().Contain("toolu_123");

        var msg5 = JsonSerializer.Serialize(messages[5]);
        msg5.Should().Contain("\"role\":\"assistant\"");
        msg5.Should().Contain("Final response");
    }
}
