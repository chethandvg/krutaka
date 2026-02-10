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
        // Use a unique directory for each test run
        var uniqueId = Guid.NewGuid().ToString("N")[..8];
        _testRoot = Path.Combine(Path.GetTempPath(), $"krutaka-session-test-{uniqueId}");
        _projectPath = Path.Combine(_testRoot, "test-project");
        Directory.CreateDirectory(_projectPath);
    }

    public void Dispose()
    {
        // Cleanup test directory
        if (Directory.Exists(_testRoot))
        {
            Directory.Delete(_testRoot, true);
        }

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
}
