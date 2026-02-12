using FluentAssertions;
using Krutaka.Core;
using Krutaka.Memory;

namespace Krutaka.Memory.Tests;

public sealed class SessionStoreDiscoveryTests : IDisposable
{
    private readonly string _testRoot;
    private readonly string _projectPath;

    public SessionStoreDiscoveryTests()
    {
        _testRoot = TestDirectoryHelper.GetTestDirectory("session-discovery-test");
        _projectPath = Path.Combine(_testRoot, "test-project");
        Directory.CreateDirectory(_projectPath);
    }

    public void Dispose()
    {
        TestDirectoryHelper.TryDeleteDirectory(_testRoot);
        GC.SuppressFinalize(this);
    }

    [Fact]
    public void FindMostRecentSession_Should_ReturnNull_WhenNoSessionsExist()
    {
        // Act
        var result = SessionStore.FindMostRecentSession(_projectPath, _testRoot);

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public async Task FindMostRecentSession_Should_ReturnMostRecent_WhenMultipleSessionsExist()
    {
        // Arrange
        var session1 = Guid.NewGuid();
        var session2 = Guid.NewGuid();
        var session3 = Guid.NewGuid();

        var encodedPath = SessionStore.EncodeProjectPath(_projectPath);
        var sessionDir = Path.Combine(_testRoot, "sessions", encodedPath);

        using var store1 = new SessionStore(_projectPath, session1, _testRoot);
        await store1.AppendAsync(new SessionEvent("user", "user", "First session", DateTimeOffset.UtcNow));
        var file1 = Path.Combine(sessionDir, $"{session1}.jsonl");
        File.SetLastWriteTimeUtc(file1, DateTime.UtcNow.AddMinutes(-2));

        using var store2 = new SessionStore(_projectPath, session2, _testRoot);
        await store2.AppendAsync(new SessionEvent("user", "user", "Second session", DateTimeOffset.UtcNow));
        var file2 = Path.Combine(sessionDir, $"{session2}.jsonl");
        File.SetLastWriteTimeUtc(file2, DateTime.UtcNow.AddMinutes(-1));

        using var store3 = new SessionStore(_projectPath, session3, _testRoot);
        await store3.AppendAsync(new SessionEvent("user", "user", "Third session (most recent)", DateTimeOffset.UtcNow));
        // file3 has the most recent timestamp (current time)

        // Act
        var result = SessionStore.FindMostRecentSession(_projectPath, _testRoot);

        // Assert
        result.Should().Be(session3);
    }

    [Fact]
    public async Task FindMostRecentSession_Should_IgnoreEmptyFiles()
    {
        // Arrange - create empty session file
        var encodedPath = SessionStore.EncodeProjectPath(_projectPath);
        var sessionDir = Path.Combine(_testRoot, "sessions", encodedPath);
        Directory.CreateDirectory(sessionDir);

        var emptySessionId = Guid.NewGuid();
        await File.WriteAllTextAsync(Path.Combine(sessionDir, $"{emptySessionId}.jsonl"), "");

        // Act
        var result = SessionStore.FindMostRecentSession(_projectPath, _testRoot);

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public async Task ListSessions_Should_ReturnOrderedByModifiedDate()
    {
        // Arrange
        var session1 = Guid.NewGuid();
        var session2 = Guid.NewGuid();

        var encodedPath = SessionStore.EncodeProjectPath(_projectPath);
        var sessionDir = Path.Combine(_testRoot, "sessions", encodedPath);

        using var store1 = new SessionStore(_projectPath, session1, _testRoot);
        await store1.AppendAsync(new SessionEvent("user", "user", "Older session", DateTimeOffset.UtcNow));
        var file1 = Path.Combine(sessionDir, $"{session1}.jsonl");
        File.SetLastWriteTimeUtc(file1, DateTime.UtcNow.AddMinutes(-1));

        using var store2 = new SessionStore(_projectPath, session2, _testRoot);
        await store2.AppendAsync(new SessionEvent("user", "user", "Newer session", DateTimeOffset.UtcNow));
        // file2 has the most recent timestamp (current time)

        // Act
        var sessions = SessionStore.ListSessions(_projectPath, storageRoot: _testRoot);

        // Assert
        sessions.Should().HaveCount(2);
        sessions[0].SessionId.Should().Be(session2); // Most recent first
        sessions[1].SessionId.Should().Be(session1);
    }

    [Fact]
    public async Task ListSessions_Should_RespectLimitParameter()
    {
        // Arrange - create 5 sessions with explicit timestamps
        var encodedPath = SessionStore.EncodeProjectPath(_projectPath);
        var sessionDir = Path.Combine(_testRoot, "sessions", encodedPath);

        for (int i = 0; i < 5; i++)
        {
            var sessionId = Guid.NewGuid();
            using var store = new SessionStore(_projectPath, sessionId, _testRoot);
            await store.AppendAsync(new SessionEvent("user", "user", $"Session {i}", DateTimeOffset.UtcNow));
            
            // Set explicit timestamp to ensure ordering
            var file = Path.Combine(sessionDir, $"{sessionId}.jsonl");
            File.SetLastWriteTimeUtc(file, DateTime.UtcNow.AddMinutes(-5 + i));
        }

        // Act
        var sessions = SessionStore.ListSessions(_projectPath, limit: 3, storageRoot: _testRoot);

        // Assert
        sessions.Should().HaveCount(3);
    }

    [Fact]
    public async Task ListSessions_Should_IncludeMessageCountAndPreview()
    {
        // Arrange
        var sessionId = Guid.NewGuid();
        using var store = new SessionStore(_projectPath, sessionId, _testRoot);

        await store.AppendAsync(new SessionEvent("user", "user", "Hello, this is my first message!", DateTimeOffset.UtcNow));
        await store.AppendAsync(new SessionEvent("assistant", "assistant", "Hi there!", DateTimeOffset.UtcNow.AddSeconds(1)));
        await store.AppendAsync(new SessionEvent("user", "user", "Second message", DateTimeOffset.UtcNow.AddSeconds(2)));

        // Act
        var sessions = SessionStore.ListSessions(_projectPath, storageRoot: _testRoot);

        // Assert
        sessions.Should().HaveCount(1);
        sessions[0].MessageCount.Should().Be(3);
        sessions[0].FirstUserMessage.Should().Be("Hello, this is my first message!");
    }

    [Fact]
    public async Task ListSessions_Should_TruncateFirstUserMessageAt50Chars()
    {
        // Arrange
        var sessionId = Guid.NewGuid();
        using var store = new SessionStore(_projectPath, sessionId, _testRoot);

        var longMessage = "This is a very long message that should be truncated at exactly fifty characters and then add ellipsis";
        await store.AppendAsync(new SessionEvent("user", "user", longMessage, DateTimeOffset.UtcNow));

        // Act
        var sessions = SessionStore.ListSessions(_projectPath, storageRoot: _testRoot);

        // Assert
        sessions.Should().HaveCount(1);
        sessions[0].FirstUserMessage.Should().HaveLength(53); // 50 chars + "..."
        sessions[0].FirstUserMessage.Should().EndWith("...");
    }

    [Fact]
    public void ListSessions_Should_ReturnEmptyList_WhenNoSessionsExist()
    {
        // Act
        var sessions = SessionStore.ListSessions(_projectPath, storageRoot: _testRoot);

        // Assert
        sessions.Should().BeEmpty();
    }

    [Fact]
    public async Task ListSessions_Should_IgnoreEmptyFiles()
    {
        // Arrange - create one valid session and one empty file
        var validSessionId = Guid.NewGuid();
        using var validStore = new SessionStore(_projectPath, validSessionId, _testRoot);
        await validStore.AppendAsync(new SessionEvent("user", "user", "Valid message", DateTimeOffset.UtcNow));

        var encodedPath = SessionStore.EncodeProjectPath(_projectPath);
        var sessionDir = Path.Combine(_testRoot, "sessions", encodedPath);
        var emptySessionId = Guid.NewGuid();
        await File.WriteAllTextAsync(Path.Combine(sessionDir, $"{emptySessionId}.jsonl"), "");

        // Act
        var sessions = SessionStore.ListSessions(_projectPath, storageRoot: _testRoot);

        // Assert
        sessions.Should().HaveCount(1);
        sessions[0].SessionId.Should().Be(validSessionId);
    }

    [Fact]
    public async Task ListSessions_Should_SkipCorruptedFiles()
    {
        // Arrange - create one valid session and one corrupted file
        var validSessionId = Guid.NewGuid();
        using var validStore = new SessionStore(_projectPath, validSessionId, _testRoot);
        await validStore.AppendAsync(new SessionEvent("user", "user", "Valid message", DateTimeOffset.UtcNow));

        var encodedPath = SessionStore.EncodeProjectPath(_projectPath);
        var sessionDir = Path.Combine(_testRoot, "sessions", encodedPath);
        var corruptedSessionId = Guid.NewGuid();
        await File.WriteAllTextAsync(Path.Combine(sessionDir, $"{corruptedSessionId}.jsonl"), "{ invalid json }{");

        // Act
        var sessions = SessionStore.ListSessions(_projectPath, storageRoot: _testRoot);

        // Assert
        sessions.Should().HaveCount(1);
        sessions[0].SessionId.Should().Be(validSessionId);
    }

    [Fact]
    public async Task ListSessions_Should_IgnoreMetadataEvents()
    {
        // Arrange
        var sessionId = Guid.NewGuid();
        using var store = new SessionStore(_projectPath, sessionId, _testRoot);

        await store.AppendAsync(new SessionEvent("user", "user", "User message", DateTimeOffset.UtcNow));
        await store.AppendAsync(new SessionEvent("meta", "meta", "Metadata event", DateTimeOffset.UtcNow, IsMeta: true));
        await store.AppendAsync(new SessionEvent("assistant", "assistant", "Assistant message", DateTimeOffset.UtcNow));

        // Act
        var sessions = SessionStore.ListSessions(_projectPath, storageRoot: _testRoot);

        // Assert
        sessions.Should().HaveCount(1);
        sessions[0].MessageCount.Should().Be(2); // Only non-meta messages
    }
}
