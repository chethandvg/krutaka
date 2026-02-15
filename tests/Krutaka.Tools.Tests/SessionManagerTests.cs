using FluentAssertions;
using Krutaka.Core;
using Krutaka.Tools;
using Microsoft.Extensions.Logging;

namespace Krutaka.Tools.Tests;

public class SessionManagerTests : IAsyncDisposable
{
    private readonly SessionManager _sessionManager;
    private readonly ISessionFactory _sessionFactory;
    private readonly string _testDirectory;

    public SessionManagerTests()
    {
        _testDirectory = Path.Combine(Path.GetTempPath(), $"krutaka-tests-{Guid.NewGuid()}");
        Directory.CreateDirectory(_testDirectory);

        var claudeClient = new MockClaudeClient();
        var securityPolicy = new MockSecurityPolicy();
        var accessPolicyEngine = new MockAccessPolicyEngine();
        var commandRiskClassifier = new MockCommandRiskClassifier();
        var toolOptions = new ToolOptions { DefaultWorkingDirectory = _testDirectory };

        _sessionFactory = new SessionFactory(
            claudeClient,
            securityPolicy,
            accessPolicyEngine,
            commandRiskClassifier,
            toolOptions,
            auditLogger: null);

        var options = new SessionManagerOptions(
            MaxActiveSessions: 3,
            IdleTimeout: TimeSpan.FromSeconds(1),
            SuspendedTtl: TimeSpan.FromSeconds(5),
            GlobalMaxTokensPerHour: 10000,
            MaxSessionsPerUser: 2,
            EvictionStrategy: EvictionStrategy.SuspendOldestIdle);

        _sessionManager = new SessionManager(_sessionFactory, options, logger: null);
    }

    public async ValueTask DisposeAsync()
    {
        await _sessionManager.DisposeAsync();

        if (Directory.Exists(_testDirectory))
        {
            Directory.Delete(_testDirectory, recursive: true);
        }

        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task CreateSessionAsync_Should_CreateAndStoreSession()
    {
        // Arrange
        var request = new SessionRequest(ProjectPath: _testDirectory);

        // Act
        var session = await _sessionManager.CreateSessionAsync(request, CancellationToken.None);

        // Assert
        session.Should().NotBeNull();
        session.SessionId.Should().NotBeEmpty();
        session.ProjectPath.Should().Be(_testDirectory);
        session.State.Should().Be(SessionState.Active);
    }

    [Fact]
    public async Task GetSession_Should_ReturnExistingSession()
    {
        // Arrange
        var request = new SessionRequest(ProjectPath: _testDirectory);
        var created = await _sessionManager.CreateSessionAsync(request, CancellationToken.None);

        // Act
        var retrieved = _sessionManager.GetSession(created.SessionId);

        // Assert
        retrieved.Should().NotBeNull();
        retrieved!.SessionId.Should().Be(created.SessionId);
    }

    [Fact]
    public void GetSession_Should_ReturnNull_WhenSessionDoesNotExist()
    {
        // Act
        var session = _sessionManager.GetSession(Guid.NewGuid());

        // Assert
        session.Should().BeNull();
    }

    [Fact]
    public async Task GetOrCreateByKeyAsync_Should_CreateNewSession_WhenKeyDoesNotExist()
    {
        // Arrange
        var externalKey = "telegram:12345";
        var request = new SessionRequest(ProjectPath: _testDirectory, ExternalKey: externalKey);

        // Act
        var session = await _sessionManager.GetOrCreateByKeyAsync(externalKey, request, CancellationToken.None);

        // Assert
        session.Should().NotBeNull();
        session.ExternalKey.Should().Be(externalKey);
    }

    [Fact]
    public async Task GetOrCreateByKeyAsync_Should_ReturnExistingSession_WhenKeyExists()
    {
        // Arrange
        var externalKey = "telegram:12345";
        var request = new SessionRequest(ProjectPath: _testDirectory, ExternalKey: externalKey);
        var firstSession = await _sessionManager.GetOrCreateByKeyAsync(externalKey, request, CancellationToken.None);

        // Act
        var secondSession = await _sessionManager.GetOrCreateByKeyAsync(externalKey, request, CancellationToken.None);

        // Assert
        secondSession.SessionId.Should().Be(firstSession.SessionId);
    }

    [Fact]
    public async Task GetOrCreateByKeyAsync_Should_CreateDifferentSessions_ForDifferentKeys()
    {
        // Arrange
        var key1 = "telegram:12345";
        var key2 = "telegram:67890";
        var request1 = new SessionRequest(ProjectPath: _testDirectory, ExternalKey: key1);
        var request2 = new SessionRequest(ProjectPath: _testDirectory, ExternalKey: key2);

        // Act
        var session1 = await _sessionManager.GetOrCreateByKeyAsync(key1, request1, CancellationToken.None);
        var session2 = await _sessionManager.GetOrCreateByKeyAsync(key2, request2, CancellationToken.None);

        // Assert
        session1.SessionId.Should().NotBe(session2.SessionId);
        session1.ExternalKey.Should().Be(key1);
        session2.ExternalKey.Should().Be(key2);
    }

    [Fact]
    public async Task CreateSessionAsync_Should_ThrowWhenMaxActiveSessionsReached_WithRejectNewStrategy()
    {
        // Arrange
        var options = new SessionManagerOptions(
            MaxActiveSessions: 1,
            EvictionStrategy: EvictionStrategy.RejectNew);
        await using var manager = new SessionManager(_sessionFactory, options, logger: null);

        var request1 = new SessionRequest(ProjectPath: _testDirectory);
        var request2 = new SessionRequest(ProjectPath: _testDirectory);

        // Act
        await manager.CreateSessionAsync(request1, CancellationToken.None);
        var act = async () => await manager.CreateSessionAsync(request2, CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*Maximum active sessions reached*");
    }

    [Fact]
    public async Task CreateSessionAsync_Should_ThrowWhenMaxSessionsPerUserReached()
    {
        // Arrange
        var userId = "user123";
        var options = new SessionManagerOptions(MaxSessionsPerUser: 2);
        await using var manager = new SessionManager(_sessionFactory, options, logger: null);

        var request1 = new SessionRequest(ProjectPath: _testDirectory, UserId: userId);
        var request2 = new SessionRequest(ProjectPath: _testDirectory, UserId: userId);
        var request3 = new SessionRequest(ProjectPath: _testDirectory, UserId: userId);

        // Act
        await manager.CreateSessionAsync(request1, CancellationToken.None);
        await manager.CreateSessionAsync(request2, CancellationToken.None);
        var act = async () => await manager.CreateSessionAsync(request3, CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*maximum session limit*");
    }

    [Fact]
    public async Task TerminateSessionAsync_Should_DisposeAndRemoveSession()
    {
        // Arrange
        var request = new SessionRequest(ProjectPath: _testDirectory);
        var session = await _sessionManager.CreateSessionAsync(request, CancellationToken.None);

        // Act
        await _sessionManager.TerminateSessionAsync(session.SessionId, CancellationToken.None);

        // Assert
        var retrieved = _sessionManager.GetSession(session.SessionId);
        retrieved.Should().BeNull();
        session.State.Should().Be(SessionState.Terminated);
    }

    [Fact]
    public async Task TerminateSessionAsync_Should_RemoveExternalKeyMapping()
    {
        // Arrange
        var externalKey = "telegram:12345";
        var request = new SessionRequest(ProjectPath: _testDirectory, ExternalKey: externalKey);
        var session = await _sessionManager.GetOrCreateByKeyAsync(externalKey, request, CancellationToken.None);
        var sessionId = session.SessionId;

        // Act
        await _sessionManager.TerminateSessionAsync(sessionId, CancellationToken.None);

        // Assert - Creating with same key should create a new session
        var newSession = await _sessionManager.GetOrCreateByKeyAsync(externalKey, request, CancellationToken.None);
        newSession.SessionId.Should().NotBe(sessionId);
    }

    [Fact]
    public async Task TerminateAllAsync_Should_DisposeAllSessions()
    {
        // Arrange
        var request1 = new SessionRequest(ProjectPath: _testDirectory);
        var request2 = new SessionRequest(ProjectPath: _testDirectory);
        var session1 = await _sessionManager.CreateSessionAsync(request1, CancellationToken.None);
        var session2 = await _sessionManager.CreateSessionAsync(request2, CancellationToken.None);

        // Act
        await _sessionManager.TerminateAllAsync(CancellationToken.None);

        // Assert
        var summaries = _sessionManager.ListActiveSessions();
        summaries.Should().BeEmpty();
        session1.State.Should().Be(SessionState.Terminated);
        session2.State.Should().Be(SessionState.Terminated);
    }

    [Fact]
    public async Task ListActiveSessions_Should_ReturnAllActiveSessions()
    {
        // Arrange
        var request1 = new SessionRequest(ProjectPath: _testDirectory);
        var request2 = new SessionRequest(ProjectPath: _testDirectory);
        await _sessionManager.CreateSessionAsync(request1, CancellationToken.None);
        await _sessionManager.CreateSessionAsync(request2, CancellationToken.None);

        // Act
        var summaries = _sessionManager.ListActiveSessions();

        // Assert
        summaries.Should().HaveCount(2);
        summaries.Should().AllSatisfy(s =>
        {
            s.ProjectPath.Should().Be(_testDirectory);
            s.State.Should().Be(SessionState.Active);
        });
    }

    [Fact]
    public async Task ConcurrentCreateSessionAsync_Should_NotThrow()
    {
        // Arrange
        var tasks = new List<Task<ManagedSession>>();
        var options = new SessionManagerOptions(MaxActiveSessions: 100);
        await using var manager = new SessionManager(_sessionFactory, options, logger: null);

        // Act
        for (int i = 0; i < 10; i++)
        {
            var request = new SessionRequest(ProjectPath: _testDirectory, ExternalKey: $"key-{i}");
            tasks.Add(manager.CreateSessionAsync(request, CancellationToken.None));
        }

        var sessions = await Task.WhenAll(tasks);

        // Assert
        sessions.Should().HaveCount(10);
        sessions.Select(s => s.SessionId).Distinct().Should().HaveCount(10);
    }

    [Fact]
    public async Task DisposeAsync_Should_CancelIdleDetectionTimer()
    {
        // Arrange
        var options = new SessionManagerOptions(IdleTimeout: TimeSpan.FromSeconds(1));
        var manager = new SessionManager(_sessionFactory, options, logger: null);

        // Act
        await manager.DisposeAsync();

        // Assert - No exception should be thrown
        await Task.Delay(1500);
    }

    [Fact]
    public async Task RecordTokenUsage_Should_TrackGlobalTokens()
    {
        // Arrange
        var options = new SessionManagerOptions(GlobalMaxTokensPerHour: 100);
        await using var manager = new SessionManager(_sessionFactory, options, logger: null);

        manager.RecordTokenUsage(50);
        manager.RecordTokenUsage(40);

        // Act - Should still allow session creation
        var request = new SessionRequest(ProjectPath: _testDirectory);
        var session = await manager.CreateSessionAsync(request, CancellationToken.None);

        // Assert
        session.Should().NotBeNull();
    }

    [Fact]
    public async Task CreateSessionAsync_Should_ThrowWhenGlobalTokenBudgetExhausted()
    {
        // Arrange
        var options = new SessionManagerOptions(GlobalMaxTokensPerHour: 100);
        await using var manager = new SessionManager(_sessionFactory, options, logger: null);

        manager.RecordTokenUsage(101);

        // Act
        var request = new SessionRequest(ProjectPath: _testDirectory);
        var act = async () => await manager.CreateSessionAsync(request, CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*Global token budget exhausted*");
    }

    [Fact]
    public async Task CreateSessionAsync_Should_AllowNewSessionAfterTerminationWhenMaxSessionsPerUserReached()
    {
        // Arrange
        var userId = "user123";
        var options = new SessionManagerOptions(MaxSessionsPerUser: 2);
        await using var manager = new SessionManager(_sessionFactory, options, logger: null);

        var request1 = new SessionRequest(ProjectPath: _testDirectory, UserId: userId);
        var request2 = new SessionRequest(ProjectPath: _testDirectory, UserId: userId);
        var request3 = new SessionRequest(ProjectPath: _testDirectory, UserId: userId);

        var session1 = await manager.CreateSessionAsync(request1, CancellationToken.None);
        var session2 = await manager.CreateSessionAsync(request2, CancellationToken.None);

        // Act - Terminate one session and create a new one
        await manager.TerminateSessionAsync(session1.SessionId, CancellationToken.None);
        var session3 = await manager.CreateSessionAsync(request3, CancellationToken.None);

        // Assert
        session1.State.Should().Be(SessionState.Terminated);
        session2.State.Should().Be(SessionState.Active);
        session3.Should().NotBeNull();
        session3.SessionId.Should().NotBe(session1.SessionId);
        session3.SessionId.Should().NotBe(session2.SessionId);
    }

    [Fact]
    public async Task ResumeSessionAsync_Should_ThrowWhenSessionNotFound()
    {
        // Act
        var act = async () => await _sessionManager.ResumeSessionAsync(
            Guid.NewGuid(),
            _testDirectory,
            CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*not found in active or suspended sessions*");
    }

    [Fact]
    public async Task ResumeSessionAsync_Should_ThrowWhenProjectPathDoesNotExist()
    {
        // Arrange
        var options = new SessionManagerOptions(IdleTimeout: TimeSpan.FromMilliseconds(50));
        await using var manager = new SessionManager(_sessionFactory, options, logger: null);

        var request = new SessionRequest(ProjectPath: _testDirectory);
        var session = await manager.CreateSessionAsync(request, CancellationToken.None);
        var sessionId = session.SessionId;

        // Wait for session to be suspended (need to wait for 2x IdleTimeout)
        await Task.Delay(200);

        // Verify the session is actually suspended
        var summaries = manager.ListActiveSessions();
        summaries.Should().Contain(s => s.SessionId == sessionId && s.State == SessionState.Suspended,
            "Session should be suspended after idle timeout");

        // Delete the project directory
        var nonExistentPath = Path.Combine(Path.GetTempPath(), $"nonexistent-{Guid.NewGuid()}");

        // Act
        var act = async () => await manager.ResumeSessionAsync(
            sessionId,
            nonExistentPath,
            CancellationToken.None);

        // Assert
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*project directory*does not exist*");
    }

    [Fact]
    public async Task ResumeSessionAsync_Should_ReturnActiveSessionIfAlreadyActive()
    {
        // Arrange
        var request = new SessionRequest(ProjectPath: _testDirectory);
        var session = await _sessionManager.CreateSessionAsync(request, CancellationToken.None);

        // Act
        var resumedSession = await _sessionManager.ResumeSessionAsync(
            session.SessionId,
            _testDirectory,
            CancellationToken.None);

        // Assert
        resumedSession.SessionId.Should().Be(session.SessionId);
        resumedSession.State.Should().Be(SessionState.Active);
    }

    [Fact]
    public async Task EvictionStrategy_Should_SuspendOldestIdleSession_WhenCapacityReached()
    {
        // Arrange
        var options = new SessionManagerOptions(
            MaxActiveSessions: 2,
            EvictionStrategy: EvictionStrategy.SuspendOldestIdle);
        await using var manager = new SessionManager(_sessionFactory, options, logger: null);

        var request1 = new SessionRequest(ProjectPath: _testDirectory);
        var request2 = new SessionRequest(ProjectPath: _testDirectory);
        var request3 = new SessionRequest(ProjectPath: _testDirectory);

        var session1 = await manager.CreateSessionAsync(request1, CancellationToken.None);
        await Task.Delay(50); // Ensure different LastActivity timestamps
        var session2 = await manager.CreateSessionAsync(request2, CancellationToken.None);

        // Act - This should trigger eviction of session1 (oldest)
        var session3 = await manager.CreateSessionAsync(request3, CancellationToken.None);

        // Assert
        session3.Should().NotBeNull();
        var summaries = manager.ListActiveSessions();
        // Should have 3 total: 2 active + 1 suspended
        summaries.Should().HaveCount(3);
        summaries.Count(s => s.State == SessionState.Suspended).Should().Be(1);
        summaries.Count(s => s.State == SessionState.Active).Should().Be(2);
    }

    [Fact]
    public async Task GetOrCreateByKeyAsync_Should_ResumeSuspendedSession_WhenExternalKeyPointsToSuspendedSession()
    {
        // Arrange
        var options = new SessionManagerOptions(IdleTimeout: TimeSpan.FromMilliseconds(50));
        await using var manager = new SessionManager(_sessionFactory, options, logger: null);

        var externalKey = "telegram:12345";
        var request = new SessionRequest(ProjectPath: _testDirectory, ExternalKey: externalKey);

        // Create a session with external key
        var session1 = await manager.GetOrCreateByKeyAsync(externalKey, request, CancellationToken.None);
        var sessionId1 = session1.SessionId;

        // Wait for session to be suspended (2x IdleTimeout)
        await Task.Delay(150);

        // Act - Get or create should resume the suspended session instead of creating a new one
        var session2 = await manager.GetOrCreateByKeyAsync(externalKey, request, CancellationToken.None);

        // Assert - Should be a new session instance (different GUID), but resumed from disk
        session2.Should().NotBeNull();
        session2.SessionId.Should().NotBe(sessionId1); // New session created, not the old one
        session2.ExternalKey.Should().Be(externalKey);

        // The old suspended session should be removed after resume
        var summaries = manager.ListActiveSessions();
        summaries.Should().HaveCount(1);
        summaries.Should().AllSatisfy(s => s.State.Should().Be(SessionState.Active));
    }

    [Fact]
    public async Task GetOrCreateByKeyAsync_Should_BeAtomic_UnderConcurrentCalls()
    {
        // Arrange
        var externalKey = "telegram:concurrent";
        var request = new SessionRequest(ProjectPath: _testDirectory, ExternalKey: externalKey);
        await using var manager = new SessionManager(_sessionFactory, new SessionManagerOptions(), logger: null);

        // Act - Make 5 concurrent calls for the same external key
        var tasks = Enumerable.Range(0, 5)
            .Select(_ => manager.GetOrCreateByKeyAsync(externalKey, request, CancellationToken.None))
            .ToList();

        var sessions = await Task.WhenAll(tasks);

        // Assert - All should return the same session ID (idempotent)
        sessions.Should().HaveCount(5);
        var uniqueSessionIds = sessions.Select(s => s.SessionId).Distinct().ToList();
        uniqueSessionIds.Should().ContainSingle("All concurrent calls should return the same session");

        // Only one session should exist
        var summaries = manager.ListActiveSessions();
        summaries.Should().ContainSingle();
    }

    // Mock implementations

    private sealed class MockClaudeClient : IClaudeClient
    {
        public async IAsyncEnumerable<AgentEvent> SendMessageAsync(
            IEnumerable<object> messages,
            string systemPrompt,
            object? tools,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await Task.CompletedTask;
            yield break;
        }

        public Task<int> CountTokensAsync(
            IEnumerable<object> messages,
            string systemPrompt,
            CancellationToken cancellationToken)
        {
            return Task.FromResult(0);
        }
    }

    private sealed class MockSecurityPolicy : ISecurityPolicy
    {
        public bool IsApprovalRequired(string toolName) => false;

        public string ValidatePath(string path, string workingDirectory, CorrelationContext? correlationContext = null)
        {
            return path;
        }

        public void ValidateCommand(string command, IEnumerable<string> arguments, CorrelationContext? correlationContext = null)
        {
        }

        public IDictionary<string, string?> ScrubEnvironment(IDictionary<string, string?> environment)
        {
            return environment;
        }
    }

    private sealed class MockAccessPolicyEngine : IAccessPolicyEngine
    {
        public Task<AccessDecision> EvaluateAsync(DirectoryAccessRequest request, CancellationToken cancellationToken)
        {
            return Task.FromResult(AccessDecision.Grant(
                scopedPath: request.Path,
                grantedLevel: AccessLevel.ReadWrite));
        }
    }

    private sealed class MockCommandRiskClassifier : ICommandRiskClassifier
    {
        public CommandRiskTier Classify(CommandExecutionRequest request)
        {
            return CommandRiskTier.Safe;
        }

        public IReadOnlyList<CommandRiskRule> GetRules()
        {
            return [];
        }
    }
}
