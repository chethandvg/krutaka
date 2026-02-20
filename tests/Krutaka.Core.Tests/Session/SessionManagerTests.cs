using FluentAssertions;
using Krutaka.Core;
using Krutaka.Tools;
using Microsoft.Extensions.DependencyInjection;

namespace Krutaka.Core.Tests;

/// <summary>
/// Tests for SessionManager implementation.
/// Validates lifecycle management, eviction, idle detection, and resource governance.
/// </summary>
public sealed class SessionManagerTests : IDisposable
{
    private readonly ServiceProvider _serviceProvider;
    private readonly string _testProjectPath;

    public SessionManagerTests()
    {
        // Use CI-safe test directory (avoids LocalAppData and reduces file lock issues)
        _testProjectPath = TestDirectoryHelper.GetTestDirectory("session-manager-test");
        Directory.CreateDirectory(_testProjectPath);

        var services = new ServiceCollection();

        // Register shared services
        services.AddSingleton<IClaudeClient, MockClaudeClient>();
        services.AddSingleton<IAuditLogger, MockAuditLogger>();

        services.AddAgentTools(options =>
        {
            options.DefaultWorkingDirectory = _testProjectPath;
            options.CeilingDirectory = _testProjectPath;
        });

        _serviceProvider = services.BuildServiceProvider();
    }

    public void Dispose()
    {
        _serviceProvider.Dispose();
        TestDirectoryHelper.TryDeleteDirectory(_testProjectPath);
    }

    private SessionManager CreateSessionManager(SessionManagerOptions? options = null)
    {
        var factory = _serviceProvider.GetRequiredService<ISessionFactory>();
        return new SessionManager(factory, options ?? new SessionManagerOptions(), logger: null);
    }

    #region Core Lifecycle Tests

    [Fact]
    public async Task CreateSessionAsync_Should_CreateAndStoreSession()
    {
        // Arrange
        await using var manager = CreateSessionManager();
        var request = new SessionRequest(_testProjectPath);

        // Act
        var session = await manager.CreateSessionAsync(request, CancellationToken.None);

        // Assert
        session.Should().NotBeNull();
        session.SessionId.Should().NotBe(Guid.Empty);
        session.State.Should().Be(SessionState.Active);
        session.ProjectPath.Should().Be(_testProjectPath);

        // Verify session is retrievable
        var retrieved = manager.GetSession(session.SessionId);
        retrieved.Should().BeSameAs(session);
    }

    [Fact]
    public async Task GetSession_Should_ReturnExistingSession()
    {
        // Arrange
        await using var manager = CreateSessionManager();
        var request = new SessionRequest(_testProjectPath);
        var session = await manager.CreateSessionAsync(request, CancellationToken.None);

        // Act
        var retrieved = manager.GetSession(session.SessionId);

        // Assert
        retrieved.Should().NotBeNull();
        retrieved.Should().BeSameAs(session);
    }

    [Fact]
    public async Task GetSession_Should_ReturnNull_WhenSessionDoesNotExist()
    {
        // Arrange
        await using var manager = CreateSessionManager();
        var nonExistentId = Guid.NewGuid();

        // Act
        var retrieved = manager.GetSession(nonExistentId);

        // Assert
        retrieved.Should().BeNull();
    }

    [Fact]
    public async Task TerminateSessionAsync_Should_DisposeSessionAndRemoveFromDictionaries()
    {
        // Arrange
        await using var manager = CreateSessionManager();
        var request = new SessionRequest(_testProjectPath, ExternalKey: "test-key", UserId: "user1");
        var session = await manager.CreateSessionAsync(request, CancellationToken.None);

        // Act
        await manager.TerminateSessionAsync(session.SessionId, CancellationToken.None);

        // Assert
        manager.GetSession(session.SessionId).Should().BeNull();
        session.State.Should().Be(SessionState.Terminated);
    }

    [Fact]
    public async Task TerminateSessionAsync_Should_RemoveExternalKeyMapping()
    {
        // Arrange
        await using var manager = CreateSessionManager();
        var externalKey = "chat-123";
        var request = new SessionRequest(_testProjectPath, ExternalKey: externalKey);
        var session = await manager.CreateSessionAsync(request, CancellationToken.None);

        // Act
        await manager.TerminateSessionAsync(session.SessionId, CancellationToken.None);

        // Create new session with same key — should create new session
        var newSession = await manager.GetOrCreateByKeyAsync(externalKey, request, CancellationToken.None);

        // Assert
        newSession.SessionId.Should().NotBe(session.SessionId);
    }

    [Fact]
    public async Task TerminateSessionAsync_Should_CleanupUserTracking()
    {
        // Arrange
        var options = new SessionManagerOptions(MaxSessionsPerUser: 2);
        await using var manager = CreateSessionManager(options);
        var userId = "user1";

        // Create and terminate one session
        var request1 = new SessionRequest(_testProjectPath, UserId: userId);
        var session1 = await manager.CreateSessionAsync(request1, CancellationToken.None);
        await manager.TerminateSessionAsync(session1.SessionId, CancellationToken.None);

        // Should be able to create 2 more sessions (total limit is 2)
        var request2 = new SessionRequest(_testProjectPath, UserId: userId);
        var session2 = await manager.CreateSessionAsync(request2, CancellationToken.None);

        var request3 = new SessionRequest(_testProjectPath, UserId: userId);
        var session3 = await manager.CreateSessionAsync(request3, CancellationToken.None);

        // Assert
        session2.Should().NotBeNull();
        session3.Should().NotBeNull();
    }

    [Fact]
    public async Task TerminateAllAsync_Should_DisposeAllSessionsAndClearEverything()
    {
        // Arrange
        await using var manager = CreateSessionManager();
        var session1 = await manager.CreateSessionAsync(new SessionRequest(_testProjectPath, ExternalKey: "key1"), CancellationToken.None);
        var session2 = await manager.CreateSessionAsync(new SessionRequest(_testProjectPath, ExternalKey: "key2"), CancellationToken.None);

        // Act
        await manager.TerminateAllAsync(CancellationToken.None);

        // Assert
        manager.GetSession(session1.SessionId).Should().BeNull();
        manager.GetSession(session2.SessionId).Should().BeNull();
        manager.ListActiveSessions().Should().BeEmpty();
    }

    [Fact]
    public async Task ListActiveSessions_Should_ReturnAllActiveAndSuspendedSessions()
    {
        // Arrange
        await using var manager = CreateSessionManager();
        var session1 = await manager.CreateSessionAsync(new SessionRequest(_testProjectPath, UserId: "user1"), CancellationToken.None);
        var session2 = await manager.CreateSessionAsync(new SessionRequest(_testProjectPath, UserId: "user2"), CancellationToken.None);

        // Act
        var summaries = manager.ListActiveSessions();

        // Assert
        summaries.Should().HaveCount(2);
        summaries.Should().Contain(s => s.SessionId == session1.SessionId);
        summaries.Should().Contain(s => s.SessionId == session2.SessionId);
    }

    [Fact]
    public async Task DisposeAsync_Should_CancelIdleDetectionTimerAndDisposeAll()
    {
        // Arrange
        var options = new SessionManagerOptions(IdleTimeout: TimeSpan.FromSeconds(1));
        var manager = CreateSessionManager(options);
        var session = await manager.CreateSessionAsync(new SessionRequest(_testProjectPath), CancellationToken.None);

        // Act
        await manager.DisposeAsync();

        // Assert - session should be terminated
        session.State.Should().Be(SessionState.Terminated);
    }

    #endregion

    #region External Key Mapping Tests

    [Fact]
    public async Task GetOrCreateByKeyAsync_Should_CreateNewSession_WhenKeyDoesNotExist()
    {
        // Arrange
        await using var manager = CreateSessionManager();
        var externalKey = "telegram-chat-123";
        var request = new SessionRequest(_testProjectPath, ExternalKey: externalKey);

        // Act
        var session = await manager.GetOrCreateByKeyAsync(externalKey, request, CancellationToken.None);

        // Assert
        session.Should().NotBeNull();
        session.ExternalKey.Should().Be(externalKey);
    }

    [Fact]
    public async Task GetOrCreateByKeyAsync_Should_ReturnExistingSession_ForSameKey()
    {
        // Arrange
        await using var manager = CreateSessionManager();
        var externalKey = "telegram-chat-456";
        var request = new SessionRequest(_testProjectPath, ExternalKey: externalKey);

        // Act
        var session1 = await manager.GetOrCreateByKeyAsync(externalKey, request, CancellationToken.None);
        var session2 = await manager.GetOrCreateByKeyAsync(externalKey, request, CancellationToken.None);

        // Assert
        session1.SessionId.Should().Be(session2.SessionId);
        session1.Should().BeSameAs(session2);
    }

    [Fact]
    public async Task GetOrCreateByKeyAsync_Should_CreateDifferentSessions_ForDifferentKeys()
    {
        // Arrange
        await using var manager = CreateSessionManager();
        var key1 = "chat-1";
        var key2 = "chat-2";
        var request1 = new SessionRequest(_testProjectPath, ExternalKey: key1);
        var request2 = new SessionRequest(_testProjectPath, ExternalKey: key2);

        // Act
        var session1 = await manager.GetOrCreateByKeyAsync(key1, request1, CancellationToken.None);
        var session2 = await manager.GetOrCreateByKeyAsync(key2, request2, CancellationToken.None);

        // Assert
        session1.SessionId.Should().NotBe(session2.SessionId);
    }

    [Fact]
    public async Task GetOrCreateByKeyAsync_Should_UpdateLastActivity_ForExistingSession()
    {
        // Arrange
        await using var manager = CreateSessionManager();
        var externalKey = "chat-789";
        var request = new SessionRequest(_testProjectPath, ExternalKey: externalKey);
        var session = await manager.GetOrCreateByKeyAsync(externalKey, request, CancellationToken.None);
        var originalLastActivity = session.LastActivity;

        // Wait a bit
        await Task.Delay(100);

        // Act
        var retrievedSession = await manager.GetOrCreateByKeyAsync(externalKey, request, CancellationToken.None);

        // Assert
        retrievedSession.LastActivity.Should().BeAfter(originalLastActivity);
    }

    [Fact]
    public async Task GetOrCreateByKeyAsync_Should_BeAtomic_UnderConcurrentCalls()
    {
        // Arrange
        await using var manager = CreateSessionManager();
        var externalKey = "concurrent-test-key";
        var request = new SessionRequest(_testProjectPath, ExternalKey: externalKey);

        // Act - Call GetOrCreateByKeyAsync 5 times concurrently
        var tasks = Enumerable.Range(0, 5)
            .Select(_ => manager.GetOrCreateByKeyAsync(externalKey, request, CancellationToken.None))
            .ToArray();

        var sessions = await Task.WhenAll(tasks);

        // Assert - All should return the same session
        var uniqueSessionIds = sessions.Select(s => s.SessionId).Distinct().ToList();
        uniqueSessionIds.Should().HaveCount(1);
    }

    #endregion

    #region Capacity & Eviction Tests

    [Fact]
    public async Task MaxActiveSessions_Should_ThrowWithRejectNew()
    {
        // Arrange
        var options = new SessionManagerOptions(MaxActiveSessions: 2, EvictionStrategy: EvictionStrategy.RejectNew);
        await using var manager = CreateSessionManager(options);

        // Create 2 sessions
        await manager.CreateSessionAsync(new SessionRequest(_testProjectPath), CancellationToken.None);
        await manager.CreateSessionAsync(new SessionRequest(_testProjectPath), CancellationToken.None);

        // Act & Assert - Third session should throw
        var act = async () => await manager.CreateSessionAsync(new SessionRequest(_testProjectPath), CancellationToken.None);
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*Maximum number of active sessions*reached*");
    }

    [Fact]
    public async Task MaxActiveSessions_Should_SuspendOldestIdle_WhenLimitReached()
    {
        // Arrange
        var options = new SessionManagerOptions(
            MaxActiveSessions: 2,
            IdleTimeout: TimeSpan.FromMilliseconds(100),
            EvictionStrategy: EvictionStrategy.SuspendOldestIdle);

        await using var manager = CreateSessionManager(options);

        // Create 2 sessions
        var session1 = await manager.CreateSessionAsync(new SessionRequest(_testProjectPath), CancellationToken.None);
        var session2 = await manager.CreateSessionAsync(new SessionRequest(_testProjectPath), CancellationToken.None);

        // Transition session1 to Idle
        session1.State = SessionState.Idle;

        // Act - Create third session (should suspend session1)
        var session3 = await manager.CreateSessionAsync(new SessionRequest(_testProjectPath), CancellationToken.None);

        // Assert
        session3.Should().NotBeNull();
        manager.GetSession(session1.SessionId).Should().BeNull(); // Suspended sessions not in active dictionary

        // Verify session1 was suspended (appears in ListActiveSessions with Suspended state)
        var summaries = manager.ListActiveSessions();
        summaries.Should().Contain(s => s.SessionId == session1.SessionId && s.State == SessionState.Suspended);
    }

    [Fact]
    public async Task MaxActiveSessions_Should_TerminateOldest_WhenLimitReached()
    {
        // Arrange
        var options = new SessionManagerOptions(
            MaxActiveSessions: 2,
            EvictionStrategy: EvictionStrategy.TerminateOldest);

        await using var manager = CreateSessionManager(options);

        // Create 2 sessions
        var session1 = await manager.CreateSessionAsync(new SessionRequest(_testProjectPath), CancellationToken.None);
        await Task.Delay(50); // Ensure session1 is older
        var session2 = await manager.CreateSessionAsync(new SessionRequest(_testProjectPath), CancellationToken.None);

        // Act - Create third session (should terminate session1)
        var session3 = await manager.CreateSessionAsync(new SessionRequest(_testProjectPath), CancellationToken.None);

        // Assert
        session1.State.Should().Be(SessionState.Terminated);
        session3.Should().NotBeNull();
        manager.GetSession(session1.SessionId).Should().BeNull();
    }

    [Fact]
    public async Task MaxSessionsPerUser_Should_Throw_WhenLimitReached()
    {
        // Arrange
        var options = new SessionManagerOptions(MaxSessionsPerUser: 2);
        await using var manager = CreateSessionManager(options);
        var userId = "user-limit-test";

        // Create 2 sessions for the user
        await manager.CreateSessionAsync(new SessionRequest(_testProjectPath, UserId: userId), CancellationToken.None);
        await manager.CreateSessionAsync(new SessionRequest(_testProjectPath, UserId: userId), CancellationToken.None);

        // Act & Assert - Third session should throw
        var act = async () => await manager.CreateSessionAsync(new SessionRequest(_testProjectPath, UserId: userId), CancellationToken.None);
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage($"*User '{userId}' has reached the maximum number of sessions*");
    }

    [Fact]
    public async Task UserSessionCleanup_Should_AllowNewSession_AfterTermination()
    {
        // Arrange
        var options = new SessionManagerOptions(MaxSessionsPerUser: 1);
        await using var manager = CreateSessionManager(options);
        var userId = "user-cleanup-test";

        // Create and terminate a session
        var request = new SessionRequest(_testProjectPath, UserId: userId);
        var session1 = await manager.CreateSessionAsync(request, CancellationToken.None);
        await manager.TerminateSessionAsync(session1.SessionId, CancellationToken.None);

        // Act - Should be able to create a new session
        var session2 = await manager.CreateSessionAsync(request, CancellationToken.None);

        // Assert
        session2.Should().NotBeNull();
        session2.SessionId.Should().NotBe(session1.SessionId);
    }

    #endregion

    #region Resume Tests

    [Fact]
    public async Task ResumeSessionAsync_Should_Throw_WhenSessionNotFound()
    {
        // Arrange
        await using var manager = CreateSessionManager();
        var nonExistentId = Guid.NewGuid();

        // Act & Assert
        var act = async () => await manager.ResumeSessionAsync(nonExistentId, _testProjectPath, CancellationToken.None);
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage($"*Session {nonExistentId} is not found in suspended sessions*");
    }

    [Fact]
    public async Task ResumeSessionAsync_Should_ValidateProjectPath()
    {
        // Arrange
        var options = new SessionManagerOptions(
            MaxActiveSessions: 1,
            IdleTimeout: TimeSpan.FromMilliseconds(50),
            EvictionStrategy: EvictionStrategy.SuspendOldestIdle);

        await using var manager = CreateSessionManager(options);

        // Create and suspend a session
        var session = await manager.CreateSessionAsync(new SessionRequest(_testProjectPath), CancellationToken.None);
        session.State = SessionState.Idle;

        // Force suspension by creating another session
        await manager.CreateSessionAsync(new SessionRequest(_testProjectPath), CancellationToken.None);

        // Act & Assert - Resume with wrong ProjectPath should fail
        var wrongPath = Path.Combine(Path.GetTempPath(), "wrong-path");
        var act = async () => await manager.ResumeSessionAsync(session.SessionId, wrongPath, CancellationToken.None);
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*ProjectPath mismatch*");
    }

    [Fact]
    public async Task ResumeSessionAsync_Should_ReturnActiveSession_IfAlreadyActive()
    {
        // Arrange
        await using var manager = CreateSessionManager();
        var session = await manager.CreateSessionAsync(new SessionRequest(_testProjectPath), CancellationToken.None);

        // Act - Resume an already-active session
        var resumed = await manager.ResumeSessionAsync(session.SessionId, _testProjectPath, CancellationToken.None);

        // Assert
        resumed.Should().BeSameAs(session);
        resumed.State.Should().Be(SessionState.Active);
    }

    #endregion

    #region Idle Detection & Suspension Tests

    [Fact]
    public async Task IdleDetection_Should_TransitionActiveToIdle_AfterTimeout()
    {
        // Arrange
        var options = new SessionManagerOptions(IdleTimeout: TimeSpan.FromMilliseconds(200));
        await using var manager = CreateSessionManager(options);

        var session = await manager.CreateSessionAsync(new SessionRequest(_testProjectPath), CancellationToken.None);

        // Verify initially active
        session.State.Should().Be(SessionState.Active);

        // Act - Wait for idle timeout + timer interval
        await Task.Delay(400);

        // Assert - Should transition to Idle
        session.State.Should().Be(SessionState.Idle);
    }

    [Fact]
    public async Task IdleDetection_Should_NotSuspendImmediately_AfterIdleTimeout()
    {
        // Arrange
        var options = new SessionManagerOptions(IdleTimeout: TimeSpan.FromMilliseconds(150));
        await using var manager = CreateSessionManager(options);

        var session = await manager.CreateSessionAsync(new SessionRequest(_testProjectPath), CancellationToken.None);

        // Act - Wait for idle timeout + a bit more
        await Task.Delay(250);

        // Assert - Should be Idle, not Suspended (grace period is 2× IdleTimeout = 300ms)
        session.State.Should().Be(SessionState.Idle);
        manager.GetSession(session.SessionId).Should().NotBeNull(); // Still in active sessions
    }

    [Fact]
    public async Task IdleDetection_Should_SuspendAfterGracePeriod()
    {
        // Arrange
        var options = new SessionManagerOptions(IdleTimeout: TimeSpan.FromMilliseconds(100));
        await using var manager = CreateSessionManager(options);

        var session = await manager.CreateSessionAsync(new SessionRequest(_testProjectPath), CancellationToken.None);
        var sessionId = session.SessionId;

        // Act - Wait for IdleTimeout + 2× IdleTimeout + timer intervals
        // The session needs to:
        // 1. Transition to Idle after 100ms
        // 2. Stay Idle for 200ms (2× IdleTimeout) before suspension
        // Total: ~300ms + timer processing time
        await Task.Delay(450);

        // Assert - Should be suspended
        manager.GetSession(sessionId).Should().BeNull(); // Removed from active sessions

        // Verify in suspended list
        var summaries = manager.ListActiveSessions();
        summaries.Should().Contain(s => s.SessionId == sessionId && s.State == SessionState.Suspended);
    }

    [Fact]
    public async Task SuspendedSessionTtl_Should_CleanupExpiredSessions()
    {
        // Arrange
        var options = new SessionManagerOptions(
            IdleTimeout: TimeSpan.FromMilliseconds(50),
            SuspendedTtl: TimeSpan.FromMilliseconds(200));

        await using var manager = CreateSessionManager(options);

        var session = await manager.CreateSessionAsync(new SessionRequest(_testProjectPath), CancellationToken.None);
        var sessionId = session.SessionId;

        // Wait for session to be suspended (2× IdleTimeout + timer)
        await Task.Delay(200);

        // Verify suspended
        manager.GetSession(sessionId).Should().BeNull();
        manager.ListActiveSessions().Should().Contain(s => s.SessionId == sessionId && s.State == SessionState.Suspended);

        // Act - Wait for SuspendedTtl to expire
        await Task.Delay(300);

        // Assert - Should be completely removed
        var summaries = manager.ListActiveSessions();
        summaries.Should().NotContain(s => s.SessionId == sessionId);
    }

    [Fact]
    public async Task GetOrCreateByKeyAsync_Should_AutoResumeSuspendedSession()
    {
        // Arrange
        var options = new SessionManagerOptions(
            MaxActiveSessions: 1,
            IdleTimeout: TimeSpan.FromMilliseconds(50),
            EvictionStrategy: EvictionStrategy.SuspendOldestIdle);

        await using var manager = CreateSessionManager(options);

        var externalKey = "telegram-auto-resume";
        var request = new SessionRequest(_testProjectPath, ExternalKey: externalKey);

        // Create first session
        var session1 = await manager.GetOrCreateByKeyAsync(externalKey, request, CancellationToken.None);
        var session1Id = session1.SessionId;

        // Make session1 idle and create session2 to force suspension of session1
        session1.State = SessionState.Idle;
        var session2 = await manager.CreateSessionAsync(new SessionRequest(_testProjectPath), CancellationToken.None);

        // Verify session1 is suspended
        manager.GetSession(session1Id).Should().BeNull();

        // Act - GetOrCreateByKeyAsync should auto-resume session1
        var resumedSession = await manager.GetOrCreateByKeyAsync(externalKey, request, CancellationToken.None);

        // Assert - Should be the same session ID (resumed, not new)
        resumedSession.SessionId.Should().Be(session1Id);
        resumedSession.State.Should().Be(SessionState.Active);
    }

    #endregion

    #region Token Budget Tests

    [Fact]
    public async Task RecordTokenUsage_Should_TrackGlobalTokens()
    {
        // Arrange
        await using var manager = CreateSessionManager();

        // Act
        manager.RecordTokenUsage(1000);
        manager.RecordTokenUsage(2000);

        // Assert - No exception should be thrown for now
        // (Global budget is 1,000,000 by default)
    }

    [Fact]
    public async Task GlobalTokenBudget_Should_ThrowOnCreateSession_WhenExhausted()
    {
        // Arrange
        var options = new SessionManagerOptions(GlobalMaxTokensPerHour: 10_000);
        await using var manager = CreateSessionManager(options);

        // Record tokens close to the limit
        manager.RecordTokenUsage(8_000);

        // Act & Assert - Creating a session with 200,000 token budget should fail
        var request = new SessionRequest(_testProjectPath, MaxTokenBudget: 200_000);
        var act = async () => await manager.CreateSessionAsync(request, CancellationToken.None);
        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*Global hourly token budget exhausted*");
    }

    [Fact]
    public async Task RecordTokenUsage_Should_ThrowArgumentOutOfRangeException_WhenNegative()
    {
        // Arrange
        await using var manager = CreateSessionManager();

        // Act & Assert
        var act = () => manager.RecordTokenUsage(-100);
        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    #endregion

    #region Concurrency Tests

    [Fact]
    public async Task ConcurrentSessionCreation_Should_NotThrow_OrCreateDuplicates()
    {
        // Arrange
        await using var manager = CreateSessionManager();

        // Act - Create 10 sessions concurrently
        var tasks = Enumerable.Range(0, 10)
            .Select(i => manager.CreateSessionAsync(
                new SessionRequest(_testProjectPath, ExternalKey: $"key-{i}"),
                CancellationToken.None))
            .ToArray();

        var sessions = await Task.WhenAll(tasks);

        // Assert - All sessions should be unique
        sessions.Should().HaveCount(10);
        sessions.Select(s => s.SessionId).Distinct().Should().HaveCount(10);
    }

    #endregion

    #region Regression Tests for Review Comments

    [Fact]
    public async Task GetOrCreateByKeyAsync_Should_ThrowWhenExternalKeyMismatch()
    {
        // Arrange
        await using var manager = CreateSessionManager();
        var externalKey = "telegram-123";
        var wrongRequest = new SessionRequest(_testProjectPath, ExternalKey: "different-key");

        // Act & Assert
        var act = async () => await manager.GetOrCreateByKeyAsync(externalKey, wrongRequest, CancellationToken.None);
        await act.Should().ThrowAsync<ArgumentException>()
            .WithMessage("*does not match the provided externalKey*");
    }

    [Fact]
    public async Task GetOrCreateByKeyAsync_Should_CreateRequestWithExternalKey_WhenRequestKeyIsNull()
    {
        // Arrange
        await using var manager = CreateSessionManager();
        var externalKey = "telegram-456";
        var requestWithoutKey = new SessionRequest(_testProjectPath, ExternalKey: null);

        // Act
        var session = await manager.GetOrCreateByKeyAsync(externalKey, requestWithoutKey, CancellationToken.None);

        // Assert
        session.ExternalKey.Should().Be(externalKey);
    }

    [Fact]
    public async Task CreateSessionAsync_Should_ThrowWhenMaxTokenBudgetIsNegative()
    {
        // Arrange
        await using var manager = CreateSessionManager();
        var request = new SessionRequest(_testProjectPath, MaxTokenBudget: -1000);

        // Act & Assert
        var act = async () => await manager.CreateSessionAsync(request, CancellationToken.None);
        await act.Should().ThrowAsync<ArgumentOutOfRangeException>();
    }

    [Fact]
    public async Task ResumeSessionAsync_Should_ApplyEvictionWhenMaxActiveReached()
    {
        // Arrange
        var options = new SessionManagerOptions(
            MaxActiveSessions: 1,
            EvictionStrategy: EvictionStrategy.SuspendOldestIdle);

        await using var manager = CreateSessionManager(options);

        // Create and suspend session1
        var session1 = await manager.CreateSessionAsync(new SessionRequest(_testProjectPath), CancellationToken.None);
        var session1Id = session1.SessionId;
        session1.State = SessionState.Idle;

        // Create session2 (evicts session1)
        var session2 = await manager.CreateSessionAsync(new SessionRequest(_testProjectPath), CancellationToken.None);

        // Verify session1 is suspended
        manager.GetSession(session1Id).Should().BeNull();

        // Act - Resume session1 should evict session2
        var resumedSession = await manager.ResumeSessionAsync(session1Id, _testProjectPath, CancellationToken.None);

        // Assert
        resumedSession.SessionId.Should().Be(session1Id);
        manager.GetSession(session2.SessionId).Should().BeNull(); // session2 should be suspended
    }

    [Fact]
    public async Task IdleDetection_Should_NotSuspendImmediately_AfterTransitionToIdle()
    {
        // Arrange
        var options = new SessionManagerOptions(IdleTimeout: TimeSpan.FromMilliseconds(100));
        await using var manager = CreateSessionManager(options);

        var session = await manager.CreateSessionAsync(new SessionRequest(_testProjectPath), CancellationToken.None);

        // Wait for Active → Idle transition
        await Task.Delay(200);

        // Assert - Should be Idle but NOT suspended yet
        session.State.Should().Be(SessionState.Idle);
        manager.GetSession(session.SessionId).Should().NotBeNull();

        // Wait for grace period (2× IdleTimeout)
        await Task.Delay(250);

        // Assert - Now should be suspended
        manager.GetSession(session.SessionId).Should().BeNull();
    }

    [Fact]
    public async Task ConcurrentResumeSessionAsync_Should_ReturnSameSession()
    {
        // Arrange
        var options = new SessionManagerOptions(
            MaxActiveSessions: 1,
            EvictionStrategy: EvictionStrategy.SuspendOldestIdle);

        await using var manager = CreateSessionManager(options);

        // Create and suspend session1
        var session1 = await manager.CreateSessionAsync(new SessionRequest(_testProjectPath), CancellationToken.None);
        var session1Id = session1.SessionId;
        session1.State = SessionState.Idle;

        // Create session2 (evicts session1)
        await manager.CreateSessionAsync(new SessionRequest(_testProjectPath), CancellationToken.None);

        // Act - Resume session1 concurrently from 3 threads
        var tasks = Enumerable.Range(0, 3)
            .Select(_ => manager.ResumeSessionAsync(session1Id, _testProjectPath, CancellationToken.None))
            .ToArray();

        var resumedSessions = await Task.WhenAll(tasks);

        // Assert - All should return the same session instance
        resumedSessions.Should().HaveCount(3);
        resumedSessions.All(s => s.SessionId == session1Id).Should().BeTrue();
    }

    [Fact]
    public async Task RemoveSessionFromUserTracking_Should_HandleConcurrentUpdates()
    {
        // Arrange
        var options = new SessionManagerOptions(MaxSessionsPerUser: 5);
        await using var manager = CreateSessionManager(options);
        var userId = "concurrent-user";

        // Create 3 sessions for the user
        var session1 = await manager.CreateSessionAsync(new SessionRequest(_testProjectPath, UserId: userId), CancellationToken.None);
        var session2 = await manager.CreateSessionAsync(new SessionRequest(_testProjectPath, UserId: userId), CancellationToken.None);
        var session3 = await manager.CreateSessionAsync(new SessionRequest(_testProjectPath, UserId: userId), CancellationToken.None);

        // Act - Terminate sessions concurrently while creating a new one
        var terminateTasks = new[]
        {
            manager.TerminateSessionAsync(session1.SessionId, CancellationToken.None),
            manager.TerminateSessionAsync(session2.SessionId, CancellationToken.None),
            manager.CreateSessionAsync(new SessionRequest(_testProjectPath, UserId: userId), CancellationToken.None)
        };

        await Task.WhenAll(terminateTasks);

        // Assert - Should be able to create another session (verifies user tracking is correct)
        var newSession = await manager.CreateSessionAsync(new SessionRequest(_testProjectPath, UserId: userId), CancellationToken.None);
        newSession.Should().NotBeNull();
    }

    #endregion

    #region Mock Implementations

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1812:Avoid uninstantiated internal classes", Justification = "MockClaudeClient is instantiated via DI container")]
    private sealed class MockClaudeClient : IClaudeClient
    {
        public IAsyncEnumerable<AgentEvent> SendMessageAsync(
            IEnumerable<object> messages,
            string systemPrompt,
            object? tools,
            CancellationToken cancellationToken)
        {
            return AsyncEnumerable.Empty<AgentEvent>();
        }

        public Task<int> CountTokensAsync(
            IEnumerable<object> messages,
            string systemPrompt,
            CancellationToken cancellationToken)
        {
            return Task.FromResult(100);
        }
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1812:Avoid uninstantiated internal classes", Justification = "MockAuditLogger is instantiated via DI container")]
    private sealed class MockAuditLogger : IAuditLogger
    {
        public void Log(AuditEvent auditEvent)
        {
        }

        public void LogUserInput(CorrelationContext correlationContext, string content)
        {
        }

        public void LogClaudeApiRequest(CorrelationContext correlationContext, string model, int tokenCount, int toolCount)
        {
        }

        public void LogClaudeApiResponse(CorrelationContext correlationContext, string stopReason, int inputTokens, int outputTokens)
        {
        }

        public void LogToolExecution(
            CorrelationContext correlationContext,
            string toolName,
            bool approved,
            bool alwaysApprove,
            long durationMs,
            int resultLength,
            string? errorMessage = null)
        {
        }

        public void LogCompaction(CorrelationContext correlationContext, int beforeTokenCount, int afterTokenCount, int messagesRemoved)
        {
        }

        public void LogSecurityViolation(CorrelationContext correlationContext, string violationType, string blockedValue, string context)
        {
        }

        public void LogCommandClassification(
            CorrelationContext correlationContext,
            string executable,
            string arguments,
            CommandRiskTier tier,
            bool autoApproved,
            string? trustedDirectory,
            string reason)
        {
        }
    }

    #endregion
}
