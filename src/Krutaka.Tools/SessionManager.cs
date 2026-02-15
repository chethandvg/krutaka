using System.Collections.Concurrent;
using Krutaka.Core;
using Microsoft.Extensions.Logging;

namespace Krutaka.Tools;

/// <summary>
/// Manages the lifecycle of multiple concurrent sessions with idle detection, suspension, and resource governance.
/// Thread-safe implementation using ConcurrentDictionary for session storage and external key mapping.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1848:Use the LoggerMessage delegates", Justification = "LoggerMessage delegates add complexity for marginal performance gain in this manager class.")]
public sealed class SessionManager : ISessionManager
{
    private readonly ISessionFactory _sessionFactory;
    private readonly SessionManagerOptions _options;
    private readonly ILogger? _logger;

    // Active sessions (Active or Idle state)
    private readonly ConcurrentDictionary<Guid, ManagedSession> _sessions = new();

    // External key to session ID mapping (for Telegram chatId → session)
    private readonly ConcurrentDictionary<string, Guid> _externalKeyMap = new();

    // Suspended sessions (orchestrator disposed, JSONL on disk)
    private readonly ConcurrentDictionary<Guid, SuspendedSessionInfo> _suspendedSessions = new();

    // UserId to session IDs mapping for per-user limits (using ConcurrentBag for thread safety)
    private readonly ConcurrentDictionary<string, ConcurrentBag<Guid>> _userSessions = new();

    // Session ID to UserId mapping for cleanup
    private readonly ConcurrentDictionary<Guid, string> _sessionToUser = new();

    // Lock for compound operations during session creation
    private readonly SemaphoreSlim _creationLock = new(1, 1);

    // Per-key locks for GetOrCreateByKeyAsync to prevent race conditions
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _keyLocks = new();

    // Global token budget tracking per hour
    private readonly object _tokenBudgetLock = new();
    private int _globalTokensThisHour;
    private DateTimeOffset _currentHourStart = DateTimeOffset.UtcNow;

    // Idle detection timer
    private readonly PeriodicTimer? _idleTimer;
    private readonly CancellationTokenSource _timerCts = new();
    private readonly Task? _idleDetectionTask;

    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="SessionManager"/> class.
    /// </summary>
    /// <param name="sessionFactory">Factory for creating session instances.</param>
    /// <param name="options">Configuration options for session management.</param>
    /// <param name="logger">Optional logger for tracking session lifecycle events.</param>
    public SessionManager(
        ISessionFactory sessionFactory,
        SessionManagerOptions options,
        ILogger<SessionManager>? logger = null)
    {
        _sessionFactory = sessionFactory ?? throw new ArgumentNullException(nameof(sessionFactory));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _logger = logger;

        // Start idle detection timer if IdleTimeout is configured
        if (_options.IdleTimeoutValue > TimeSpan.Zero)
        {
            _idleTimer = new PeriodicTimer(_options.IdleTimeoutValue);
            _idleDetectionTask = RunIdleDetectionAsync();
        }
    }

    /// <inheritdoc/>
    public async Task<ManagedSession> CreateSessionAsync(SessionRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        // Use lock to prevent race conditions in validation and creation
        await _creationLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Check global token budget
            if (IsGlobalTokenBudgetExhausted())
            {
                throw new InvalidOperationException(
                    $"Global token budget exhausted ({_options.GlobalMaxTokensPerHour} tokens per hour). " +
                    "Please wait or contact the administrator.");
            }

            // Validate per-user session limits
            if (request.UserId is not null)
            {
                var userSessionCount = CountSessionsForUser(request.UserId);
                if (userSessionCount >= _options.MaxSessionsPerUser)
                {
                    throw new InvalidOperationException(
                        $"User '{request.UserId}' has reached the maximum session limit ({_options.MaxSessionsPerUser}). " +
                        "Please terminate an existing session before creating a new one.");
                }
            }

            // Check MaxActiveSessions and apply eviction if needed
            while (_sessions.Count >= _options.MaxActiveSessions)
            {
                if (_options.EvictionStrategy == EvictionStrategy.RejectNew)
                {
                    throw new InvalidOperationException(
                        $"Maximum active sessions reached ({_options.MaxActiveSessions}). " +
                        "Cannot create new session.");
                }

                await ApplyEvictionAsync(cancellationToken).ConfigureAwait(false);
            }

            // Create the session via factory
            var session = _sessionFactory.Create(request);

            // Store in active sessions dictionary
            if (!_sessions.TryAdd(session.SessionId, session))
            {
                // This should never happen due to GUID uniqueness, but handle it defensively
                await session.DisposeAsync().ConfigureAwait(false);
                throw new InvalidOperationException($"Session with ID {session.SessionId} already exists.");
            }

            // Map external key if provided
            if (request.ExternalKey is not null)
            {
                _externalKeyMap[request.ExternalKey] = session.SessionId;
            }

            // Track user sessions if UserId is provided
            if (request.UserId is not null)
            {
                _sessionToUser[session.SessionId] = request.UserId;
                var bag = _userSessions.GetOrAdd(request.UserId, _ => new ConcurrentBag<Guid>());
                bag.Add(session.SessionId);
            }

            _logger?.LogInformation(
                "Session {SessionId} created for project '{ProjectPath}'",
                session.SessionId,
                session.ProjectPath);

            return session;
        }
        finally
        {
            _creationLock.Release();
        }
    }

    /// <inheritdoc/>
    public ManagedSession? GetSession(Guid sessionId)
    {
        return _sessions.TryGetValue(sessionId, out var session) ? session : null;
    }

    /// <inheritdoc/>
    public async Task<ManagedSession> GetOrCreateByKeyAsync(
        string externalKey,
        SessionRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(externalKey);
        ArgumentNullException.ThrowIfNull(request);

        // Get or create a lock for this specific external key to serialize operations
        var keyLock = _keyLocks.GetOrAdd(externalKey, _ => new SemaphoreSlim(1, 1));

        await keyLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Try to get existing active session by external key
            if (_externalKeyMap.TryGetValue(externalKey, out var existingSessionId))
            {
                if (_sessions.TryGetValue(existingSessionId, out var existingSession))
                {
                    // Update last activity and return existing session
                    existingSession.UpdateLastActivity();
                    return existingSession;
                }

                // Check if session is suspended - if so, resume it
                if (_suspendedSessions.TryGetValue(existingSessionId, out var suspendedInfo))
                {
                    // Resume the suspended session
                    return await ResumeSessionAsync(existingSessionId, suspendedInfo.ProjectPath, cancellationToken).ConfigureAwait(false);
                }

                // Session ID found but session doesn't exist in active or suspended — clean up stale mapping
                _externalKeyMap.TryRemove(externalKey, out _);
            }

            // Create new session with external key
            var newRequest = request with { ExternalKey = externalKey };
            return await CreateSessionAsync(newRequest, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            keyLock.Release();
        }
    }

    /// <inheritdoc/>
    public async Task<ManagedSession> ResumeSessionAsync(
        Guid sessionId,
        string projectPath,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(projectPath);

        // Check if session is already active
        if (_sessions.TryGetValue(sessionId, out var activeSession))
        {
            activeSession.UpdateLastActivity();
            return activeSession;
        }

        // Check if session is suspended
        if (!_suspendedSessions.TryGetValue(sessionId, out var suspendedInfo))
        {
            throw new InvalidOperationException(
                $"Session {sessionId} not found in active or suspended sessions. " +
                "Cannot resume.");
        }

        // Re-validate ProjectPath exists BEFORE removing suspended entry
        if (!Directory.Exists(projectPath))
        {
            throw new InvalidOperationException(
                $"Cannot resume session {sessionId}: project directory '{projectPath}' does not exist.");
        }

        // Create new session request from suspended info
        var request = new SessionRequest(
            ProjectPath: projectPath,
            ExternalKey: suspendedInfo.ExternalKey,
            UserId: suspendedInfo.UserId,
            MaxTokenBudget: suspendedInfo.MaxTokenBudget,
            MaxToolCallBudget: suspendedInfo.MaxToolCallBudget);

        ManagedSession newSession;
        try
        {
            // Create new session instance via factory
            newSession = await CreateSessionAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            // If creation fails, keep the suspended entry intact for retry
            throw;
        }

        // Only remove from suspended sessions after successful creation
        _suspendedSessions.TryRemove(sessionId, out _);

        // History reconstruction must be done by the caller (composition root)
        // since SessionManager cannot reference Krutaka.Memory
        // The caller should use SessionStore.ReconstructMessagesAsync() and
        // orchestrator.RestoreConversationHistory() after getting the resumed session

        _logger?.LogInformation(
            "Session {SessionId} resumed (history reconstruction must be done by caller)",
            sessionId);

        return newSession;
    }

    /// <inheritdoc/>
    public async Task TerminateSessionAsync(Guid sessionId, CancellationToken cancellationToken)
    {
        // Remove from active sessions
        if (_sessions.TryRemove(sessionId, out var session))
        {
            // Remove external key mapping if present
            if (session.ExternalKey is not null)
            {
                _externalKeyMap.TryRemove(session.ExternalKey, out _);
            }

            // Remove from user tracking if present
            if (_sessionToUser.TryRemove(sessionId, out var userId))
            {
                RemoveSessionFromUserTracking(sessionId, userId);
            }

            await session.DisposeAsync().ConfigureAwait(false);

            _logger?.LogInformation(
                "Session {SessionId} terminated and resources released",
                sessionId);

            return;
        }

        // Remove from suspended sessions if present
        if (_suspendedSessions.TryRemove(sessionId, out var suspendedInfo))
        {
            if (suspendedInfo.ExternalKey is not null)
            {
                _externalKeyMap.TryRemove(suspendedInfo.ExternalKey, out _);
            }

            // Remove from user tracking if present
            if (suspendedInfo.UserId is not null)
            {
                _sessionToUser.TryRemove(sessionId, out _);
                RemoveSessionFromUserTracking(sessionId, suspendedInfo.UserId);
            }

            _logger?.LogInformation(
                "Suspended session {SessionId} terminated",
                sessionId);
        }
    }

    /// <inheritdoc/>
    public IReadOnlyList<SessionSummary> ListActiveSessions()
    {
        var summaries = new List<SessionSummary>();

        // Add active sessions
        foreach (var kvp in _sessions)
        {
            var session = kvp.Value;
            summaries.Add(new SessionSummary(
                SessionId: session.SessionId,
                State: session.State,
                ProjectPath: session.ProjectPath,
                ExternalKey: session.ExternalKey,
                UserId: null, // UserId not tracked on ManagedSession
                CreatedAt: session.CreatedAt,
                LastActivity: session.LastActivity,
                TokensUsed: session.Budget.TokensUsed,
                TurnsUsed: session.Budget.TurnsUsed));
        }

        // Add suspended sessions
        foreach (var kvp in _suspendedSessions)
        {
            var info = kvp.Value;
            summaries.Add(new SessionSummary(
                SessionId: kvp.Key,
                State: SessionState.Suspended,
                ProjectPath: info.ProjectPath,
                ExternalKey: info.ExternalKey,
                UserId: info.UserId,
                CreatedAt: info.CreatedAt,
                LastActivity: info.SuspendedAt,
                TokensUsed: info.TokensUsed,
                TurnsUsed: info.TurnsUsed));
        }

        return summaries;
    }

    /// <inheritdoc/>
    public async Task TerminateAllAsync(CancellationToken cancellationToken)
    {
        // Dispose all active sessions
        var disposeTasks = new List<Task>();
        foreach (var kvp in _sessions)
        {
            disposeTasks.Add(kvp.Value.DisposeAsync().AsTask());
        }

        await Task.WhenAll(disposeTasks).ConfigureAwait(false);

        // Clear all dictionaries
        _sessions.Clear();
        _externalKeyMap.Clear();
        _suspendedSessions.Clear();
        _userSessions.Clear();
        _sessionToUser.Clear();

        _logger?.LogInformation("All sessions terminated");
    }

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        // Cancel idle detection timer
        await _timerCts.CancelAsync().ConfigureAwait(false);
        _idleTimer?.Dispose();

        if (_idleDetectionTask is not null)
        {
            try
            {
                await _idleDetectionTask.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Expected when timer is cancelled
            }
        }

        // Terminate all sessions
        await TerminateAllAsync(CancellationToken.None).ConfigureAwait(false);

        _timerCts.Dispose();
        _creationLock.Dispose();

        // Dispose all per-key locks
        foreach (var keyLock in _keyLocks.Values)
        {
            keyLock.Dispose();
        }

        _keyLocks.Clear();

        _disposed = true;
    }

    /// <summary>
    /// Background task that runs on a periodic timer to detect idle sessions and suspend them.
    /// </summary>
    private async Task RunIdleDetectionAsync()
    {
        if (_idleTimer is null)
        {
            return;
        }

        try
        {
            while (await _idleTimer.WaitForNextTickAsync(_timerCts.Token).ConfigureAwait(false))
            {
                await CheckAndSuspendIdleSessionsAsync().ConfigureAwait(false);
                await RemoveExpiredSuspendedSessionsAsync().ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // Timer was cancelled during shutdown
        }
    }

    /// <summary>
    /// Checks all active sessions for idle timeout and suspends them if needed.
    /// Sessions transition to Idle state after IdleTimeout, then remain idle for one more
    /// timer period before suspension to provide a grace period.
    /// </summary>
    private async Task CheckAndSuspendIdleSessionsAsync()
    {
        var now = DateTimeOffset.UtcNow;
        var suspensionTasks = new List<Task>();

        foreach (var kvp in _sessions)
        {
            var session = kvp.Value;
            var idleDuration = now - session.LastActivity;

            // First check: transition Active → Idle after IdleTimeout
            if (session.State == SessionState.Active && idleDuration >= _options.IdleTimeoutValue)
            {
                session.TransitionToIdle();
                _logger?.LogDebug(
                    "Session {SessionId} transitioned to Idle state",
                    session.SessionId);
            }
            // Second check: suspend Idle sessions that have been idle for 2x IdleTimeout
            // This provides a grace period before suspension
            else if (session.State == SessionState.Idle && idleDuration >= (_options.IdleTimeoutValue * 2))
            {
                suspensionTasks.Add(SuspendSessionAsync(session));
            }
        }

        await Task.WhenAll(suspensionTasks).ConfigureAwait(false);
    }

    /// <summary>
    /// Suspends a session by disposing the orchestrator and moving it to suspended tracking.
    /// </summary>
    private async Task SuspendSessionAsync(ManagedSession session)
    {
        // Get UserId from tracking before removing session
        _sessionToUser.TryGetValue(session.SessionId, out var userId);

        // Create suspended session info before disposing
        var suspendedInfo = new SuspendedSessionInfo(
            ProjectPath: session.ProjectPath,
            ExternalKey: session.ExternalKey,
            UserId: userId,
            CreatedAt: session.CreatedAt,
            SuspendedAt: DateTimeOffset.UtcNow,
            TokensUsed: session.Budget.TokensUsed,
            TurnsUsed: session.Budget.TurnsUsed,
            MaxTokenBudget: session.Budget.MaxTokens,
            MaxToolCallBudget: session.Budget.MaxToolCalls);

        // Remove from active sessions
        if (_sessions.TryRemove(session.SessionId, out _))
        {
            // Add to suspended sessions
            _suspendedSessions.TryAdd(session.SessionId, suspendedInfo);

            // Remove from user active tracking but keep in _sessionToUser for later cleanup
            // Note: We keep the session counted against the user's limit even when suspended
            // This prevents users from creating unlimited sessions by letting them suspend

            // Dispose the orchestrator (free memory, keep JSONL on disk)
            await session.DisposeAsync().ConfigureAwait(false);

            _logger?.LogInformation(
                "Session {SessionId} suspended due to idle timeout",
                session.SessionId);
        }
    }

    /// <summary>
    /// Removes suspended sessions that have exceeded their TTL.
    /// </summary>
    private async Task RemoveExpiredSuspendedSessionsAsync()
    {
        var now = DateTimeOffset.UtcNow;
        var toRemove = new List<Guid>();

        foreach (var kvp in _suspendedSessions)
        {
            var suspendedDuration = now - kvp.Value.SuspendedAt;
            if (suspendedDuration >= _options.SuspendedTtlValue)
            {
                toRemove.Add(kvp.Key);
            }
        }

        foreach (var sessionId in toRemove)
        {
            await TerminateSessionAsync(sessionId, CancellationToken.None).ConfigureAwait(false);

            _logger?.LogInformation(
                "Suspended session {SessionId} expired and removed",
                sessionId);
        }
    }

    /// <summary>
    /// Applies the configured eviction strategy to make room for new sessions.
    /// </summary>
    private async Task ApplyEvictionAsync(CancellationToken cancellationToken)
    {
        ManagedSession? victimSession = null;

        switch (_options.EvictionStrategy)
        {
            case EvictionStrategy.SuspendOldestIdle:
                victimSession = FindOldestIdleSession();
                if (victimSession is not null)
                {
                    await SuspendSessionAsync(victimSession).ConfigureAwait(false);
                }

                break;

            case EvictionStrategy.TerminateOldest:
                victimSession = FindOldestSession();
                if (victimSession is not null)
                {
                    await TerminateSessionAsync(victimSession.SessionId, cancellationToken).ConfigureAwait(false);
                }

                break;

            case EvictionStrategy.RejectNew:
                // Already handled in CreateSessionAsync
                break;
        }
    }

    /// <summary>
    /// Finds the session with the oldest LastActivity timestamp for eviction.
    /// </summary>
    private ManagedSession? FindOldestIdleSession()
    {
        ManagedSession? oldest = null;
        DateTimeOffset oldestActivity = DateTimeOffset.MaxValue;

        foreach (var session in _sessions.Values)
        {
            if (session.State == SessionState.Idle && session.LastActivity < oldestActivity)
            {
                oldest = session;
                oldestActivity = session.LastActivity;
            }
        }

        // If no idle session found, fall back to oldest active session
        if (oldest is null)
        {
            oldest = FindOldestSession();
        }

        return oldest;
    }

    /// <summary>
    /// Finds the session with the oldest LastActivity timestamp regardless of state.
    /// </summary>
    private ManagedSession? FindOldestSession()
    {
        ManagedSession? oldest = null;
        DateTimeOffset oldestActivity = DateTimeOffset.MaxValue;

        foreach (var session in _sessions.Values)
        {
            if (session.LastActivity < oldestActivity)
            {
                oldest = session;
                oldestActivity = session.LastActivity;
            }
        }

        return oldest;
    }

    /// <summary>
    /// Counts the number of active and suspended sessions for a given user.
    /// </summary>
    private int CountSessionsForUser(string userId)
    {
        // Count all sessions in _sessionToUser mapping (includes both active and suspended)
        // This ensures suspended sessions still count against the user's limit
        return _sessionToUser.Count(kvp => kvp.Value == userId);
    }

    /// <summary>
    /// Removes a session from user tracking.
    /// Thread-safe operation that handles ConcurrentBag cleanup.
    /// </summary>
    private void RemoveSessionFromUserTracking(Guid sessionId, string userId)
    {
        if (_userSessions.TryGetValue(userId, out var sessionBag))
        {
            // ConcurrentBag doesn't support Remove, so we rebuild without the target session
            var remainingSessions = sessionBag.Where(id => id != sessionId).ToList();

            if (remainingSessions.Count == 0)
            {
                // Remove the user entry entirely if no sessions remain
                _userSessions.TryRemove(userId, out _);
            }
            else if (remainingSessions.Count != sessionBag.Count)
            {
                // Rebuild the bag with remaining sessions
                _userSessions.TryUpdate(userId, new ConcurrentBag<Guid>(remainingSessions), sessionBag);
            }
        }
    }

    /// <summary>
    /// Checks if the global token budget for the current hour is exhausted.
    /// Resets the budget at the start of each hour.
    /// </summary>
    private bool IsGlobalTokenBudgetExhausted()
    {
        lock (_tokenBudgetLock)
        {
            var now = DateTimeOffset.UtcNow;

            // Reset budget if we're in a new hour
            if (now - _currentHourStart >= TimeSpan.FromHours(1))
            {
                _globalTokensThisHour = 0;
                _currentHourStart = now;
            }

            return _globalTokensThisHour >= _options.GlobalMaxTokensPerHour;
        }
    }

    /// <inheritdoc/>
    public void RecordTokenUsage(int tokens)
    {
        lock (_tokenBudgetLock)
        {
            _globalTokensThisHour += tokens;
        }
    }

    /// <summary>
    /// Information about a suspended session stored on disk.
    /// </summary>
    private sealed record SuspendedSessionInfo(
        string ProjectPath,
        string? ExternalKey,
        string? UserId,
        DateTimeOffset CreatedAt,
        DateTimeOffset SuspendedAt,
        int TokensUsed,
        int TurnsUsed,
        int MaxTokenBudget,
        int MaxToolCallBudget);
}
