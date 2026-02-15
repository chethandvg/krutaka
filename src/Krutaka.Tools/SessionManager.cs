using System.Collections.Concurrent;
using Krutaka.Core;
using Krutaka.Memory;
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

    // UserId to session IDs mapping for per-user limits
    private readonly ConcurrentDictionary<string, HashSet<Guid>> _userSessions = new();

    // Session ID to UserId mapping for cleanup
    private readonly ConcurrentDictionary<Guid, string> _sessionToUser = new();

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
            _userSessions.AddOrUpdate(
                request.UserId,
                _ => [session.SessionId],
                (_, sessionIds) =>
                {
                    sessionIds.Add(session.SessionId);
                    return sessionIds;
                });
        }

        _logger?.LogInformation(
            "Session {SessionId} created for project '{ProjectPath}'",
            session.SessionId,
            session.ProjectPath);

        return session;
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

        // Try to get existing session by external key
        if (_externalKeyMap.TryGetValue(externalKey, out var existingSessionId))
        {
            if (_sessions.TryGetValue(existingSessionId, out var existingSession))
            {
                // Update last activity and return existing session
                existingSession.UpdateLastActivity();
                return existingSession;
            }

            // Session ID found but session doesn't exist — clean up stale mapping
            _externalKeyMap.TryRemove(externalKey, out _);
        }

        // Create new session with external key
        var newRequest = request with { ExternalKey = externalKey };
        return await CreateSessionAsync(newRequest, cancellationToken).ConfigureAwait(false);
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
        if (!_suspendedSessions.TryRemove(sessionId, out var suspendedInfo))
        {
            throw new InvalidOperationException(
                $"Session {sessionId} not found in active or suspended sessions. " +
                "Cannot resume.");
        }

        // Re-validate ProjectPath exists
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

        // Create new session instance via factory
        var newSession = await CreateSessionAsync(request, cancellationToken).ConfigureAwait(false);

        // Reconstruct conversation history from JSONL
        try
        {
            using var sessionStore = new SessionStore(projectPath, sessionId);
            var messages = await sessionStore.ReconstructMessagesAsync(cancellationToken).ConfigureAwait(false);

            if (messages.Count > 0)
            {
                newSession.Orchestrator.RestoreConversationHistory(messages);

                _logger?.LogInformation(
                    "Session {SessionId} resumed with {MessageCount} messages from disk",
                    sessionId,
                    messages.Count);
            }
        }
        catch (Exception ex) when (ex is IOException or System.Text.Json.JsonException or UnauthorizedAccessException)
        {
            _logger?.LogWarning(
                ex,
                "Failed to reconstruct conversation history for session {SessionId}",
                sessionId);

            // Continue with empty session rather than failing completely
        }

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
                if (_userSessions.TryGetValue(userId, out var sessionIds))
                {
                    sessionIds.Remove(sessionId);
                    if (sessionIds.Count == 0)
                    {
                        _userSessions.TryRemove(userId, out _);
                    }
                }
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

            _logger?.LogInformation(
                "Suspended session {SessionId} terminated",
                sessionId);
        }

        await Task.CompletedTask.ConfigureAwait(false);
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
    /// </summary>
    private async Task CheckAndSuspendIdleSessionsAsync()
    {
        var now = DateTimeOffset.UtcNow;
        var suspensionTasks = new List<Task>();

        foreach (var kvp in _sessions)
        {
            var session = kvp.Value;
            var idleDuration = now - session.LastActivity;

            if (idleDuration >= _options.IdleTimeoutValue)
            {
                // Transition to Idle state first
                if (session.State == SessionState.Active)
                {
                    session.TransitionToIdle();
                }

                // If already idle, suspend the session
                if (session.State == SessionState.Idle)
                {
                    suspensionTasks.Add(SuspendSessionAsync(session));
                }
            }
        }

        await Task.WhenAll(suspensionTasks).ConfigureAwait(false);
    }

    /// <summary>
    /// Suspends a session by disposing the orchestrator and moving it to suspended tracking.
    /// </summary>
    private async Task SuspendSessionAsync(ManagedSession session)
    {
        // Create suspended session info before disposing
        var suspendedInfo = new SuspendedSessionInfo(
            ProjectPath: session.ProjectPath,
            ExternalKey: session.ExternalKey,
            UserId: null, // UserId not available on ManagedSession
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
    /// Counts the number of active sessions for a given user.
    /// </summary>
    private int CountSessionsForUser(string userId)
    {
        if (_userSessions.TryGetValue(userId, out var sessionIds))
        {
            return sessionIds.Count;
        }

        return 0;
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

    /// <summary>
    /// Records token usage for global budget tracking.
    /// Should be called after each prompt/response cycle.
    /// </summary>
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
