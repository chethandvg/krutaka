using Krutaka.Core;
using Microsoft.Extensions.Logging;
using System.Collections.Concurrent;

#pragma warning disable CA1848 // Use LoggerMessage delegates for improved performance
#pragma warning disable CA1873 // Evaluation of logging arguments may be expensive when logging is disabled

namespace Krutaka.Tools;

/// <summary>
/// Manages the lifecycle of multiple concurrent sessions.
/// Handles creation, idle detection, suspension, resumption, termination, and eviction.
/// </summary>
public sealed class SessionManager : ISessionManager
{
    private readonly ISessionFactory _factory;
    private readonly SessionManagerOptions _options;
    private readonly ILogger<SessionManager>? _logger;

    // Active sessions: SessionId → ManagedSession
    private readonly ConcurrentDictionary<Guid, ManagedSession> _activeSessions = new();

    // External key mapping: ExternalKey → SessionId
    private readonly ConcurrentDictionary<string, Guid> _externalKeyMap = new();

    // Suspended sessions: SessionId → SuspendedSessionInfo
    private readonly ConcurrentDictionary<Guid, SuspendedSessionInfo> _suspendedSessions = new();

    // Per-user tracking: UserId → ImmutableHashSet<SessionId>
    // Use ImmutableHashSet for thread-safe add/remove operations
    private readonly ConcurrentDictionary<string, System.Collections.Immutable.ImmutableHashSet<Guid>> _userSessions = new();

    // Session to user mapping: SessionId → UserId
    private readonly ConcurrentDictionary<Guid, string> _sessionToUser = new();

    // Per-key locks for GetOrCreateByKeyAsync atomicity
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _keyLocks = new();

    // Track when sessions transitioned to Idle state (for grace period enforcement)
    private readonly ConcurrentDictionary<Guid, DateTimeOffset> _idleSince = new();

    // Global creation lock for capacity validation
    private readonly SemaphoreSlim _creationLock = new(1, 1);

    // Global token budget tracking (clock-hour reset)
    private readonly object _tokenBudgetLock = new();
    private int _globalTokensThisHour;
    private DateTimeOffset _tokenBudgetResetTime = GetNextClockHour(DateTimeOffset.UtcNow);

    // Idle detection background timer
    private readonly PeriodicTimer? _idleDetectionTimer;
    private readonly Task? _idleDetectionTask;
    private readonly CancellationTokenSource _disposeCts = new();

    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="SessionManager"/> class.
    /// </summary>
    /// <param name="factory">The session factory for creating new sessions.</param>
    /// <param name="options">Configuration options for the session manager.</param>
    /// <param name="logger">Optional logger for diagnostics.</param>
    public SessionManager(
        ISessionFactory factory,
        SessionManagerOptions options,
        ILogger<SessionManager>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(factory);
        ArgumentNullException.ThrowIfNull(options);

        _factory = factory;
        _options = options;
        _logger = logger;

        // Start idle detection timer if IdleTimeout is configured
        if (_options.IdleTimeoutValue > TimeSpan.Zero)
        {
            // Run idle detection every 30 seconds or half the idle timeout (whichever is smaller)
            var timerInterval = TimeSpan.FromSeconds(Math.Min(30, _options.IdleTimeoutValue.TotalSeconds / 2));
            _idleDetectionTimer = new PeriodicTimer(timerInterval);
            _idleDetectionTask = RunIdleDetectionAsync(_disposeCts.Token);
        }
    }

    /// <inheritdoc/>
    public async Task<ManagedSession> CreateSessionAsync(SessionRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentOutOfRangeException.ThrowIfNegative(request.MaxTokenBudget);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(request.MaxToolCallBudget);

        // Use creation lock to ensure atomic capacity validation and session creation
        await _creationLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Validate global token budget
            lock (_tokenBudgetLock)
            {
                // Reset if hour boundary crossed
                if (DateTimeOffset.UtcNow >= _tokenBudgetResetTime)
                {
                    _globalTokensThisHour = 0;
                    _tokenBudgetResetTime = GetNextClockHour(DateTimeOffset.UtcNow);
                }

                // Check if budget would be exceeded (conservatively assume session will use its max budget)
                if (_globalTokensThisHour + request.MaxTokenBudget > _options.GlobalMaxTokensPerHour)
                {
                    throw new InvalidOperationException(
                        $"Global hourly token budget exhausted. Current: {_globalTokensThisHour}, Limit: {_options.GlobalMaxTokensPerHour}");
                }
            }

            // Validate per-user limits
            if (request.UserId is not null)
            {
                var userSessionCount = CountUserSessions(request.UserId);
                if (userSessionCount >= _options.MaxSessionsPerUser)
                {
                    throw new InvalidOperationException(
                        $"User '{request.UserId}' has reached the maximum number of sessions ({_options.MaxSessionsPerUser}).");
                }
            }

            // Check capacity and apply eviction if necessary
            var totalActiveSessions = _activeSessions.Count;
            if (totalActiveSessions >= _options.MaxActiveSessions)
            {
                await ApplyEvictionStrategyAsync(cancellationToken).ConfigureAwait(false);
            }

            // Create the session
            var session = _factory.Create(request);

            // Store in active sessions
            _activeSessions[session.SessionId] = session;

            // Store external key mapping if provided
            if (request.ExternalKey is not null)
            {
                _externalKeyMap[request.ExternalKey] = session.SessionId;
            }

            // Track per-user session
            if (request.UserId is not null)
            {
                AddSessionToUserTracking(request.UserId, session.SessionId);
                _sessionToUser[session.SessionId] = request.UserId;
            }

            _logger?.LogInformation(
                "Session {SessionId} created for project '{ProjectPath}' with ExternalKey '{ExternalKey}', UserId '{UserId}'",
                session.SessionId, request.ProjectPath, request.ExternalKey, request.UserId);

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
        return _activeSessions.TryGetValue(sessionId, out var session) ? session : null;
    }

    /// <inheritdoc/>
    public async Task<ManagedSession> GetOrCreateByKeyAsync(
        string externalKey,
        SessionRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(externalKey);
        ArgumentNullException.ThrowIfNull(request);

        // Validate that the request's ExternalKey matches the provided externalKey
        // If request.ExternalKey is null, we'll create a new request with the correct key
        // If it's different, throw to prevent mapping errors
        SessionRequest validatedRequest = request;
        if (request.ExternalKey is not null && !string.Equals(request.ExternalKey, externalKey, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                $"SessionRequest.ExternalKey '{request.ExternalKey}' does not match the provided externalKey '{externalKey}'.",
                nameof(request));
        }
        else if (request.ExternalKey is null)
        {
            // Create a new request with the correct ExternalKey
            validatedRequest = request with { ExternalKey = externalKey };
        }

        // Get or create per-key lock for atomic get-then-create
        var keyLock = _keyLocks.GetOrAdd(externalKey, _ => new SemaphoreSlim(1, 1));

        await keyLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Check if external key already exists
            if (_externalKeyMap.TryGetValue(externalKey, out var sessionId))
            {
                // Check if session is active
                if (_activeSessions.TryGetValue(sessionId, out var activeSession))
                {
                    // Update last activity timestamp
                    activeSession.UpdateLastActivity();
                    _logger?.LogDebug("Returning existing active session {SessionId} for ExternalKey '{ExternalKey}'",
                        sessionId, externalKey);
                    return activeSession;
                }

                // Check if session is suspended — resume it automatically
                if (_suspendedSessions.TryGetValue(sessionId, out var suspendedInfo))
                {
                    _logger?.LogInformation(
                        "Automatically resuming suspended session {SessionId} for ExternalKey '{ExternalKey}'",
                        sessionId, externalKey);
                    return await ResumeSessionAsync(sessionId, suspendedInfo.ProjectPath, cancellationToken).ConfigureAwait(false);
                }

                // Session was terminated — fall through to create new session
                _logger?.LogWarning(
                    "ExternalKey '{ExternalKey}' pointed to terminated session {SessionId}. Creating new session.",
                    externalKey, sessionId);
            }

            // Create new session with validated request
            var newSession = await CreateSessionAsync(validatedRequest, cancellationToken).ConfigureAwait(false);
            return newSession;
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

        // Use creation lock to ensure atomic resume and capacity enforcement
        await _creationLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Check if session is already active (idempotent)
            if (_activeSessions.TryGetValue(sessionId, out var activeSession))
            {
                _logger?.LogDebug("Session {SessionId} is already active. Returning existing session.", sessionId);
                return activeSession;
            }

            // Retrieve suspended session info
            if (!_suspendedSessions.TryGetValue(sessionId, out var suspendedInfo))
            {
                throw new InvalidOperationException($"Session {sessionId} is not found in suspended sessions.");
            }

            // Validate ProjectPath matches (security: prevent path tampering)
            if (!string.Equals(suspendedInfo.ProjectPath, projectPath, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"ProjectPath mismatch for session {sessionId}. " +
                    $"Expected: '{suspendedInfo.ProjectPath}', Provided: '{projectPath}'");
            }

            // Check capacity and apply eviction if necessary (same as CreateSessionAsync)
            var totalActiveSessions = _activeSessions.Count;
            if (totalActiveSessions >= _options.MaxActiveSessions)
            {
                await ApplyEvictionStrategyAsync(cancellationToken).ConfigureAwait(false);
            }

            try
            {
                // Create new session request from suspended info
                var request = new SessionRequest(
                    ProjectPath: suspendedInfo.ProjectPath,
                    ExternalKey: suspendedInfo.ExternalKey,
                    UserId: suspendedInfo.UserId);

                // Create new session instance with the SAME session ID to preserve identity
                var session = _factory.Create(request, sessionId);

                // Store in active sessions
                _activeSessions[sessionId] = session;

                // Update external key mapping to point to the resumed session
                if (suspendedInfo.ExternalKey is not null)
                {
                    _externalKeyMap[suspendedInfo.ExternalKey] = sessionId;
                }

                // Restore user tracking
                if (suspendedInfo.UserId is not null)
                {
                    AddSessionToUserTracking(suspendedInfo.UserId, sessionId);
                    _sessionToUser[sessionId] = suspendedInfo.UserId;
                }

                // Remove from suspended sessions AFTER successful creation
                _suspendedSessions.TryRemove(sessionId, out _);

                _logger?.LogInformation(
                    "Session {SessionId} resumed from suspended state. " +
                    "Caller is responsible for reconstructing conversation history from JSONL.",
                    sessionId);

                return session;
            }
            catch (Exception ex)
            {
                // Keep suspended entry on failure (fail-safe)
                _logger?.LogError(ex, "Failed to resume session {SessionId}. Session remains suspended.", sessionId);
                throw;
            }
        }
        finally
        {
            _creationLock.Release();
        }
    }

    /// <inheritdoc/>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Session is disposed via DisposeSessionAsync on line 296")]
    public async Task TerminateSessionAsync(Guid sessionId, CancellationToken cancellationToken)
    {
        // Try to get and remove active session
        if (_activeSessions.TryRemove(sessionId, out var session))
        {
            await DisposeSessionAsync(session).ConfigureAwait(false);

            // Remove external key mapping
            if (session.ExternalKey is not null)
            {
                _externalKeyMap.TryRemove(session.ExternalKey, out _);
            }

            // Remove from user tracking
            if (_sessionToUser.TryRemove(sessionId, out var userId))
            {
                RemoveSessionFromUserTracking(userId, sessionId);
            }

            // Clean up idle tracking
            _idleSince.TryRemove(sessionId, out _);

            _logger?.LogInformation("Session {SessionId} terminated.", sessionId);
        }
        else if (_suspendedSessions.TryRemove(sessionId, out var suspendedInfo))
        {
            // Terminate suspended session
            // Remove external key mapping
            if (suspendedInfo.ExternalKey is not null)
            {
                _externalKeyMap.TryRemove(suspendedInfo.ExternalKey, out _);
            }

            // Remove from user tracking
            if (suspendedInfo.UserId is not null)
            {
                RemoveSessionFromUserTracking(suspendedInfo.UserId, sessionId);
                _sessionToUser.TryRemove(sessionId, out _);
            }

            _logger?.LogInformation("Suspended session {SessionId} terminated.", sessionId);
        }
        else
        {
            _logger?.LogWarning("Session {SessionId} not found for termination.", sessionId);
        }
    }

    /// <inheritdoc/>
    public IReadOnlyList<SessionSummary> ListActiveSessions()
    {
        var summaries = new List<SessionSummary>();

        // Add active sessions
        foreach (var session in _activeSessions.Values)
        {
            summaries.Add(new SessionSummary(
                SessionId: session.SessionId,
                State: session.State,
                ProjectPath: session.ProjectPath,
                ExternalKey: session.ExternalKey,
                UserId: _sessionToUser.TryGetValue(session.SessionId, out var userId) ? userId : null,
                CreatedAt: session.CreatedAt,
                LastActivity: session.LastActivity,
                TokensUsed: session.Budget.TokensUsed,
                TurnsUsed: session.Budget.TurnsUsed));
        }

        // Add suspended sessions
        foreach (var suspendedInfo in _suspendedSessions.Values)
        {
            summaries.Add(new SessionSummary(
                SessionId: suspendedInfo.SessionId,
                State: SessionState.Suspended,
                ProjectPath: suspendedInfo.ProjectPath,
                ExternalKey: suspendedInfo.ExternalKey,
                UserId: suspendedInfo.UserId,
                CreatedAt: suspendedInfo.CreatedAt,
                LastActivity: suspendedInfo.LastActivity,
                TokensUsed: suspendedInfo.TokensUsed,
                TurnsUsed: suspendedInfo.TurnsUsed));
        }

        return summaries;
    }

    /// <inheritdoc/>
    public async Task TerminateAllAsync(CancellationToken cancellationToken)
    {
        // Terminate all active sessions
        var activeSessionIds = _activeSessions.Keys.ToList();
        foreach (var sessionId in activeSessionIds)
        {
            await TerminateSessionAsync(sessionId, cancellationToken).ConfigureAwait(false);
        }

        // Clear suspended sessions
        _suspendedSessions.Clear();

        // Clear external key mappings
        _externalKeyMap.Clear();

        // Clear user tracking
        _userSessions.Clear();
        _sessionToUser.Clear();

        _logger?.LogInformation("All sessions terminated.");
    }

    /// <inheritdoc/>
    public void RecordTokenUsage(int tokens)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(tokens);

        lock (_tokenBudgetLock)
        {
            // Reset if hour boundary crossed
            if (DateTimeOffset.UtcNow >= _tokenBudgetResetTime)
            {
                _globalTokensThisHour = 0;
                _tokenBudgetResetTime = DateTimeOffset.UtcNow.AddHours(1);
            }

            _globalTokensThisHour += tokens;

            _logger?.LogDebug("Recorded {Tokens} tokens. Global hourly total: {Total}/{Limit}",
                tokens, _globalTokensThisHour, _options.GlobalMaxTokensPerHour);
        }
    }

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        // Cancel idle detection timer
        if (_idleDetectionTimer is not null)
        {
            await _disposeCts.CancelAsync().ConfigureAwait(false);
            _idleDetectionTimer.Dispose();

            // Wait for idle detection task to complete
            if (_idleDetectionTask is not null)
            {
                try
                {
                    await _idleDetectionTask.ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    // Expected when cancelling
                }
            }
        }

        // Terminate all sessions
        await TerminateAllAsync(CancellationToken.None).ConfigureAwait(false);

        // Dispose locks
        _creationLock.Dispose();
        _disposeCts.Dispose();

        foreach (var keyLock in _keyLocks.Values)
        {
            keyLock.Dispose();
        }

        _logger?.LogInformation("SessionManager disposed.");
    }

    #region Private Methods

    private async Task ApplyEvictionStrategyAsync(CancellationToken cancellationToken)
    {
        switch (_options.EvictionStrategy)
        {
            case EvictionStrategy.RejectNew:
                throw new InvalidOperationException(
                    $"Maximum number of active sessions ({_options.MaxActiveSessions}) reached. " +
                    "Eviction strategy is set to RejectNew.");

            case EvictionStrategy.SuspendOldestIdle:
                await SuspendOldestIdleSessionAsync(cancellationToken).ConfigureAwait(false);
                break;

            case EvictionStrategy.TerminateOldest:
                await TerminateOldestSessionAsync(cancellationToken).ConfigureAwait(false);
                break;

            default:
                throw new InvalidOperationException($"Unknown eviction strategy: {_options.EvictionStrategy}");
        }
    }

    private async Task SuspendOldestIdleSessionAsync(CancellationToken cancellationToken)
    {
        // Find the oldest session (prefer Idle, fallback to Active)
        var idleSessions = _activeSessions.Values
            .Where(s => s.State == SessionState.Idle)
            .OrderBy(s => s.LastActivity)
            .ToList();

        ManagedSession? sessionToSuspend = null;

        if (idleSessions.Count > 0)
        {
            sessionToSuspend = idleSessions.First();
        }
        else
        {
            // No idle sessions — suspend oldest active session
            var activeSessions = _activeSessions.Values
                .Where(s => s.State == SessionState.Active)
                .OrderBy(s => s.LastActivity)
                .ToList();

            if (activeSessions.Count > 0)
            {
                sessionToSuspend = activeSessions.First();
            }
        }

        if (sessionToSuspend is null)
        {
            throw new InvalidOperationException("No sessions available to suspend.");
        }

        await SuspendSessionAsync(sessionToSuspend, cancellationToken).ConfigureAwait(false);
    }

    private async Task TerminateOldestSessionAsync(CancellationToken cancellationToken)
    {
        var oldestSession = _activeSessions.Values
            .OrderBy(s => s.LastActivity)
            .FirstOrDefault();

        if (oldestSession is null)
        {
            throw new InvalidOperationException("No sessions available to terminate.");
        }

        await TerminateSessionAsync(oldestSession.SessionId, cancellationToken).ConfigureAwait(false);
    }

    private async Task SuspendSessionAsync(ManagedSession session, CancellationToken cancellationToken)
    {
        // Note: cancellationToken parameter is kept for consistency with other async methods
        // even though suspension is not currently cancellable
        _ = cancellationToken; // Suppress IDE0060

        // Capture metadata before disposal
        var userId = _sessionToUser.TryGetValue(session.SessionId, out var uid) ? uid : null;

        var suspendedInfo = new SuspendedSessionInfo(
            SessionId: session.SessionId,
            ProjectPath: session.ProjectPath,
            ExternalKey: session.ExternalKey,
            UserId: userId,
            CreatedAt: session.CreatedAt,
            SuspendedAt: DateTimeOffset.UtcNow,
            LastActivity: session.LastActivity,
            TokensUsed: session.Budget.TokensUsed,
            TurnsUsed: session.Budget.TurnsUsed);

        // Update session state to Suspended
        session.State = SessionState.Suspended;

        // Remove from active sessions BEFORE disposal so it is no longer observable as active
        _activeSessions.TryRemove(session.SessionId, out _);

        // Dispose orchestrator to free memory (JSONL remains on disk)
        await DisposeSessionAsync(session).ConfigureAwait(false);

        // Move to suspended tracking
        _suspendedSessions[session.SessionId] = suspendedInfo;

        _logger?.LogInformation(
            "Session {SessionId} suspended. UserId: {UserId}, LastActivity: {LastActivity}",
            session.SessionId, userId, session.LastActivity);
    }

    private async Task RunIdleDetectionAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested && _idleDetectionTimer is not null)
        {
            try
            {
                await _idleDetectionTimer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false);

                var now = DateTimeOffset.UtcNow;
                var idleTimeout = _options.IdleTimeoutValue;
                var suspensionGracePeriod = idleTimeout * 2; // 2× IdleTimeout

                // Process active sessions for transition to Idle
                var sessionsToTransitionToIdle = new List<ManagedSession>();
                foreach (var session in _activeSessions.Values)
                {
                    if (session.State == SessionState.Active)
                    {
                        var timeSinceLastActivity = now - session.LastActivity;
                        if (timeSinceLastActivity >= idleTimeout)
                        {
                            sessionsToTransitionToIdle.Add(session);
                        }
                    }
                }

                // Transition Active → Idle and record the transition time
                foreach (var session in sessionsToTransitionToIdle)
                {
                    session.State = SessionState.Idle;
                    _idleSince[session.SessionId] = now; // Track when it became Idle
                    _logger?.LogInformation(
                        "Session {SessionId} transitioned to Idle after {Duration} of inactivity.",
                        session.SessionId, now - session.LastActivity);
                }

                // Process idle sessions for suspension
                // Only suspend sessions that have been Idle for the full grace period
                var sessionsToSuspend = new List<ManagedSession>();
                foreach (var session in _activeSessions.Values)
                {
                    if (session.State == SessionState.Idle && _idleSince.TryGetValue(session.SessionId, out var idleSinceTime))
                    {
                        var timeSinceIdle = now - idleSinceTime;
                        if (timeSinceIdle >= suspensionGracePeriod)
                        {
                            sessionsToSuspend.Add(session);
                        }
                    }
                }

                // Suspend sessions
                foreach (var session in sessionsToSuspend)
                {
                    await SuspendSessionAsync(session, cancellationToken).ConfigureAwait(false);
                    _idleSince.TryRemove(session.SessionId, out _); // Clean up tracking
                }

                // Clean up expired suspended sessions
                var expiredSuspendedSessions = _suspendedSessions.Values
                    .Where(s => now - s.SuspendedAt >= _options.SuspendedTtlValue)
                    .Select(s => s.SessionId)
                    .ToList();

                foreach (var sessionId in expiredSuspendedSessions)
                {
                    await TerminateSessionAsync(sessionId, cancellationToken).ConfigureAwait(false);
                    _logger?.LogInformation(
                        "Suspended session {SessionId} expired after TTL of {TTL}.",
                        sessionId, _options.SuspendedTtlValue);
                }
            }
            catch (OperationCanceledException)
            {
                // Expected when disposing
                break;
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch (Exception ex)
#pragma warning restore CA1031
            {
                _logger?.LogError(ex, "Error in idle detection task.");
            }
        }
    }

    private int CountUserSessions(string userId)
    {
        if (!_userSessions.TryGetValue(userId, out var sessions))
        {
            return 0;
        }

        return sessions.Count;
    }

    private void AddSessionToUserTracking(string userId, Guid sessionId)
    {
        _userSessions.AddOrUpdate(
            userId,
            _ => System.Collections.Immutable.ImmutableHashSet.Create(sessionId),
            (_, existingSessions) => existingSessions.Add(sessionId));
    }

    private void RemoveSessionFromUserTracking(string userId, Guid sessionId)
    {
        while (true)
        {
            if (!_userSessions.TryGetValue(userId, out var sessions))
            {
                // No sessions tracked for this user; nothing to remove.
                return;
            }

            var updatedSessions = sessions.Remove(sessionId);

            if (updatedSessions.IsEmpty)
            {
                // Attempt to remove the user entry only if it still maps to the
                // same sessions set we just used to compute updatedSessions.
                // This prevents losing concurrent additions.
                if (_userSessions.TryRemove(new KeyValuePair<string, System.Collections.Immutable.ImmutableHashSet<Guid>>(userId, sessions)))
                {
                    return;
                }

                // Another thread modified the entry; retry with the new value.
                continue;
            }

            // Attempt to update the sessions set only if it has not changed
            // since we read it, to avoid losing concurrent updates.
            if (_userSessions.TryUpdate(userId, updatedSessions, sessions))
            {
                return;
            }

            // Another thread modified the entry; retry with the new value.
        }
    }

    private static async ValueTask DisposeSessionAsync(ManagedSession session)
    {
        await session.DisposeAsync().ConfigureAwait(false);
    }

    /// <summary>
    /// Calculates the next clock hour boundary from the given time.
    /// </summary>
    /// <param name="time">The current time.</param>
    /// <returns>The next top-of-hour timestamp (minutes and seconds truncated to zero).</returns>
    private static DateTimeOffset GetNextClockHour(DateTimeOffset time)
    {
        // Truncate minutes and seconds to zero, then add one hour
        var truncated = new DateTimeOffset(time.Year, time.Month, time.Day, time.Hour, 0, 0, time.Offset);
        return truncated.AddHours(1);
    }

    #endregion
}
