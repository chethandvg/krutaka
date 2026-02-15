namespace Krutaka.Core;

/// <summary>
/// Manages the lifecycle of multiple concurrent sessions.
/// Handles creation, idle detection, suspension, resumption, termination, and eviction.
/// </summary>
public interface ISessionManager : IAsyncDisposable
{
    /// <summary>
    /// Creates a new session with the specified parameters.
    /// </summary>
    /// <param name="request">The session creation request.</param>
    /// <param name="cancellationToken">Cancellation token to cancel the operation.</param>
    /// <returns>The newly created managed session.</returns>
    /// <exception cref="InvalidOperationException">Thrown when MaxActiveSessions is reached and EvictionStrategy is RejectNew.</exception>
    Task<ManagedSession> CreateSessionAsync(SessionRequest request, CancellationToken cancellationToken);

    /// <summary>
    /// Gets an active session by its unique identifier.
    /// </summary>
    /// <param name="sessionId">The session identifier.</param>
    /// <returns>The managed session, or null if not found or terminated.</returns>
    ManagedSession? GetSession(Guid sessionId);

    /// <summary>
    /// Gets an existing session by external key, or creates a new one if not found.
    /// Used by Telegram to map chatId to session.
    /// </summary>
    /// <param name="externalKey">The external key (e.g., Telegram chatId).</param>
    /// <param name="request">The session creation request to use if a new session is created.</param>
    /// <param name="cancellationToken">Cancellation token to cancel the operation.</param>
    /// <returns>The existing or newly created managed session.</returns>
    Task<ManagedSession> GetOrCreateByKeyAsync(string externalKey, SessionRequest request, CancellationToken cancellationToken);

    /// <summary>
    /// Resumes a suspended session by reconstructing its conversation history from disk.
    /// </summary>
    /// <param name="sessionId">The session identifier to resume.</param>
    /// <param name="projectPath">The project path for the session.</param>
    /// <param name="cancellationToken">Cancellation token to cancel the operation.</param>
    /// <returns>The resumed managed session.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the session is not found or cannot be resumed.</exception>
    Task<ManagedSession> ResumeSessionAsync(Guid sessionId, string projectPath, CancellationToken cancellationToken);

    /// <summary>
    /// Terminates a session, releasing all resources and transitioning it to Terminated state.
    /// </summary>
    /// <param name="sessionId">The session identifier to terminate.</param>
    /// <param name="cancellationToken">Cancellation token to cancel the operation.</param>
    Task TerminateSessionAsync(Guid sessionId, CancellationToken cancellationToken);

    /// <summary>
    /// Lists all active sessions (Active, Idle, or Suspended states).
    /// </summary>
    /// <returns>A read-only list of session summaries.</returns>
    IReadOnlyList<SessionSummary> ListActiveSessions();

    /// <summary>
    /// Terminates all active sessions and releases all resources.
    /// Called during shutdown.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token to cancel the operation.</param>
    Task TerminateAllAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Records token usage for global budget tracking.
    /// Should be called after each prompt/response cycle.
    /// </summary>
    /// <param name="tokens">Number of tokens consumed.</param>
    void RecordTokenUsage(int tokens);
}
