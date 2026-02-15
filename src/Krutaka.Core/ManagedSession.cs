namespace Krutaka.Core;

/// <summary>
/// Represents a managed session with isolated per-session state and resources.
/// Implements IAsyncDisposable to clean up resources when the session is terminated.
/// </summary>
public sealed class ManagedSession : IAsyncDisposable
{
    /// <summary>
    /// Gets the unique session identifier.
    /// </summary>
    public Guid SessionId { get; }

    /// <summary>
    /// Gets the absolute path to the project directory for this session.
    /// </summary>
    public string ProjectPath { get; }

    /// <summary>
    /// Gets the optional external key (e.g., Telegram chatId) used to look up this session.
    /// </summary>
    public string? ExternalKey { get; }

    /// <summary>
    /// Gets the timestamp when this session was created.
    /// </summary>
    public DateTimeOffset CreatedAt { get; }

    /// <summary>
    /// Gets the timestamp of the last activity in this session.
    /// Updated via UpdateLastActivity() when new messages arrive.
    /// </summary>
    public DateTimeOffset LastActivity { get; private set; }

    /// <summary>
    /// Gets the current session state.
    /// </summary>
    public SessionState State { get; internal set; }

    /// <summary>
    /// Gets the per-session agent orchestrator responsible for the agentic loop.
    /// </summary>
    public AgentOrchestrator Orchestrator { get; }

    /// <summary>
    /// Gets the per-session correlation context for tracking SessionId, TurnId, and RequestId.
    /// </summary>
    public CorrelationContext CorrelationContext { get; }

    /// <summary>
    /// Gets the session budget tracker for tokens, tool calls, and turns.
    /// </summary>
    public SessionBudget Budget { get; }

    /// <summary>
    /// Gets the per-session access store for directory grants (IDisposable).
    /// </summary>
    public ISessionAccessStore? SessionAccessStore { get; }

    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="ManagedSession"/> class.
    /// </summary>
    /// <param name="sessionId">The unique session identifier.</param>
    /// <param name="projectPath">The project directory path.</param>
    /// <param name="externalKey">Optional external key for session lookup.</param>
    /// <param name="orchestrator">The per-session agent orchestrator.</param>
    /// <param name="correlationContext">The per-session correlation context.</param>
    /// <param name="budget">The session budget tracker.</param>
    /// <param name="sessionAccessStore">Optional per-session access store for directory grants.</param>
    public ManagedSession(
        Guid sessionId,
        string projectPath,
        string? externalKey,
        AgentOrchestrator orchestrator,
        CorrelationContext correlationContext,
        SessionBudget budget,
        ISessionAccessStore? sessionAccessStore = null)
    {
        ArgumentNullException.ThrowIfNull(orchestrator);
        ArgumentNullException.ThrowIfNull(correlationContext);
        ArgumentNullException.ThrowIfNull(budget);
        ArgumentException.ThrowIfNullOrWhiteSpace(projectPath);

        SessionId = sessionId;
        ProjectPath = projectPath;
        ExternalKey = externalKey;
        Orchestrator = orchestrator;
        CorrelationContext = correlationContext;
        Budget = budget;
        SessionAccessStore = sessionAccessStore;
        CreatedAt = DateTimeOffset.UtcNow;
        LastActivity = CreatedAt;
        State = SessionState.Active;
    }

    /// <summary>
    /// Updates the last activity timestamp to the current UTC time.
    /// Called when new messages arrive to reset the idle timeout.
    /// </summary>
    public void UpdateLastActivity()
    {
        LastActivity = DateTimeOffset.UtcNow;
    }

    /// <summary>
    /// Disposes the session, releasing all resources and transitioning to Terminated state.
    /// Calls Orchestrator.Dispose() synchronously since AgentOrchestrator implements IDisposable (not IAsyncDisposable).
    /// Disposes SessionAccessStore if present (InMemorySessionAccessStore implements IDisposable).
    /// </summary>
    public ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return default;
        }

        State = SessionState.Terminated;

        // AgentOrchestrator implements IDisposable (synchronous), not IAsyncDisposable
        // It only releases the SemaphoreSlim — no async resources to dispose
        Orchestrator.Dispose();

        // Dispose SessionAccessStore if present (InMemorySessionAccessStore has SemaphoreSlim)
        if (SessionAccessStore is IDisposable disposableStore)
        {
            disposableStore.Dispose();
        }

        _disposed = true;

        return default;
    }
}
