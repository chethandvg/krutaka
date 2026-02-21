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

    /// <summary>
    /// Gets the per-session autonomy level provider (immutable level per S9).
    /// May be null if not configured (e.g., in tests or legacy sessions).
    /// </summary>
    public IAutonomyLevelProvider? AutonomyLevelProvider { get; }

    /// <summary>
    /// Gets the per-session task budget tracker for monitoring resource consumption.
    /// May be null if not configured (e.g., in tests or legacy sessions).
    /// </summary>
    public ITaskBudgetTracker? TaskBudgetTracker { get; }

    /// <summary>
    /// Gets the per-session git checkpoint service for manual checkpoint and rollback operations.
    /// May be null if git is not available or checkpoints are disabled for this session.
    /// </summary>
    public IGitCheckpointService? GitCheckpointService { get; }

    /// <summary>
    /// Gets the per-session agent state manager for pause/resume/abort lifecycle control (v0.5.0).
    /// Used by <see cref="SessionManager"/> to wire the deadman's switch timer (S12).
    /// May be null if not configured (e.g., in tests or legacy sessions).
    /// </summary>
    public IAgentStateManager? AgentStateManager { get; }

    private bool _disposed;
    private readonly HashSet<string> _tempDirectoriesToCleanup = new(StringComparer.OrdinalIgnoreCase);

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
    /// <param name="autonomyLevelProvider">Optional per-session autonomy level provider (immutable per S9).</param>
    /// <param name="taskBudgetTracker">Optional per-session task budget tracker for resource consumption monitoring.</param>
    /// <param name="gitCheckpointService">Optional per-session git checkpoint service for manual checkpoint/rollback.</param>
    /// <param name="agentStateManager">Optional per-session agent state manager for pause/resume/abort lifecycle control (v0.5.0).</param>
    public ManagedSession(
        Guid sessionId,
        string projectPath,
        string? externalKey,
        AgentOrchestrator orchestrator,
        CorrelationContext correlationContext,
        SessionBudget budget,
        ISessionAccessStore? sessionAccessStore = null,
        IAutonomyLevelProvider? autonomyLevelProvider = null,
        ITaskBudgetTracker? taskBudgetTracker = null,
        IGitCheckpointService? gitCheckpointService = null,
        IAgentStateManager? agentStateManager = null)
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
        AutonomyLevelProvider = autonomyLevelProvider;
        TaskBudgetTracker = taskBudgetTracker;
        GitCheckpointService = gitCheckpointService;
        AgentStateManager = agentStateManager;
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
    /// Registers a temporary directory for automatic cleanup when the session is disposed.
    /// </summary>
    /// <param name="directoryPath">The absolute path to the temporary directory.</param>
    public void RegisterTempDirectoryForCleanup(string directoryPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directoryPath);
        
        lock (_tempDirectoriesToCleanup)
        {
            _tempDirectoriesToCleanup.Add(directoryPath);
        }
    }

    /// <summary>
    /// Disposes the session, releasing all resources and transitioning to Terminated state.
    /// Calls Orchestrator.Dispose() synchronously since AgentOrchestrator implements IDisposable (not IAsyncDisposable).
    /// Disposes SessionAccessStore if present (InMemorySessionAccessStore implements IDisposable).
    /// Cleans up registered temporary directories.
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

        // Dispose GitCheckpointService if present (GitCheckpointService has SemaphoreSlim).
        // When auto-checkpoint is enabled, AgentOrchestrator.Dispose() (called above) also disposes
        // this instance, but GitCheckpointService.Dispose() only releases a SemaphoreSlim which is
        // idempotent — so double-disposing is safe.
        if (GitCheckpointService is IDisposable disposableCheckpoint)
        {
            disposableCheckpoint.Dispose();
        }

        // Clean up registered temporary directories
        lock (_tempDirectoriesToCleanup)
        {
            foreach (var tempDir in _tempDirectoriesToCleanup)
            {
                try
                {
                    if (Directory.Exists(tempDir))
                    {
                        Directory.Delete(tempDir, recursive: true);
                    }
                }
#pragma warning disable CA1031 // Do not catch general exception types - cleanup failures should not prevent disposal
                catch
#pragma warning restore CA1031
                {
                    // Ignore cleanup errors - best effort cleanup
                }
            }

            _tempDirectoriesToCleanup.Clear();
        }

        _disposed = true;

        return default;
    }
}
