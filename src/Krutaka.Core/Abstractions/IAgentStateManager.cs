namespace Krutaka.Core;

/// <summary>
/// Manages agent lifecycle state transitions for pause, resume, and abort operations.
/// Implementations must be thread-safe and enforce the valid transition table.
/// </summary>
public interface IAgentStateManager
{
    /// <summary>
    /// Gets the current agent state. Thread-safe.
    /// </summary>
    AgentState CurrentState { get; }

    /// <summary>
    /// Gets the reason for the current pause, or <see langword="null"/> if not paused.
    /// </summary>
    string? PauseReason { get; }

    /// <summary>
    /// Attempts to transition directly to <paramref name="target"/>.
    /// Returns <see langword="false"/> if the transition is invalid (e.g. from <see cref="AgentState.Aborted"/>).
    /// </summary>
    /// <param name="target">The desired target state.</param>
    /// <returns><see langword="true"/> if the transition succeeded; otherwise <see langword="false"/>.</returns>
    bool TryTransition(AgentState target);

    /// <summary>
    /// Requests that the agent pause after completing its current tool call.
    /// Transitions <see cref="AgentState.Running"/> → <see cref="AgentState.Paused"/>.
    /// </summary>
    /// <param name="reason">Human-readable reason shown for diagnostic display.</param>
    void RequestPause(string reason);

    /// <summary>
    /// Immediately transitions to <see cref="AgentState.Aborted"/> (terminal state).
    /// Valid from <see cref="AgentState.Running"/> and <see cref="AgentState.Paused"/>.
    /// </summary>
    /// <param name="reason">Human-readable reason for the abort.</param>
    void RequestAbort(string reason);

    /// <summary>
    /// Resumes a paused agent.
    /// Transitions <see cref="AgentState.Paused"/> → <see cref="AgentState.Running"/>.
    /// No-op if the agent is not currently paused.
    /// </summary>
    void ResumeAgent();

    /// <summary>
    /// Raised when the agent state changes successfully.
    /// Subscribers should not throw from this event.
    /// </summary>
    event EventHandler<AgentStateChangedEventArgs>? StateChanged;
}
