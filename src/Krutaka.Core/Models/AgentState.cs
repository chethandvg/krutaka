namespace Krutaka.Core;

/// <summary>
/// Represents the lifecycle state of the agent within a session.
/// Used by the state machine to govern pause, resume, and abort operations.
/// </summary>
public enum AgentState
{
    /// <summary>
    /// The agent is actively processing. This is the initial state.
    /// </summary>
    Running = 0,

    /// <summary>
    /// The agent has completed its current tool call and is waiting for a resume signal.
    /// Transitions to <see cref="Running"/> via <c>Resume()</c> or to <see cref="Aborted"/> via <c>RequestAbort()</c>.
    /// </summary>
    Paused = 1,

    /// <summary>
    /// The agent has been permanently stopped. This is a terminal state — no transitions out.
    /// </summary>
    Aborted = 2,
}
