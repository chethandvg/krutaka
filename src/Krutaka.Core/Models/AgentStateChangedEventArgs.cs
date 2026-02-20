namespace Krutaka.Core;

/// <summary>
/// Provides data for the <see cref="IAgentStateManager.StateChanged"/> event.
/// </summary>
public sealed class AgentStateChangedEventArgs : EventArgs
{
    /// <summary>
    /// Initializes a new instance of <see cref="AgentStateChangedEventArgs"/>.
    /// </summary>
    /// <param name="oldState">The state before the transition.</param>
    /// <param name="newState">The state after the transition.</param>
    /// <param name="reason">The human-readable reason for the transition.</param>
    public AgentStateChangedEventArgs(AgentState oldState, AgentState newState, string reason)
    {
        OldState = oldState;
        NewState = newState;
        Reason = reason;
    }

    /// <summary>Gets the state before the transition.</summary>
    public AgentState OldState { get; }

    /// <summary>Gets the state after the transition.</summary>
    public AgentState NewState { get; }

    /// <summary>Gets the human-readable reason for the transition.</summary>
    public string Reason { get; }
}
