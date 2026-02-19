namespace Krutaka.Core;

/// <summary>
/// Defines the strategy for evicting sessions when MaxActiveSessions is reached.
/// </summary>
public enum EvictionStrategy
{
    /// <summary>
    /// Suspend the session with the oldest LastActivity timestamp.
    /// This is the default strategy, preserving session data on disk.
    /// </summary>
    SuspendOldestIdle,

    /// <summary>
    /// Reject the new session request by throwing an exception.
    /// No existing sessions are modified.
    /// </summary>
    RejectNew,

    /// <summary>
    /// Terminate the oldest session entirely, freeing all resources.
    /// This is the most aggressive strategy.
    /// </summary>
    TerminateOldest
}
