namespace Krutaka.Core;

/// <summary>
/// Represents the lifecycle state of a managed session.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Naming", "CA1724:Type names should not match namespaces", Justification = "SessionState is a clear name in the Krutaka.Core namespace. Conflict with System.Web.SessionState is irrelevant for .NET 10 applications.")]
public enum SessionState
{
    /// <summary>
    /// Session is actively processing messages and executing tasks.
    /// </summary>
    Active,

    /// <summary>
    /// Session has no activity for IdleTimeout duration but is still in memory.
    /// </summary>
    Idle,

    /// <summary>
    /// Session orchestrator has been disposed to free memory, but JSONL is preserved on disk.
    /// Can be resumed by reconstructing from session history.
    /// </summary>
    Suspended,

    /// <summary>
    /// Session has been explicitly terminated and all resources released.
    /// This is the final state.
    /// </summary>
    Terminated
}
