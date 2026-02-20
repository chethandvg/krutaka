namespace Krutaka.Core;

/// <summary>
/// Creates lightweight git stashes or commits before file modifications for rollback safety.
/// Implementations must ensure that checkpoints are isolated per session and do not interfere
/// with the user's working tree or stash stack beyond what is strictly required.
/// </summary>
public interface IGitCheckpointService
{
    /// <summary>
    /// Creates a new checkpoint capturing the current state of the working tree.
    /// </summary>
    /// <param name="message">A human-readable description of why the checkpoint is being created.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>
    /// The unique identifier of the created checkpoint (e.g., a git commit SHA or stash ref)
    /// that can be passed to <see cref="RollbackToCheckpointAsync"/> to restore this state.
    /// </returns>
    Task<string> CreateCheckpointAsync(string message, CancellationToken ct);

    /// <summary>
    /// Rolls back the working tree to the state captured by the specified checkpoint.
    /// </summary>
    /// <param name="checkpointId">The identifier returned by <see cref="CreateCheckpointAsync"/>.</param>
    /// <param name="ct">Cancellation token.</param>
    Task RollbackToCheckpointAsync(string checkpointId, CancellationToken ct);

    /// <summary>
    /// Returns the list of all checkpoints created during the current session, ordered chronologically.
    /// </summary>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>A read-only list of <see cref="CheckpointInfo"/> records, oldest first.</returns>
    Task<IReadOnlyList<CheckpointInfo>> ListCheckpointsAsync(CancellationToken ct);
}
