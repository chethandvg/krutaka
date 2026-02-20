namespace Krutaka.Core;

/// <summary>
/// An immutable record describing a git checkpoint created before a file modification operation.
/// Checkpoints enable rollback to a known-good state if subsequent agent actions cause undesired changes.
/// </summary>
/// <param name="CheckpointId">The unique identifier for this checkpoint (e.g., a git commit SHA or stash ref).</param>
/// <param name="Message">A human-readable description of why the checkpoint was created.</param>
/// <param name="CreatedAt">The UTC timestamp at which the checkpoint was created.</param>
/// <param name="FilesModified">The number of files that were modified or staged at checkpoint time.</param>
public sealed record CheckpointInfo(
    string CheckpointId,
    string Message,
    DateTime CreatedAt,
    int FilesModified
);
