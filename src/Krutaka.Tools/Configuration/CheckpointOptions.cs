namespace Krutaka.Tools;

/// <summary>
/// Configuration options for git checkpoint creation.
/// Loaded from the <c>ToolOptions:Checkpoint</c> section in appsettings.json.
/// </summary>
public sealed class CheckpointOptions
{
    /// <summary>
    /// Gets or sets the maximum number of git checkpoints that can be created per session.
    /// When the limit is reached, the oldest checkpoint is pruned to make room for the new one.
    /// Default is 50 (prevents disk exhaustion — AT4 mitigation).
    /// </summary>
    public int MaxCheckpointsPerSession { get; set; } = 50;

    /// <summary>
    /// Gets or sets whether checkpoints are automatically created before file-modifying tool calls
    /// (<c>write_file</c> and <c>edit_file</c>). When <c>false</c>, checkpoints must be created
    /// manually via the <c>/checkpoint</c> steering command.
    /// Default is <c>true</c>.
    /// </summary>
    public bool AutoCheckpointOnFileModification { get; set; } = true;
}
