namespace Krutaka.Core;

/// <summary>
/// An immutable point-in-time snapshot of resource consumption against a <see cref="TaskBudget"/>.
/// Percentage values are expected to be in the range [0.0, 1.0] (where 1.0 represents 100% consumed)
/// when produced by a conforming <see cref="ITaskBudgetTracker"/>.
/// </summary>
/// <param name="TokensConsumed">Total Claude API tokens consumed so far.</param>
/// <param name="ToolCallsConsumed">Total tool invocations executed so far.</param>
/// <param name="FilesModified">Total files created or modified so far.</param>
/// <param name="ProcessesSpawned">Total child processes spawned so far.</param>
/// <param name="TokensPercentage">Fraction of the token budget consumed (typically 0.0–1.0 from a conforming tracker).</param>
/// <param name="ToolCallsPercentage">Fraction of the tool-call budget consumed (typically 0.0–1.0 from a conforming tracker).</param>
/// <param name="FilesModifiedPercentage">Fraction of the file-modification budget consumed (typically 0.0–1.0 from a conforming tracker).</param>
/// <param name="ProcessesSpawnedPercentage">Fraction of the process-spawn budget consumed (typically 0.0–1.0 from a conforming tracker).</param>
public sealed record TaskBudgetSnapshot(
    int TokensConsumed,
    int ToolCallsConsumed,
    int FilesModified,
    int ProcessesSpawned,
    double TokensPercentage,
    double ToolCallsPercentage,
    double FilesModifiedPercentage,
    double ProcessesSpawnedPercentage
);
