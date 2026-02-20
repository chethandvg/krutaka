namespace Krutaka.Core;

/// <summary>
/// An immutable point-in-time snapshot of resource consumption against a <see cref="TaskBudget"/>.
/// All percentage values are in the range [0.0, 1.0] where 1.0 represents 100% consumed.
/// </summary>
/// <param name="TokensConsumed">Total Claude API tokens consumed so far.</param>
/// <param name="ToolCallsConsumed">Total tool invocations executed so far.</param>
/// <param name="FilesModified">Total files created or modified so far.</param>
/// <param name="ProcessesSpawned">Total child processes spawned so far.</param>
/// <param name="TokensPercentage">Fraction of the token budget consumed (0.0–1.0).</param>
/// <param name="ToolCallsPercentage">Fraction of the tool-call budget consumed (0.0–1.0).</param>
/// <param name="FilesModifiedPercentage">Fraction of the file-modification budget consumed (0.0–1.0).</param>
/// <param name="ProcessesSpawnedPercentage">Fraction of the process-spawn budget consumed (0.0–1.0).</param>
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
