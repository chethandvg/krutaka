namespace Krutaka.Core;

/// <summary>
/// Identifies a measurable resource dimension tracked by the task budget.
/// Each dimension maps to a corresponding limit in <see cref="TaskBudget"/>
/// and a counter in <see cref="TaskBudgetSnapshot"/>.
/// </summary>
public enum BudgetDimension
{
    /// <summary>
    /// The number of Claude API tokens consumed across all requests in the task.
    /// Corresponds to <see cref="TaskBudget.MaxClaudeTokens"/>.
    /// </summary>
    Tokens = 0,

    /// <summary>
    /// The total number of tool invocations executed during the task.
    /// Corresponds to <see cref="TaskBudget.MaxToolCalls"/>.
    /// </summary>
    ToolCalls = 1,

    /// <summary>
    /// The number of distinct files that have been created or modified during the task.
    /// Corresponds to <see cref="TaskBudget.MaxFilesModified"/>.
    /// </summary>
    FilesModified = 2,

    /// <summary>
    /// The number of child processes spawned during the task.
    /// Corresponds to <see cref="TaskBudget.MaxProcessesSpawned"/>.
    /// </summary>
    ProcessesSpawned = 3
}
