namespace Krutaka.Core;

/// <summary>
/// Defines the resource limits for a single agentic task.
/// All limits are upper bounds; the task is considered exhausted once any limit is reached.
/// </summary>
/// <param name="MaxClaudeTokens">Maximum number of Claude API tokens the task may consume.</param>
/// <param name="MaxToolCalls">Maximum number of tool invocations allowed during the task.</param>
/// <param name="MaxFilesModified">Maximum number of files the task may create or modify.</param>
/// <param name="MaxProcessesSpawned">Maximum number of child processes the task may spawn.</param>
public sealed record TaskBudget(
    int MaxClaudeTokens = 200_000,
    int MaxToolCalls = 100,
    int MaxFilesModified = 20,
    int MaxProcessesSpawned = 10
);
