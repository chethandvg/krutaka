namespace Krutaka.Core;

/// <summary>
/// An immutable point-in-time snapshot of observable agent behavioral metrics used by
/// <see cref="IBehaviorAnomalyDetector"/> to detect anomalous or unsafe patterns.
/// </summary>
/// <param name="ToolCallFrequency">
/// The rate of tool invocations per unit time (calls per second).
/// Unusually high values may indicate a runaway loop or uncontrolled execution.
/// </param>
/// <param name="RepeatedFailureCount">
/// The number of consecutive or recent tool call failures observed.
/// A high count may indicate the agent is stuck or repeatedly attempting an unsafe operation.
/// </param>
/// <param name="AccessEscalationCount">
/// The number of times the agent has attempted to access resources outside its originally granted scope.
/// Non-zero values may indicate scope creep or a prompt injection attack.
/// </param>
/// <param name="FileModificationVelocity">
/// The rate of file modifications per unit time (files per second).
/// Unusually high values may indicate bulk destructive operations.
/// </param>
/// <param name="DirectoryScopeExpansionCount">
/// The number of distinct directories accessed beyond the initial working directory.
/// High values may indicate uncontrolled filesystem traversal.
/// </param>
public sealed record AgentBehaviorSnapshot(
    double ToolCallFrequency,
    int RepeatedFailureCount,
    int AccessEscalationCount,
    double FileModificationVelocity,
    int DirectoryScopeExpansionCount
);
