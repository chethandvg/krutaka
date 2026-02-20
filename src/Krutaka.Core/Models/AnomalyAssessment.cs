namespace Krutaka.Core;

/// <summary>
/// An immutable record representing the result of a behavioral anomaly assessment against an
/// <see cref="AgentBehaviorSnapshot"/>. Produced by <see cref="IBehaviorAnomalyDetector"/>.
/// </summary>
/// <param name="IsAnomalous">
/// <see langword="true"/> if the assessed snapshot indicates anomalous agent behavior;
/// <see langword="false"/> if the behavior is within acceptable bounds.
/// </param>
/// <param name="Reason">
/// A human-readable explanation of why the behavior was classified as anomalous, or
/// <see langword="null"/> when <paramref name="IsAnomalous"/> is <see langword="false"/>.
/// </param>
/// <param name="Severity">The severity level of the detected anomaly.</param>
public sealed record AnomalyAssessment(
    bool IsAnomalous,
    string? Reason,
    AnomalySeverity Severity
);
