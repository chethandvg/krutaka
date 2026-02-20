namespace Krutaka.Core;

/// <summary>
/// Analyses an <see cref="AgentBehaviorSnapshot"/> to detect anomalous or potentially unsafe
/// agent behavior patterns such as runaway loops, scope creep, or access escalation attempts.
/// Implementations should be stateless and deterministic given the same snapshot.
/// </summary>
public interface IBehaviorAnomalyDetector
{
    /// <summary>
    /// Assesses the provided behavioral snapshot for anomalies.
    /// </summary>
    /// <param name="snapshot">The point-in-time behavioral metrics to evaluate.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// An <see cref="AnomalyAssessment"/> describing whether anomalous behavior was detected,
    /// the reason for the classification, and the severity of the anomaly.
    /// </returns>
    Task<AnomalyAssessment> AssessAsync(AgentBehaviorSnapshot snapshot, CancellationToken cancellationToken);
}
