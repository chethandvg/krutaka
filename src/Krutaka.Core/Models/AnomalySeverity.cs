namespace Krutaka.Core;

/// <summary>
/// Indicates the severity of a detected behavioral anomaly in the agent's operation.
/// Higher severity values indicate a greater risk of unintended or unsafe behavior.
/// </summary>
public enum AnomalySeverity
{
    /// <summary>No anomaly detected; behavior is within expected parameters.</summary>
    None = 0,

    /// <summary>Minor deviation from expected behavior; informational only.</summary>
    Low = 1,

    /// <summary>Moderate deviation that warrants attention but may not require immediate intervention.</summary>
    Medium = 2,

    /// <summary>Significant deviation indicating potentially unsafe or uncontrolled agent behavior.</summary>
    High = 3,
}
