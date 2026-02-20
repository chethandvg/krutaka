namespace Krutaka.Core;

/// <summary>
/// Defines the autonomy level for the agent, controlling how much human approval is required.
/// Higher levels grant more automatic decision-making authority within configured policy bounds.
/// </summary>
public enum AutonomyLevel
{
    /// <summary>
    /// Every action requires explicit human approval before execution.
    /// This is the default mode used in v0.1.0 through v0.4.x.
    /// </summary>
    Supervised = 0,

    /// <summary>
    /// Safe-tier actions are auto-approved; moderate-tier actions prompt for approval.
    /// Elevated and dangerous actions are still blocked or require explicit approval.
    /// </summary>
    Guided = 1,

    /// <summary>
    /// Safe and moderate-tier actions are auto-approved; elevated-tier actions prompt for approval.
    /// Dangerous actions remain blocked regardless of autonomy level.
    /// </summary>
    SemiAutonomous = 2,

    /// <summary>
    /// All actions within policy are auto-approved; only dangerous-tier actions are blocked.
    /// Requires explicit operator opt-in and audit logging is mandatory.
    /// </summary>
    Autonomous = 3
}
