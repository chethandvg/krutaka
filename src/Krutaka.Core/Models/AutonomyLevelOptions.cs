namespace Krutaka.Core;

/// <summary>
/// Configuration options for the agent autonomy level.
/// Bound from the <c>Agent</c> section in appsettings.json.
/// </summary>
public sealed class AutonomyLevelOptions
{
    /// <summary>
    /// The configuration section name this class binds to.
    /// </summary>
    public const string SectionName = "Agent";

    /// <summary>
    /// Gets or sets the autonomy level for the agent.
    /// Controls how much human approval is required for tool calls.
    /// Default is <see cref="AutonomyLevel.Guided"/> (existing v0.3.0 behavior).
    /// </summary>
    /// <remarks>
    /// Supports both <c>Agent:Level</c> and <c>Agent:AutonomyLevel</c> configuration keys.
    /// The <c>AutonomyLevel</c> property is the canonical key per v0.5.0 spec;
    /// <c>Level</c> is retained for backward compatibility.
    /// </remarks>
    public AutonomyLevel Level { get; set; } = AutonomyLevel.Guided;

    /// <summary>
    /// Alias for <see cref="Level"/> matching the <c>Agent:AutonomyLevel</c> configuration key
    /// described in the v0.5.0 spec. Both keys are equivalent; last writer wins when both are set.
    /// </summary>
    public AutonomyLevel AutonomyLevel
    {
        get => Level;
        set => Level = value;
    }

    /// <summary>
    /// Gets or sets whether Autonomous mode is explicitly enabled.
    /// Must be set to <c>true</c> to use <see cref="AutonomyLevel.Autonomous"/>.
    /// This acts as a deliberate operator opt-in to prevent accidental configuration.
    /// Default is <c>false</c>.
    /// </summary>
    public bool AllowAutonomousMode { get; set; }

    /// <summary>
    /// Validates the options and throws if the configuration is invalid.
    /// Called during session creation to enforce the opt-in invariant (S9).
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when <see cref="Level"/> is <see cref="AutonomyLevel.Autonomous"/>
    /// but <see cref="AllowAutonomousMode"/> is <c>false</c>.
    /// </exception>
    public void Validate()
    {
        if (Level == AutonomyLevel.Autonomous && !AllowAutonomousMode)
        {
            throw new InvalidOperationException(
                "Autonomous mode (Level=3) requires 'Agent:AllowAutonomousMode' to be set to true in configuration. " +
                "This is a deliberate opt-in to prevent accidental use of fully autonomous operation.");
        }
    }
}
