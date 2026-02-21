namespace Krutaka.Core;

/// <summary>
/// Resolves the autonomy level from configuration and determines whether tool calls
/// should be auto-approved based on the configured level and the tool's risk tier.
/// The level is set once at construction and is immutable thereafter (security invariant S9).
/// </summary>
public sealed class AutonomyLevelProvider : IAutonomyLevelProvider
{
    private readonly AutonomyLevel _level;

    /// <summary>
    /// Initializes a new instance of the <see cref="AutonomyLevelProvider"/> class.
    /// Validates the options and captures the immutable level.
    /// </summary>
    /// <param name="options">The autonomy level configuration options.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="options"/> is null.</exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when <see cref="AutonomyLevel.Autonomous"/> is configured without the opt-in flag.
    /// </exception>
    public AutonomyLevelProvider(AutonomyLevelOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        _level = options.Level;
    }

    /// <inheritdoc/>
    public AutonomyLevel GetLevel() => _level;

    /// <inheritdoc/>
    /// <remarks>
    /// Auto-approval rules by level:
    /// <list type="bullet">
    ///   <item><term>Supervised (0)</term><description>Auto-approve nothing — every action requires explicit human approval.</description></item>
    ///   <item><term>Guided (1)</term><description>Auto-approve Safe-tier tools only (<paramref name="isApprovalRequired"/> = false). Moderate and Elevated require approval.</description></item>
    ///   <item><term>SemiAutonomous (2)</term><description>Auto-approve Safe and Moderate-tier tools. Elevated tools still require approval.</description></item>
    ///   <item><term>Autonomous (3)</term><description>Auto-approve Safe, Moderate, and Elevated tools. Only Dangerous tier is ever blocked (enforced by the security policy before this method is reached).</description></item>
    /// </list>
    /// Dangerous-tier tools are always blocked by the security policy and never reach this method.
    /// </remarks>
    public bool ShouldAutoApprove(string toolName, bool isApprovalRequired)
    {
        return _level switch
        {
            AutonomyLevel.Supervised => false,           // Auto-approve nothing
            AutonomyLevel.Guided => !isApprovalRequired, // Auto-approve Safe only
            AutonomyLevel.SemiAutonomous => true,        // Auto-approve Safe + Moderate (all non-Dangerous)
            AutonomyLevel.Autonomous => true,            // Auto-approve Safe + Moderate + Elevated
            _ => false
        };
    }
}
