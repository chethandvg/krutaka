namespace Krutaka.Core;

/// <summary>
/// Provides the current autonomy level for an agent session and determines
/// whether tool calls should be auto-approved based on the configured level.
/// The level is immutable after session creation (security invariant S9).
/// </summary>
public interface IAutonomyLevelProvider
{
    /// <summary>
    /// Gets the configured autonomy level for this session.
    /// The level is set once at session creation and never changes at runtime (S9).
    /// </summary>
    /// <returns>The autonomy level for this session.</returns>
    AutonomyLevel GetLevel();

    /// <summary>
    /// Determines whether a tool call should be auto-approved at the current autonomy level.
    /// </summary>
    /// <param name="toolName">The name of the tool being invoked.</param>
    /// <param name="isApprovalRequired">
    /// Whether the security policy normally requires human approval for this tool.
    /// <c>false</c> indicates a Safe-tier tool; <c>true</c> indicates a tool that
    /// normally requires approval (Moderate or Elevated tier).
    /// </param>
    /// <returns>
    /// <c>true</c> if the tool call should be auto-approved (skipping the human approval prompt);
    /// <c>false</c> if human approval is required.
    /// </returns>
    bool ShouldAutoApprove(string toolName, bool isApprovalRequired);
}
