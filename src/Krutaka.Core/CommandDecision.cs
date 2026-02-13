namespace Krutaka.Core;

/// <summary>
/// Represents the result of evaluating a command execution request through the command policy.
/// Contains the decision outcome, risk tier, and reasoning for the decision.
/// </summary>
/// <param name="Outcome">
/// The decision outcome: Approved, RequiresApproval, or Denied.
/// </param>
/// <param name="Tier">
/// The classified risk tier for this command.
/// </param>
/// <param name="Reason">
/// Human-readable explanation of the decision.
/// Examples: "Auto-approved (Safe tier)", "Requires approval (Elevated tier)", "Blocked (Dangerous tier)".
/// </param>
public sealed record CommandDecision(
    CommandOutcome Outcome,
    CommandRiskTier Tier,
    string Reason
)
{
    /// <summary>
    /// Gets a value indicating whether the command is approved for immediate execution without human approval.
    /// </summary>
    public bool IsApproved => Outcome == CommandOutcome.Approved;

    /// <summary>
    /// Gets a value indicating whether human approval is required before execution.
    /// </summary>
    public bool RequiresApproval => Outcome == CommandOutcome.RequiresApproval;

    /// <summary>
    /// Gets a value indicating whether the command is denied and will not execute.
    /// </summary>
    public bool IsDenied => Outcome == CommandOutcome.Denied;

    /// <summary>
    /// Creates an approved decision for auto-approved commands (Safe or Moderate in trusted directories).
    /// </summary>
    /// <param name="tier">The risk tier that was classified.</param>
    /// <param name="reason">The reason for auto-approval.</param>
    /// <returns>A CommandDecision indicating the command is approved and does not require human approval.</returns>
    public static CommandDecision Approve(CommandRiskTier tier, string reason)
    {
        return new CommandDecision(
            Outcome: CommandOutcome.Approved,
            Tier: tier,
            Reason: reason
        );
    }

    /// <summary>
    /// Creates a decision requiring human approval (Moderate in untrusted directories or Elevated tier).
    /// </summary>
    /// <param name="tier">The risk tier that was classified.</param>
    /// <param name="reason">The reason approval is required.</param>
    /// <returns>A CommandDecision indicating the command requires human approval before execution.</returns>
    public static CommandDecision RequireApproval(CommandRiskTier tier, string reason)
    {
        return new CommandDecision(
            Outcome: CommandOutcome.RequiresApproval,
            Tier: tier,
            Reason: reason
        );
    }

    /// <summary>
    /// Creates a denied decision for blocked commands (Dangerous tier or unknown executables).
    /// </summary>
    /// <param name="tier">The risk tier that was classified.</param>
    /// <param name="reason">The reason for denial.</param>
    /// <returns>A CommandDecision indicating the command is denied and will not execute.</returns>
    public static CommandDecision Deny(CommandRiskTier tier, string reason)
    {
        return new CommandDecision(
            Outcome: CommandOutcome.Denied,
            Tier: tier,
            Reason: reason
        );
    }
}
