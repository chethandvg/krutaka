namespace Krutaka.Core;

/// <summary>
/// Represents the result of evaluating a command execution request through the command policy.
/// Contains the approval decision, risk tier, and reasoning for the decision.
/// </summary>
/// <param name="Approved">
/// True if the command is approved for execution (either auto-approved or requires human approval).
/// False if the command is denied/blocked.
/// </param>
/// <param name="Tier">
/// The classified risk tier for this command.
/// </param>
/// <param name="Reason">
/// Human-readable explanation of the decision.
/// Examples: "Auto-approved (Safe tier)", "Requires approval (Elevated tier)", "Blocked (Dangerous tier)".
/// </param>
/// <param name="RequiresApproval">
/// True if human approval is required before execution.
/// False if the command is auto-approved or denied (no approval prompt needed).
/// </param>
public sealed record CommandDecision(
    bool Approved,
    CommandRiskTier Tier,
    string Reason,
    bool RequiresApproval
)
{
    /// <summary>
    /// Creates an approved decision for auto-approved commands (Safe or Moderate in trusted directories).
    /// </summary>
    /// <param name="tier">The risk tier that was classified.</param>
    /// <param name="reason">The reason for auto-approval.</param>
    /// <returns>A CommandDecision indicating the command is approved and does not require human approval.</returns>
    public static CommandDecision Approve(CommandRiskTier tier, string reason)
    {
        return new CommandDecision(
            Approved: true,
            Tier: tier,
            Reason: reason,
            RequiresApproval: false
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
            Approved: true,
            Tier: tier,
            Reason: reason,
            RequiresApproval: true
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
            Approved: false,
            Tier: tier,
            Reason: reason,
            RequiresApproval: false
        );
    }
}
