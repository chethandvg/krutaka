namespace Krutaka.Core;

/// <summary>
/// Evaluates command execution requests against security and risk policies.
/// This is the main policy enforcement interface for graduated command execution.
/// It combines risk classification, security validation, and directory trust evaluation
/// to produce approval decisions.
/// </summary>
public interface ICommandPolicy
{
    /// <summary>
    /// Evaluates a command execution request and determines whether it should be approved,
    /// denied, or requires human approval.
    /// </summary>
    /// <param name="request">The command execution request to evaluate.</param>
    /// <param name="cancellationToken">Cancellation token for async operations.</param>
    /// <param name="correlationContext">Optional correlation context for audit logging.</param>
    /// <returns>
    /// A <see cref="CommandDecision"/> indicating:
    /// - Whether the command is approved or denied
    /// - The classified risk tier
    /// - Whether human approval is required before execution
    /// - The reasoning for the decision
    /// </returns>
    /// <remarks>
    /// The evaluation follows this sequence:
    /// 1. Security policy validation (ISecurityPolicy.ValidateCommand) - shell metacharacters, blocklist
    /// 2. Risk classification (ICommandRiskClassifier.Classify) - determine tier
    /// 3. Tier-based evaluation:
    ///    - Safe: Auto-approve
    ///    - Moderate: Auto-approve in trusted directories, require approval elsewhere
    ///    - Elevated: Always require approval
    ///    - Dangerous: Always deny
    /// </remarks>
    Task<CommandDecision> EvaluateAsync(
        CommandExecutionRequest request,
        CancellationToken cancellationToken,
        CorrelationContext? correlationContext = null);
}
