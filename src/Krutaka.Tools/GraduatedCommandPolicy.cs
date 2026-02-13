using System.Security;
using Krutaka.Core;

namespace Krutaka.Tools;

/// <summary>
/// Implements graduated command execution policy with tiered risk evaluation.
/// Evaluates commands through three stages:
/// 1. Security pre-check (metacharacters, blocklist) via ISecurityPolicy
/// 2. Risk classification (Safe/Moderate/Elevated/Dangerous) via ICommandRiskClassifier
/// 3. Tier-based approval decision with directory trust integration
/// </summary>
/// <remarks>
/// This is the v0.3.0 policy engine that replaces binary approval with graduated tiers.
/// See docs/versions/v0.3.0.md for complete specification.
/// </remarks>
public sealed class GraduatedCommandPolicy : ICommandPolicy
{
    private readonly ICommandRiskClassifier _classifier;
    private readonly ISecurityPolicy _securityPolicy;
    private readonly IAccessPolicyEngine? _policyEngine;
    private readonly CommandPolicyOptions _options;

    /// <summary>
    /// Initializes a new instance of the <see cref="GraduatedCommandPolicy"/> class.
    /// </summary>
    /// <param name="classifier">The risk classifier for determining command tiers.</param>
    /// <param name="securityPolicy">The security policy for pre-check validation.</param>
    /// <param name="policyEngine">Optional access policy engine for directory trust evaluation. If null, Moderate tier always requires approval.</param>
    /// <param name="options">Configuration options for tier behavior.</param>
    /// <exception cref="ArgumentNullException">Thrown if classifier, securityPolicy, or options is null.</exception>
    public GraduatedCommandPolicy(
        ICommandRiskClassifier classifier,
        ISecurityPolicy securityPolicy,
        IAccessPolicyEngine? policyEngine,
        CommandPolicyOptions options)
    {
        _classifier = classifier ?? throw new ArgumentNullException(nameof(classifier));
        _securityPolicy = securityPolicy ?? throw new ArgumentNullException(nameof(securityPolicy));
        _policyEngine = policyEngine;
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    /// <inheritdoc/>
    public async Task<CommandDecision> EvaluateAsync(
        CommandExecutionRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        // Step 1: Security pre-check (ALWAYS runs first - immutable security boundary)
        // This validates shell metacharacters and blocklist enforcement
        // Throws SecurityException if validation fails
        _securityPolicy.ValidateCommand(request.Executable, request.Arguments);

        // Step 2: Classify command risk tier
        var tier = _classifier.Classify(request);

        // Step 3: Tier-based evaluation
        return tier switch
        {
            CommandRiskTier.Safe => EvaluateSafeTier(),
            CommandRiskTier.Moderate => await EvaluateModerateTierAsync(request, cancellationToken).ConfigureAwait(false),
            CommandRiskTier.Elevated => EvaluateElevatedTier(),
            CommandRiskTier.Dangerous => EvaluateDangerousTier(),
            _ => throw new InvalidOperationException($"Unknown command risk tier: {tier}")
        };
    }

    /// <summary>
    /// Evaluates Safe tier commands - always auto-approved.
    /// </summary>
    private static CommandDecision EvaluateSafeTier()
    {
        return CommandDecision.Approve(
            CommandRiskTier.Safe,
            "Auto-approved (Safe tier - read-only operation)");
    }

    /// <summary>
    /// Evaluates Moderate tier commands - context-dependent approval.
    /// Auto-approved in trusted directories if configured, otherwise requires approval.
    /// </summary>
    private async Task<CommandDecision> EvaluateModerateTierAsync(
        CommandExecutionRequest request,
        CancellationToken cancellationToken)
    {
        // If feature is disabled via config, always require approval
        if (!_options.ModerateAutoApproveInTrustedDirs)
        {
            return CommandDecision.RequireApproval(
                CommandRiskTier.Moderate,
                "Requires approval (Moderate tier - auto-approval disabled by configuration)");
        }

        // If no policy engine is available, cannot determine trust - require approval
        if (_policyEngine is null)
        {
            return CommandDecision.RequireApproval(
                CommandRiskTier.Moderate,
                "Requires approval (Moderate tier - no access policy engine available)");
        }

        // If working directory is not specified, cannot evaluate trust - require approval
        if (string.IsNullOrWhiteSpace(request.WorkingDirectory))
        {
            return CommandDecision.RequireApproval(
                CommandRiskTier.Moderate,
                "Requires approval (Moderate tier - no working directory specified)");
        }

        // Check if working directory is in a trusted zone (auto-grant or session-approved)
        var accessRequest = new DirectoryAccessRequest(
            Path: request.WorkingDirectory,
            Level: AccessLevel.Execute,
            Justification: $"Command execution: {request.Executable} {string.Join(" ", request.Arguments)}"
        );

        var accessDecision = await _policyEngine.EvaluateAsync(accessRequest, cancellationToken).ConfigureAwait(false);

        // Evaluate based on access decision outcome
        return accessDecision.Outcome switch
        {
            // If directory access is granted (trusted zone), auto-approve the command
            AccessOutcome.Granted => CommandDecision.Approve(
                CommandRiskTier.Moderate,
                "Auto-approved (Moderate tier in trusted directory)"),

            // If directory access is explicitly denied (e.g., system directories, paths above ceiling),
            // deny the command - this is a hard boundary that cannot be overridden
            AccessOutcome.Denied => CommandDecision.Deny(
                CommandRiskTier.Moderate,
                $"Denied (Moderate tier - directory access denied: {string.Join(", ", accessDecision.DeniedReasons)})"),

            // If directory access requires approval, require approval for the command
            AccessOutcome.RequiresApproval => CommandDecision.RequireApproval(
                CommandRiskTier.Moderate,
                "Requires approval (Moderate tier in untrusted directory)"),

            // Defensive: should never reach here
            _ => throw new InvalidOperationException($"Unknown access outcome: {accessDecision.Outcome}")
        };
    }

    /// <summary>
    /// Evaluates Elevated tier commands - always requires approval.
    /// Directory trust does not override Elevated tier requirement.
    /// </summary>
    private static CommandDecision EvaluateElevatedTier()
    {
        return CommandDecision.RequireApproval(
            CommandRiskTier.Elevated,
            "Requires approval (Elevated tier - potentially destructive operation)");
    }

    /// <summary>
    /// Evaluates Dangerous tier commands - always denied.
    /// This is defense-in-depth as pre-check should have already thrown SecurityException.
    /// </summary>
    private static CommandDecision EvaluateDangerousTier()
    {
        // Defense-in-depth: This should not be reached because the pre-check
        // (ISecurityPolicy.ValidateCommand) should have thrown SecurityException.
        // However, we throw here as well to ensure no dangerous command can execute.
        throw new SecurityException(
            "Command classified as Dangerous tier and cannot be executed. " +
            "This is a security boundary that cannot be overridden.");
    }
}
