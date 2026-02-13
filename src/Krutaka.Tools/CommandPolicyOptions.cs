using Krutaka.Core;

namespace Krutaka.Tools;

/// <summary>
/// Configuration options for command execution policy and tier overrides.
/// Loaded from appsettings.json at startup and validated by <see cref="CommandTierConfigValidator"/>.
/// </summary>
public sealed class CommandPolicyOptions
{
    /// <summary>
    /// Gets or sets the user-defined tier override rules.
    /// Allows adding custom toolchains (e.g., cargo, make, go) or adjusting tiers for existing commands.
    /// Default: empty array (no overrides).
    /// </summary>
    /// <remarks>
    /// These rules are merged with the default rules in <see cref="CommandRiskClassifier"/>.
    /// User overrides are checked BEFORE default rules during classification.
    /// Security invariants enforced by <see cref="CommandTierConfigValidator"/>:
    /// - Cannot promote blocklisted (Dangerous-tier) commands
    /// - Cannot assign Dangerous tier (users cannot add to blocklist via config)
    /// - Executable must be a simple name (no path separators or shell metacharacters)
    /// - Argument patterns cannot contain shell metacharacters
    /// </remarks>
#pragma warning disable CA1819 // Properties should not return arrays - this is configuration data
    public CommandRiskRule[] TierOverrides { get; set; } = [];
#pragma warning restore CA1819

    /// <summary>
    /// Gets or sets whether Moderate-tier commands should be auto-approved when executed in trusted directories.
    /// Default: true.
    /// </summary>
    /// <remarks>
    /// When true, Moderate-tier commands in auto-grant directories (Layer 2) or user-approved directories
    /// (Layer 3) are executed without prompting. When false, Moderate commands always require approval
    /// regardless of directory trust level.
    /// This setting affects the behavior of <see cref="ICommandPolicy.EvaluateAsync"/>.
    /// </remarks>
    public bool ModerateAutoApproveInTrustedDirs { get; set; } = true;
}
