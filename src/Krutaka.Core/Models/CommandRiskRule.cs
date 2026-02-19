namespace Krutaka.Core;

/// <summary>
/// Represents a rule that maps an executable and its argument patterns to a risk tier.
/// Used by <see cref="ICommandRiskClassifier"/> to determine the tier for a command.
/// </summary>
/// <param name="Executable">
/// The executable name (e.g., "git", "dotnet"). Case-insensitive. Should not include path or .exe suffix.
/// </param>
/// <param name="ArgumentPatterns">
/// Optional list of argument patterns to match (e.g., ["status", "log", "diff"]).
/// If null, the rule applies to any arguments for this executable.
/// Patterns are case-insensitive and matched against the first argument (or first two for dotnet).
/// </param>
/// <param name="Tier">
/// The risk tier assigned to commands matching this rule.
/// </param>
/// <param name="Description">
/// Optional human-readable description of the rule (e.g., "Read-only git operations").
/// Used for documentation and system prompt generation.
/// </param>
public sealed record CommandRiskRule(
    string Executable,
    IReadOnlyList<string>? ArgumentPatterns,
    CommandRiskTier Tier,
    string? Description
);
