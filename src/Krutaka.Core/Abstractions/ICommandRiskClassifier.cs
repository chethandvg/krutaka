namespace Krutaka.Core;

/// <summary>
/// Classifies commands into risk tiers based on executable name and arguments.
/// This interface defines the contract for determining the risk level of a command
/// without making approval decisions (approval is handled by <see cref="ICommandPolicy"/>).
/// </summary>
public interface ICommandRiskClassifier
{
    /// <summary>
    /// Classifies a command execution request into one of the four risk tiers.
    /// The classification is deterministic and based solely on the executable and arguments,
    /// not on session state or dynamic trust progression.
    /// </summary>
    /// <param name="request">The command execution request to classify.</param>
    /// <returns>
    /// The risk tier for this command: Safe, Moderate, Elevated, or Dangerous.
    /// Unknown executables return Dangerous (fail-closed).
    /// </returns>
    CommandRiskTier Classify(CommandExecutionRequest request);

    /// <summary>
    /// Gets all configured risk classification rules.
    /// Used for system prompt generation to inform the AI agent about command tiers.
    /// </summary>
    /// <returns>
    /// A read-only list of all active risk rules, including default rules and user-configured overrides.
    /// </returns>
    IReadOnlyList<CommandRiskRule> GetRules();
}
