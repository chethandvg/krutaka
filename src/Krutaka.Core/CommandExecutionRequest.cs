namespace Krutaka.Core;

/// <summary>
/// Represents a request to execute a command, used as input to command policy evaluation.
/// Contains all information needed to classify the command's risk tier and determine approval requirements.
/// </summary>
/// <param name="Executable">
/// The executable name or path (e.g., "git", "dotnet", "npm").
/// Will be normalized (case-insensitive, .exe suffix stripped) during classification.
/// </param>
/// <param name="Arguments">
/// The command arguments. Used for pattern matching during risk classification.
/// Should not contain shell metacharacters (validated separately by security policy).
/// </param>
/// <param name="WorkingDirectory">
/// Optional working directory where the command will execute.
/// Used for context-dependent approval (e.g., trusted vs. untrusted directories for Moderate tier).
/// </param>
/// <param name="Justification">
/// Human-readable explanation of why the command is being executed.
/// Provided by the AI agent and shown to the user during approval prompts.
/// </param>
public sealed record CommandExecutionRequest(
    string Executable,
    IReadOnlyList<string> Arguments,
    string? WorkingDirectory,
    string Justification
);
