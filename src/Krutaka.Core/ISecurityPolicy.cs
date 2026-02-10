using System.Security;

namespace Krutaka.Core;

/// <summary>
/// Enforces security policies for file access, command execution, and environment scrubbing.
/// All file and command operations MUST validate through this policy before execution.
/// </summary>
public interface ISecurityPolicy
{
    /// <summary>
    /// Validates a file path for read or write access.
    /// Performs canonicalization and checks against blocked directories and patterns.
    /// </summary>
    /// <param name="path">The path to validate (can be relative or absolute).</param>
    /// <param name="allowedRoot">The allowed root directory (project root).</param>
    /// <returns>The canonicalized, validated absolute path.</returns>
    /// <exception cref="SecurityException">Thrown if the path violates security policy.</exception>
    string ValidatePath(string path, string allowedRoot);

    /// <summary>
    /// Validates a command and its arguments before execution.
    /// Checks against allowlist/blocklist and validates for shell metacharacters.
    /// </summary>
    /// <param name="executable">The executable name or path.</param>
    /// <param name="arguments">The command arguments.</param>
    /// <exception cref="SecurityException">Thrown if the command violates security policy.</exception>
    void ValidateCommand(string executable, IEnumerable<string> arguments);

    /// <summary>
    /// Scrubs sensitive environment variables before spawning child processes.
    /// Removes API keys, secrets, tokens, and cloud provider credentials.
    /// </summary>
    /// <param name="environment">The environment variable dictionary to scrub.</param>
    /// <returns>A scrubbed copy of the environment variables.</returns>
    IDictionary<string, string?> ScrubEnvironment(IDictionary<string, string?> environment);

    /// <summary>
    /// Determines if human approval is required for a tool invocation.
    /// </summary>
    /// <param name="toolName">The name of the tool being invoked.</param>
    /// <returns>True if approval is required, false otherwise.</returns>
    bool IsApprovalRequired(string toolName);
}
