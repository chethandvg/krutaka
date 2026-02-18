namespace Krutaka.Core;

/// <summary>
/// Provides read-only access to tool configuration for system prompt generation.
/// </summary>
public interface IToolOptions
{
    /// <summary>
    /// Gets the default working directory for command execution and file operations.
    /// </summary>
    string DefaultWorkingDirectory { get; }

    /// <summary>
    /// Gets the ceiling directory - the maximum ancestor directory the agent can access.
    /// </summary>
    string CeilingDirectory { get; }

    /// <summary>
    /// Gets the glob patterns for auto-approved directory access.
    /// </summary>
#pragma warning disable CA1819 // Properties should not return arrays - this is configuration data
    string[] AutoGrantPatterns { get; }
#pragma warning restore CA1819
}
