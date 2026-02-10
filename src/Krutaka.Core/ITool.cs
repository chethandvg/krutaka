using System.Text.Json;

namespace Krutaka.Core;

/// <summary>
/// Defines the contract for a tool that can be invoked by the AI agent.
/// Tools are exposed to Claude via JSON Schema and executed locally with security policies enforced.
/// </summary>
public interface ITool
{
    /// <summary>
    /// The tool name, following Claude's naming convention (^[a-zA-Z0-9_-]{1,64}$).
    /// </summary>
    string Name { get; }

    /// <summary>
    /// A detailed description of what the tool does (3-4 sentences recommended).
    /// This description is sent to Claude to help it decide when to use the tool.
    /// </summary>
    string Description { get; }

    /// <summary>
    /// JSON Schema defining the tool's input parameters.
    /// Must conform to the schema format expected by Claude API.
    /// </summary>
    JsonElement InputSchema { get; }

    /// <summary>
    /// Executes the tool with the provided input parameters.
    /// </summary>
    /// <param name="input">The input parameters as a JsonElement.</param>
    /// <param name="cancellationToken">Cancellation token for async operation.</param>
    /// <returns>The tool execution result as a string to be sent back to Claude.</returns>
    Task<string> ExecuteAsync(JsonElement input, CancellationToken cancellationToken);
}
