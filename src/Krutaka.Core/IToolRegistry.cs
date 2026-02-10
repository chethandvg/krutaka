using System.Text.Json;

namespace Krutaka.Core;

/// <summary>
/// Manages the collection of available tools and handles tool dispatch.
/// </summary>
public interface IToolRegistry
{
    /// <summary>
    /// Registers a tool for use by the agent.
    /// </summary>
    /// <param name="tool">The tool to register.</param>
    void Register(ITool tool);

    /// <summary>
    /// Gets all registered tool definitions formatted for Claude API.
    /// Returns a JSON-serializable representation of tool definitions.
    /// </summary>
    /// <returns>A collection of tool definitions.</returns>
    object GetToolDefinitions();

    /// <summary>
    /// Executes a tool by name with the provided input.
    /// </summary>
    /// <param name="name">The name of the tool to execute.</param>
    /// <param name="input">The input parameters as a JsonElement.</param>
    /// <param name="cancellationToken">Cancellation token for async operation.</param>
    /// <returns>The tool execution result.</returns>
    Task<string> ExecuteAsync(string name, JsonElement input, CancellationToken cancellationToken);
}
