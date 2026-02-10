using System.Text.Json;
using Krutaka.Core;

namespace Krutaka.Tools;

/// <summary>
/// Manages the collection of available tools and handles tool dispatch.
/// Provides tool definitions for Claude API and executes tool calls.
/// </summary>
public sealed class ToolRegistry : IToolRegistry
{
    private readonly Dictionary<string, ITool> _tools = new(StringComparer.OrdinalIgnoreCase);

    /// <inheritdoc/>
    public void Register(ITool tool)
    {
        ArgumentNullException.ThrowIfNull(tool);
        _tools[tool.Name] = tool;
    }

    /// <inheritdoc/>
    public object GetToolDefinitions()
    {
        // Return a list of anonymous objects that can be serialized to Claude API format
        // The AI layer will convert these to the appropriate Anthropic SDK types
        var toolDefinitions = _tools.Values.Select(t => new
        {
            name = t.Name,
            description = t.Description,
            input_schema = t.InputSchema
        }).ToList();

        return toolDefinitions;
    }

    /// <inheritdoc/>
    public async Task<string> ExecuteAsync(
        string name,
        JsonElement input,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(name);

        if (!_tools.TryGetValue(name, out var tool))
        {
            throw new InvalidOperationException($"Unknown tool: {name}");
        }

        return await tool.ExecuteAsync(input, cancellationToken).ConfigureAwait(false);
    }
}

