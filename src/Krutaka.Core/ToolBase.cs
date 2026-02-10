using System.Text.Json;

namespace Krutaka.Core;

/// <summary>
/// Abstract base class for tool implementations providing JSON Schema generation helpers.
/// </summary>
public abstract class ToolBase : ITool
{
    /// <inheritdoc/>
    public abstract string Name { get; }

    /// <inheritdoc/>
    public abstract string Description { get; }

    /// <inheritdoc/>
    public abstract JsonElement InputSchema { get; }

    /// <inheritdoc/>
    public abstract Task<string> ExecuteAsync(JsonElement input, CancellationToken cancellationToken);

    /// <summary>
    /// Helper method to build a JSON Schema for tool input parameters.
    /// </summary>
    /// <param name="properties">Array of property definitions (name, type, description, required).</param>
    /// <returns>A JsonElement representing the JSON Schema.</returns>
    protected static JsonElement BuildSchema(params (string name, string type, string description, bool required)[] properties)
    {
        ArgumentNullException.ThrowIfNull(properties);

        var props = new Dictionary<string, object>();
        var requiredList = new List<string>();

        foreach (var (name, type, description, required) in properties)
        {
            props[name] = new { type, description };
            if (required)
            {
                requiredList.Add(name);
            }
        }

        var schema = new
        {
            type = "object",
            properties = props,
            required = requiredList.ToArray()
        };

        return JsonSerializer.SerializeToElement(schema);
    }
}
