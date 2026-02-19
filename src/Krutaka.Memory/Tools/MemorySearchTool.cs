using System.Text;
using System.Text.Json;
using Krutaka.Core;

namespace Krutaka.Memory;

/// <summary>
/// Tool for searching persistent memory using SQLite FTS5.
/// Provides read-only access to stored facts, learnings, and conversation history.
/// </summary>
public class MemorySearchTool : ToolBase
{
    private readonly IMemoryService _memoryService;

    /// <summary>
    /// Initializes a new instance of the <see cref="MemorySearchTool"/> class.
    /// </summary>
    /// <param name="memoryService">The memory service for searching.</param>
    public MemorySearchTool(IMemoryService memoryService)
    {
        ArgumentNullException.ThrowIfNull(memoryService, nameof(memoryService));
        _memoryService = memoryService;
    }

    /// <inheritdoc/>
    public override string Name => "memory_search";

    /// <inheritdoc/>
    public override string Description => "Search persistent memory for relevant facts, learnings, and past context. " +
        "Use this when you need to recall information from previous sessions, find project-specific conventions, " +
        "or retrieve stored preferences and decisions. " +
        "The search uses full-text search with stemming to find relevant content across all stored memories.";

    /// <inheritdoc/>
    public override JsonElement InputSchema => BuildSchema(
        ("query", "string", "The search query (keywords or natural language question)", true),
        ("limit", "integer", "Maximum number of results to return (default: 10, max: 50)", false)
    );

    /// <inheritdoc/>
    public override async Task<string> ExecuteAsync(JsonElement input, CancellationToken cancellationToken)
    {
        try
        {
            // Extract parameters
            if (!input.TryGetProperty("query", out var queryElement))
            {
                return "Error: Missing required parameter 'query'";
            }

            var query = queryElement.GetString();
            if (string.IsNullOrWhiteSpace(query))
            {
                return "Error: Parameter 'query' cannot be empty";
            }

            // Extract optional limit parameter
            var limit = 10;
            if (input.TryGetProperty("limit", out var limitElement) &&
                limitElement.ValueKind == JsonValueKind.Number)
            {
                limit = limitElement.GetInt32();
                if (limit <= 0)
                {
                    return "Error: Parameter 'limit' must be positive";
                }

                if (limit > 50)
                {
                    limit = 50; // Cap at 50
                }
            }

            // Perform search
            var results = await _memoryService.HybridSearchAsync(query, limit, cancellationToken).ConfigureAwait(false);

            if (results.Count == 0)
            {
                return "No matching memories found for the query.";
            }

            // Format results for Claude
            var output = new StringBuilder();
            output.AppendLine(System.Globalization.CultureInfo.InvariantCulture, $"Found {results.Count} relevant memor{(results.Count == 1 ? "y" : "ies")}:");
            output.AppendLine();

            for (int i = 0; i < results.Count; i++)
            {
                var result = results[i];
                output.AppendLine(System.Globalization.CultureInfo.InvariantCulture, $"{i + 1}. **{result.Source}** (Score: {result.Score:F2}, {result.CreatedAt:yyyy-MM-dd HH:mm})");
                output.AppendLine(System.Globalization.CultureInfo.InvariantCulture, $"   <untrusted_content>{result.Content}</untrusted_content>");
                output.AppendLine();
            }

            return output.ToString();
        }
#pragma warning disable CA1031 // Do not catch general exception types - returning user-friendly error messages
        catch (Exception ex)
        {
            return $"Error: Failed to search memory - {ex.Message}";
        }
#pragma warning restore CA1031
    }
}
