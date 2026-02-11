using System.Text.Json;
using Krutaka.Core;

namespace Krutaka.Memory;

/// <summary>
/// Tool for storing facts and learnings in persistent memory.
/// Updates MEMORY.md and indexes content into SQLite for search.
/// </summary>
public class MemoryStoreTool : ToolBase
{
    private readonly Memory.MemoryFileService _memoryFileService;
    private readonly IMemoryService _memoryService;

    /// <summary>
    /// Initializes a new instance of the <see cref="MemoryStoreTool"/> class.
    /// </summary>
    /// <param name="memoryFileService">The memory file service.</param>
    /// <param name="memoryService">The memory service for indexing.</param>
    public MemoryStoreTool(MemoryFileService memoryFileService, IMemoryService memoryService)
    {
        ArgumentNullException.ThrowIfNull(memoryFileService, nameof(memoryFileService));
        ArgumentNullException.ThrowIfNull(memoryService, nameof(memoryService));

        _memoryFileService = memoryFileService;
        _memoryService = memoryService;
    }

    /// <inheritdoc/>
    public override string Name => "memory_store";

    /// <inheritdoc/>
    public override string Description => "Store a fact, preference, or learning in persistent memory. " +
        "Use this when you learn something important about the user, the project, or the task that should be remembered for future sessions. " +
        "The information is stored in MEMORY.md under the specified category and indexed for search. " +
        "Examples: user preferences, project conventions, important file locations, technical decisions.";

    /// <inheritdoc/>
    public override JsonElement InputSchema => BuildSchema(
        ("key", "string", "The category or section header (e.g., 'User Preferences', 'Project Context', 'Technical Decisions')", true),
        ("value", "string", "The fact or information to remember", true)
    );

    /// <inheritdoc/>
    public override async Task<string> ExecuteAsync(JsonElement input, CancellationToken cancellationToken)
    {
        try
        {
            // Extract parameters
            if (!input.TryGetProperty("key", out var keyElement))
            {
                return "Error: Missing required parameter 'key'";
            }

            if (!input.TryGetProperty("value", out var valueElement))
            {
                return "Error: Missing required parameter 'value'";
            }

            var key = keyElement.GetString();
            var value = valueElement.GetString();

            if (string.IsNullOrWhiteSpace(key))
            {
                return "Error: Parameter 'key' cannot be empty";
            }

            if (string.IsNullOrWhiteSpace(value))
            {
                return "Error: Parameter 'value' cannot be empty";
            }

            // Append to MEMORY.md
            var wasAdded = await _memoryFileService.AppendToMemoryAsync(key, value, cancellationToken).ConfigureAwait(false);

            if (!wasAdded)
            {
                return "Memory entry was not added because it already exists in MEMORY.md.";
            }

            // Index into SQLite for search
            var source = $"memory/{key}";
            await _memoryService.StoreAsync(value, source, cancellationToken).ConfigureAwait(false);

            return $"Successfully stored memory entry under category '{key}'. The information has been saved to MEMORY.md and indexed for future retrieval.";
        }
#pragma warning disable CA1031 // Do not catch general exception types - returning user-friendly error messages
        catch (Exception ex)
        {
            return $"Error: Failed to store memory - {ex.Message}";
        }
#pragma warning restore CA1031
    }
}
