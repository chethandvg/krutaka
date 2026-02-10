using System.Text.Json.Serialization;

namespace Krutaka.Core;

/// <summary>
/// Represents a single result from memory search (hybrid FTS5 + vector).
/// </summary>
/// <param name="Id">The unique identifier of the memory chunk.</param>
/// <param name="Content">The memory content text.</param>
/// <param name="Source">The source identifier (e.g., file path, session ID, "MEMORY.md").</param>
/// <param name="CreatedAt">When this memory was created.</param>
/// <param name="Score">The relevance score (from Reciprocal Rank Fusion).</param>
[method: JsonConstructor]
public sealed record MemoryResult(
    [property: JsonPropertyName("id")] long Id,
    [property: JsonPropertyName("content")] string Content,
    [property: JsonPropertyName("source")] string Source,
    [property: JsonPropertyName("created_at")] DateTimeOffset CreatedAt,
    [property: JsonPropertyName("score")] double Score
);
