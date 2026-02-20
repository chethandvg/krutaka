namespace Krutaka.Memory;

/// <summary>
/// Configuration options for the memory system.
/// </summary>
public sealed class MemoryOptions
{
    /// <summary>
    /// Gets or sets the path to the SQLite database file.
    /// </summary>
    /// <value>
    /// Defaults to "~/.krutaka/memory.db".
    /// </value>
    public string DatabasePath { get; set; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        ".krutaka",
        "memory.db");

    /// <summary>
    /// Gets or sets the target chunk size in tokens.
    /// </summary>
    /// <value>
    /// Defaults to 500 tokens per chunk.
    /// </value>
    public int ChunkSizeTokens { get; set; } = 500;

    /// <summary>
    /// Gets or sets the overlap size in tokens between consecutive chunks.
    /// </summary>
    /// <value>
    /// Defaults to 50 tokens overlap.
    /// </value>
    public int ChunkOverlapTokens { get; set; } = 50;
}
