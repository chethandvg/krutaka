namespace Krutaka.Core;

/// <summary>
/// Provides hybrid memory search combining keyword (FTS5) and vector similarity.
/// Stores and retrieves conversation history and curated memory.
/// </summary>
public interface IMemoryService
{
    /// <summary>
    /// Performs hybrid search combining keyword and vector similarity with Reciprocal Rank Fusion.
    /// </summary>
    /// <param name="query">The search query.</param>
    /// <param name="topK">Maximum number of results to return.</param>
    /// <param name="cancellationToken">Cancellation token for async operation.</param>
    /// <returns>Ranked list of memory results.</returns>
    Task<IReadOnlyList<MemoryResult>> HybridSearchAsync(
        string query,
        int topK = 10,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Stores content in the memory index for future retrieval.
    /// </summary>
    /// <param name="content">The content to store.</param>
    /// <param name="source">The source identifier (e.g., file path, session ID).</param>
    /// <param name="cancellationToken">Cancellation token for async operation.</param>
    /// <returns>The ID of the stored memory entry.</returns>
    Task<long> StoreAsync(
        string content,
        string source,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Chunks a large text into smaller pieces and indexes them for search.
    /// </summary>
    /// <param name="content">The content to chunk and index.</param>
    /// <param name="source">The source identifier.</param>
    /// <param name="cancellationToken">Cancellation token for async operation.</param>
    /// <returns>The number of chunks created.</returns>
    Task<int> ChunkAndIndexAsync(
        string content,
        string source,
        CancellationToken cancellationToken = default);
}
