using System.Data;
using Krutaka.Core;
using Microsoft.Data.Sqlite;

namespace Krutaka.Memory;

/// <summary>
/// SQLite-based memory store with FTS5 keyword search.
/// Vector search will be added in a future version.
/// </summary>
public sealed class SqliteMemoryStore : IMemoryService, IDisposable
{
    private readonly string _databasePath;
    private readonly TextChunker _chunker;
    private readonly SemaphoreSlim _dbLock = new(1, 1);
    private SqliteConnection? _connection;
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="SqliteMemoryStore"/> class.
    /// </summary>
    /// <param name="options">Memory configuration options.</param>
    /// <exception cref="ArgumentNullException">Thrown when options is null.</exception>
    public SqliteMemoryStore(MemoryOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        _databasePath = options.DatabasePath;
        _chunker = new TextChunker(options.ChunkSizeTokens, options.ChunkOverlapTokens);
    }

    /// <summary>
    /// Ensures the database is initialized with the required schema.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await _dbLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_connection != null)
            {
                return; // Already initialized
            }

            // Ensure directory exists
            var directory = Path.GetDirectoryName(_databasePath);
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }

            _connection = new SqliteConnection($"Data Source={_databasePath}");
            await _connection.OpenAsync(cancellationToken).ConfigureAwait(false);

            // Create main table
            using var createTableCmd = _connection.CreateCommand();
            createTableCmd.CommandText = @"
                CREATE TABLE IF NOT EXISTS memory_chunks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    content TEXT NOT NULL,
                    source TEXT NOT NULL,
                    chunk_index INTEGER NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    embedding BLOB
                );";
            await createTableCmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

            // Create FTS5 virtual table with porter stemming and unicode61 tokenizer
            using var createFtsCmd = _connection.CreateCommand();
            createFtsCmd.CommandText = @"
                CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts USING fts5(
                    content,
                    source,
                    content='memory_chunks',
                    content_rowid='id',
                    tokenize='porter unicode61'
                );";
            await createFtsCmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

            // Create triggers to keep FTS5 index in sync
            using var createTriggersCmd = _connection.CreateCommand();
            createTriggersCmd.CommandText = @"
                CREATE TRIGGER IF NOT EXISTS memory_chunks_ai AFTER INSERT ON memory_chunks BEGIN
                    INSERT INTO memory_fts(rowid, content, source)
                    VALUES (new.id, new.content, new.source);
                END;

                CREATE TRIGGER IF NOT EXISTS memory_chunks_ad AFTER DELETE ON memory_chunks BEGIN
                    INSERT INTO memory_fts(memory_fts, rowid, content, source)
                    VALUES('delete', old.id, old.content, old.source);
                END;

                CREATE TRIGGER IF NOT EXISTS memory_chunks_au AFTER UPDATE ON memory_chunks BEGIN
                    INSERT INTO memory_fts(memory_fts, rowid, content, source)
                    VALUES('delete', old.id, old.content, old.source);
                    INSERT INTO memory_fts(rowid, content, source)
                    VALUES (new.id, new.content, new.source);
                END;";
            await createTriggersCmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _dbLock.Release();
        }
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<MemoryResult>> HybridSearchAsync(
        string query,
        int topK = 10,
        CancellationToken cancellationToken = default)
    {
        // For v1, hybrid search is just FTS5 keyword search
        // Vector search will be added in v2
        return await KeywordSearchAsync(query, topK, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Performs keyword search using SQLite FTS5.
    /// </summary>
    /// <param name="query">The search query.</param>
    /// <param name="limit">Maximum number of results to return.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Ranked list of memory results ordered by FTS5 relevance.</returns>
    public async Task<IReadOnlyList<MemoryResult>> KeywordSearchAsync(
        string query,
        int limit = 10,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(query);

        if (limit <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(limit), "Limit must be positive.");
        }

        await EnsureInitializedAsync(cancellationToken).ConfigureAwait(false);

        // Escape FTS5 special characters by wrapping query in double quotes
        // This treats the query as a phrase search which is safer for user input
        var sanitizedQuery = $"\"{query.Replace("\"", "\"\"", StringComparison.Ordinal)}\"";

        await _dbLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var cmd = _connection!.CreateCommand();
            cmd.CommandText = @"
                SELECT
                    mc.id,
                    mc.content,
                    mc.source,
                    mc.created_at,
                    fts.rank
                FROM memory_fts fts
                INNER JOIN memory_chunks mc ON mc.id = fts.rowid
                WHERE memory_fts MATCH $query
                ORDER BY fts.rank
                LIMIT $limit;";
            cmd.Parameters.AddWithValue("$query", sanitizedQuery);
            cmd.Parameters.AddWithValue("$limit", limit);

            var results = new List<MemoryResult>();

            using var reader = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                var id = reader.GetInt64(0);
                var content = reader.GetString(1);
                var source = reader.GetString(2);
                var createdAtText = reader.GetString(3);
                var rank = reader.GetDouble(4);

                // Parse SQLite datetime to DateTimeOffset
                var createdAt = DateTimeOffset.Parse(createdAtText, System.Globalization.CultureInfo.InvariantCulture);

                // Convert FTS5 rank (negative) to positive score
                // Lower rank (more negative) = better match, so negate it
                var score = -rank;

                results.Add(new MemoryResult(id, content, source, createdAt, score));
            }

            return results;
        }
        finally
        {
            _dbLock.Release();
        }
    }

    /// <inheritdoc />
    public async Task<long> StoreAsync(
        string content,
        string source,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(content);
        ArgumentException.ThrowIfNullOrWhiteSpace(source);

        await EnsureInitializedAsync(cancellationToken).ConfigureAwait(false);

        await _dbLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var cmd = _connection!.CreateCommand();
            cmd.CommandText = @"
                INSERT INTO memory_chunks (content, source, chunk_index)
                VALUES ($content, $source, 0);
                SELECT last_insert_rowid();";
            cmd.Parameters.AddWithValue("$content", content);
            cmd.Parameters.AddWithValue("$source", source);

            var id = (long)(await cmd.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false))!;
            return id;
        }
        finally
        {
            _dbLock.Release();
        }
    }

    /// <inheritdoc />
    public async Task<int> ChunkAndIndexAsync(
        string content,
        string source,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(content);
        ArgumentException.ThrowIfNullOrWhiteSpace(source);

        var chunks = _chunker.Chunk(content);

        if (chunks.Count == 0)
        {
            return 0;
        }

        await EnsureInitializedAsync(cancellationToken).ConfigureAwait(false);

        await _dbLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var transaction = await _connection!.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
            using (transaction)
            {
                for (int i = 0; i < chunks.Count; i++)
                {
                    using var cmd = _connection.CreateCommand();
                    cmd.Transaction = (SqliteTransaction)transaction;
                    cmd.CommandText = @"
                        INSERT INTO memory_chunks (content, source, chunk_index)
                        VALUES ($content, $source, $chunkIndex);";
                    cmd.Parameters.AddWithValue("$content", chunks[i]);
                    cmd.Parameters.AddWithValue("$source", source);
                    cmd.Parameters.AddWithValue("$chunkIndex", i);

                    await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
                }

                await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            }

            return chunks.Count;
        }
        finally
        {
            _dbLock.Release();
        }
    }

    /// <summary>
    /// Ensures the database is initialized before use.
    /// </summary>
    private async Task EnsureInitializedAsync(CancellationToken cancellationToken)
    {
        if (_connection == null)
        {
            await InitializeAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _connection?.Dispose();
        _dbLock.Dispose();
        _disposed = true;
        GC.SuppressFinalize(this);
    }
}
