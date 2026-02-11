using FluentAssertions;
using Krutaka.Core;
using Krutaka.Memory;

namespace Krutaka.Memory.Tests;

internal sealed class SqliteMemoryStoreTests : IDisposable
{
    private readonly string _testDbPath;
    private readonly SqliteMemoryStore _store;

    public SqliteMemoryStoreTests()
    {
        // Use in-memory database for tests
        _testDbPath = ":memory:";
        var options = new MemoryOptions
        {
            DatabasePath = _testDbPath,
            ChunkSizeTokens = 10,
            ChunkOverlapTokens = 2
        };
        _store = new SqliteMemoryStore(options);
    }

    public void Dispose()
    {
        _store.Dispose();
        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task Should_InitializeDatabase()
    {
        // Act
        await _store.InitializeAsync();

        // Assert - No exception means success
        // The database should be ready for use
    }

    [Fact]
    public async Task Should_StoreAndRetrieveContent()
    {
        // Arrange
        await _store.InitializeAsync();
        var content = "This is a test memory entry about C# programming.";
        var source = "test-source";

        // Act
        var id = await _store.StoreAsync(content, source);

        // Assert
        id.Should().BeGreaterThan(0);
    }

    [Fact]
    public async Task Should_PerformKeywordSearch()
    {
        // Arrange
        await _store.InitializeAsync();
        await _store.StoreAsync("C# is a powerful programming language.", "doc1");
        await _store.StoreAsync("Python is great for scripting.", "doc2");
        await _store.StoreAsync("C# has excellent tooling support.", "doc3");

        // Act
        var results = await _store.KeywordSearchAsync("C#", limit: 10);

        // Assert
        results.Should().HaveCount(2);
        results.Should().AllSatisfy(r =>
        {
            r.Content.Should().Contain("C#");
            r.Score.Should().BeGreaterThan(0);
        });
    }

    [Fact]
    public async Task Should_RankResultsByRelevance()
    {
        // Arrange
        await _store.InitializeAsync();
        await _store.StoreAsync("C# programming language", "doc1");
        await _store.StoreAsync("C# is used for .NET development", "doc2");
        await _store.StoreAsync("Python programming", "doc3");

        // Act
        var results = await _store.KeywordSearchAsync("C# programming", limit: 10);

        // Assert
        results.Should().HaveCountGreaterThan(0);
        results[0].Content.Should().Contain("C#");

        // Verify scores are in descending order (higher score = better match)
        for (int i = 0; i < results.Count - 1; i++)
        {
            results[i].Score.Should().BeGreaterThanOrEqualTo(results[i + 1].Score);
        }
    }

    [Fact]
    public async Task Should_RespectSearchLimit()
    {
        // Arrange
        await _store.InitializeAsync();
        for (int i = 0; i < 10; i++)
        {
            await _store.StoreAsync($"Test content number {i}", $"source{i}");
        }

        // Act
        var results = await _store.KeywordSearchAsync("Test", limit: 5);

        // Assert
        results.Should().HaveCount(5);
    }

    [Fact]
    public async Task Should_ChunkAndIndexLargeText()
    {
        // Arrange
        await _store.InitializeAsync();
        var words = Enumerable.Range(1, 25).Select(i => $"word{i}");
        var content = string.Join(' ', words);
        var source = "large-doc";

        // Act
        var chunkCount = await _store.ChunkAndIndexAsync(content, source);

        // Assert - With chunk size 10 and overlap 2, 25 words should create 3 chunks
        chunkCount.Should().Be(3);

        // Verify all chunks are searchable
        var results = await _store.KeywordSearchAsync("word1", limit: 10);
        results.Should().HaveCountGreaterThan(0);
        results.Should().Contain(r => r.Source == source);
    }

    [Fact]
    public async Task Should_HandleMultipleChunksFromSameSource()
    {
        // Arrange
        await _store.InitializeAsync();
        var words = Enumerable.Range(1, 30).Select(i => $"word{i}");
        var content = string.Join(' ', words);

        // Act
        var chunkCount = await _store.ChunkAndIndexAsync(content, "multi-chunk-doc");

        // Assert
        chunkCount.Should().BeGreaterThan(1);

        // Search for word1 OR word30 (not as phrase)
        var results = await _store.KeywordSearchAsync("word1", limit: 10);
        results.Should().HaveCountGreaterThan(0);
    }

    [Fact]
    public async Task Should_ReturnEmptyResultsForNoMatches()
    {
        // Arrange
        await _store.InitializeAsync();
        await _store.StoreAsync("C# programming", "doc1");

        // Act
        var results = await _store.KeywordSearchAsync("Python", limit: 10);

        // Assert
        results.Should().BeEmpty();
    }

    [Fact]
    public async Task Should_HandleEmptyQuery()
    {
        // Arrange
        await _store.InitializeAsync();

        // Act
        var act = async () => await _store.KeywordSearchAsync(string.Empty);

        // Assert
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task Should_HandleNullQuery()
    {
        // Arrange
        await _store.InitializeAsync();

        // Act
        var act = async () => await _store.KeywordSearchAsync(null!);

        // Assert
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task Should_HandleInvalidLimit()
    {
        // Arrange
        await _store.InitializeAsync();

        // Act
        var act = async () => await _store.KeywordSearchAsync("test", limit: 0);

        // Assert
        await act.Should().ThrowAsync<ArgumentOutOfRangeException>();
    }

    [Fact]
    public async Task Should_ThrowWhenStoreAsyncContentIsNull()
    {
        // Arrange
        await _store.InitializeAsync();

        // Act
        var act = async () => await _store.StoreAsync(null!, "source");

        // Assert
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task Should_ThrowWhenStoreAsyncSourceIsNull()
    {
        // Arrange
        await _store.InitializeAsync();

        // Act
        var act = async () => await _store.StoreAsync("content", null!);

        // Assert
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task Should_ThrowWhenChunkAndIndexContentIsNull()
    {
        // Arrange
        await _store.InitializeAsync();

        // Act
        var act = async () => await _store.ChunkAndIndexAsync(null!, "source");

        // Assert
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task Should_ThrowWhenChunkAndIndexSourceIsNull()
    {
        // Arrange
        await _store.InitializeAsync();

        // Act
        var act = async () => await _store.ChunkAndIndexAsync("content", null!);

        // Assert
        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task Should_AutoInitializeOnFirstUse()
    {
        // Arrange - Don't call InitializeAsync explicitly

        // Act
        var id = await _store.StoreAsync("Auto-init test", "source");

        // Assert
        id.Should().BeGreaterThan(0);
    }

    [Fact]
    public async Task Should_HandlePorterStemming()
    {
        // Arrange
        await _store.InitializeAsync();
        await _store.StoreAsync("The programmer is programming in C#.", "doc1");

        // Act - Porter stemmer should match "program" with "programmer" and "programming"
        var results = await _store.KeywordSearchAsync("program", limit: 10);

        // Assert
        results.Should().HaveCount(1);
        results[0].Content.Should().Contain("programming");
    }

    [Fact]
    public async Task Should_HybridSearchDelegateToKeywordSearch()
    {
        // Arrange
        await _store.InitializeAsync();
        await _store.StoreAsync("C# programming language", "doc1");

        // Act - For v1, HybridSearchAsync should behave like KeywordSearchAsync
        var keywordResults = await _store.KeywordSearchAsync("C#", limit: 10);
        var hybridResults = await _store.HybridSearchAsync("C#", topK: 10);

        // Assert
        hybridResults.Should().HaveCount(keywordResults.Count);
        hybridResults.Should().BeEquivalentTo(keywordResults);
    }

    [Fact]
    public async Task Should_ReturnZeroChunksForEmptyContent()
    {
        // Arrange
        await _store.InitializeAsync();

        // Act
        var chunkCount = await _store.ChunkAndIndexAsync("   ", "empty-source");

        // Assert
        chunkCount.Should().Be(0);
    }

    [Fact]
    public async Task Should_IncludeCreatedAtTimestamp()
    {
        // Arrange
        await _store.InitializeAsync();
        var beforeStore = DateTimeOffset.UtcNow.AddSeconds(-1);
        await _store.StoreAsync("Timestamped content", "source");
        var afterStore = DateTimeOffset.UtcNow.AddSeconds(1);

        // Act
        var results = await _store.KeywordSearchAsync("Timestamped", limit: 10);

        // Assert
        results.Should().HaveCount(1);
        results[0].CreatedAt.Should().BeAfter(beforeStore);
        results[0].CreatedAt.Should().BeBefore(afterStore);
    }

    [Fact]
    public async Task Should_IncludeSourceInResults()
    {
        // Arrange
        await _store.InitializeAsync();
        var source = "specific-source-identifier";
        await _store.StoreAsync("Content with source", source);

        // Act
        var results = await _store.KeywordSearchAsync("Content", limit: 10);

        // Assert
        results.Should().HaveCount(1);
        results[0].Source.Should().Be(source);
    }

    [Fact]
    public void Should_ThrowWhenConstructorOptionsHasNullDatabasePath()
    {
        // Arrange
        var options = new MemoryOptions { DatabasePath = null! };

        // Act
        var act = () => new SqliteMemoryStore(options);

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithParameterName("DatabasePath");
    }

    [Fact]
    public void Should_ThrowWhenConstructorOptionsHasEmptyDatabasePath()
    {
        // Arrange
        var options = new MemoryOptions { DatabasePath = string.Empty };

        // Act
        var act = () => new SqliteMemoryStore(options);

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithParameterName("DatabasePath");
    }

    [Fact]
    public void Should_ThrowWhenConstructorOptionsHasWhitespaceDatabasePath()
    {
        // Arrange
        var options = new MemoryOptions { DatabasePath = "   " };

        // Act
        var act = () => new SqliteMemoryStore(options);

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithParameterName("DatabasePath");
    }

    [Fact]
    public async Task Should_ThrowObjectDisposedExceptionWhenInitializeCalledAfterDispose()
    {
        // Arrange
        var options = new MemoryOptions { DatabasePath = ":memory:" };
        var store = new SqliteMemoryStore(options);
        store.Dispose();

        // Act
        var act = async () => await store.InitializeAsync();

        // Assert
        await act.Should().ThrowAsync<ObjectDisposedException>();
    }

    [Fact]
    public async Task Should_ThrowObjectDisposedExceptionWhenStoreAsyncCalledAfterDispose()
    {
        // Arrange
        var options = new MemoryOptions { DatabasePath = ":memory:" };
        var store = new SqliteMemoryStore(options);
        store.Dispose();

        // Act
        var act = async () => await store.StoreAsync("content", "source");

        // Assert
        await act.Should().ThrowAsync<ObjectDisposedException>();
    }

    [Fact]
    public async Task Should_ThrowObjectDisposedExceptionWhenChunkAndIndexAsyncCalledAfterDispose()
    {
        // Arrange
        var options = new MemoryOptions { DatabasePath = ":memory:" };
        var store = new SqliteMemoryStore(options);
        store.Dispose();

        // Act
        var act = async () => await store.ChunkAndIndexAsync("content", "source");

        // Assert
        await act.Should().ThrowAsync<ObjectDisposedException>();
    }

    [Fact]
    public async Task Should_ThrowObjectDisposedExceptionWhenKeywordSearchAsyncCalledAfterDispose()
    {
        // Arrange
        var options = new MemoryOptions { DatabasePath = ":memory:" };
        var store = new SqliteMemoryStore(options);
        store.Dispose();

        // Act
        var act = async () => await store.KeywordSearchAsync("query");

        // Assert
        await act.Should().ThrowAsync<ObjectDisposedException>();
    }

    [Fact]
    public async Task Should_ThrowObjectDisposedExceptionWhenHybridSearchAsyncCalledAfterDispose()
    {
        // Arrange
        var options = new MemoryOptions { DatabasePath = ":memory:" };
        var store = new SqliteMemoryStore(options);
        store.Dispose();

        // Act
        var act = async () => await store.HybridSearchAsync("query");

        // Assert
        await act.Should().ThrowAsync<ObjectDisposedException>();
    }
}
