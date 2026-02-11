using FluentAssertions;
using Krutaka.Memory;

namespace Krutaka.Memory.Tests;

internal sealed class TextChunkerTests
{
    [Fact]
    public void Should_ThrowWhenChunkSizeIsZero()
    {
        // Act
        var act = () => new TextChunker(chunkSizeTokens: 0);

        // Assert
        act.Should().Throw<ArgumentOutOfRangeException>()
            .WithParameterName("chunkSizeTokens");
    }

    [Fact]
    public void Should_ThrowWhenChunkSizeIsNegative()
    {
        // Act
        var act = () => new TextChunker(chunkSizeTokens: -1);

        // Assert
        act.Should().Throw<ArgumentOutOfRangeException>()
            .WithParameterName("chunkSizeTokens");
    }

    [Fact]
    public void Should_ThrowWhenOverlapIsNegative()
    {
        // Act
        var act = () => new TextChunker(chunkSizeTokens: 100, chunkOverlapTokens: -1);

        // Assert
        act.Should().Throw<ArgumentOutOfRangeException>()
            .WithParameterName("chunkOverlapTokens");
    }

    [Fact]
    public void Should_ThrowWhenOverlapIsGreaterThanOrEqualToChunkSize()
    {
        // Act
        var act = () => new TextChunker(chunkSizeTokens: 100, chunkOverlapTokens: 100);

        // Assert
        act.Should().Throw<ArgumentOutOfRangeException>()
            .WithParameterName("chunkOverlapTokens");
    }

    [Fact]
    public void Should_ThrowWhenTextIsNull()
    {
        // Arrange
        var chunker = new TextChunker();

        // Act
        var act = () => chunker.Chunk(null!);

        // Assert
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("text");
    }

    [Fact]
    public void Should_ReturnEmptyListForEmptyText()
    {
        // Arrange
        var chunker = new TextChunker();

        // Act
        var result = chunker.Chunk(string.Empty);

        // Assert
        result.Should().BeEmpty();
    }

    [Fact]
    public void Should_ReturnEmptyListForWhitespaceOnlyText()
    {
        // Arrange
        var chunker = new TextChunker();

        // Act
        var result = chunker.Chunk("   \t\n\r   ");

        // Assert
        result.Should().BeEmpty();
    }

    [Fact]
    public void Should_ReturnSingleChunkWhenTextIsSmallerThanChunkSize()
    {
        // Arrange
        var chunker = new TextChunker(chunkSizeTokens: 100, chunkOverlapTokens: 10);
        var text = "This is a short text with only a few words.";

        // Act
        var result = chunker.Chunk(text);

        // Assert
        result.Should().HaveCount(1);
        result[0].Should().Be("This is a short text with only a few words.");
    }

    [Fact]
    public void Should_CreateMultipleChunksWithOverlap()
    {
        // Arrange
        var chunker = new TextChunker(chunkSizeTokens: 5, chunkOverlapTokens: 2);
        var text = "one two three four five six seven eight nine ten";

        // Act
        var result = chunker.Chunk(text);

        // Assert
        // With chunk size 5 and overlap 2, step size is 3
        // Chunk 0: words 0-4 (one two three four five)
        // Chunk 1: words 3-7 (four five six seven eight)
        // Chunk 2: words 6-10 (seven eight nine ten)
        result.Should().HaveCount(3);
        result[0].Should().Be("one two three four five");
        result[1].Should().Be("four five six seven eight");
        result[2].Should().Be("seven eight nine ten");
    }

    [Fact]
    public void Should_HandleTextExactlyAtChunkSize()
    {
        // Arrange
        var chunker = new TextChunker(chunkSizeTokens: 5, chunkOverlapTokens: 0);
        var text = "one two three four five";

        // Act
        var result = chunker.Chunk(text);

        // Assert
        result.Should().HaveCount(1);
        result[0].Should().Be("one two three four five");
    }

    [Fact]
    public void Should_HandleTextWithMultipleWhitespaceTypes()
    {
        // Arrange
        var chunker = new TextChunker(chunkSizeTokens: 10, chunkOverlapTokens: 2);
        var text = "word1\tword2\nword3\r\nword4  word5";

        // Act
        var result = chunker.Chunk(text);

        // Assert
        result.Should().HaveCount(1);
        result[0].Should().Be("word1 word2 word3 word4 word5");
    }

    [Fact]
    public void Should_CreateChunksWithCorrectOverlapSize()
    {
        // Arrange
        var chunker = new TextChunker(chunkSizeTokens: 10, chunkOverlapTokens: 3);
        var words = Enumerable.Range(1, 25).Select(i => $"word{i}").ToArray();
        var text = string.Join(' ', words);

        // Act
        var result = chunker.Chunk(text);

        // Assert
        // With chunk size 10 and overlap 3, step size is 7
        // Chunk 0: words 1-10
        // Chunk 1: words 8-17 (overlap of 3 words: 8, 9, 10)
        // Chunk 2: words 15-24 (overlap of 3 words: 15, 16, 17)
        // Chunk 3: words 22-25 (overlap of 3 words: 22, 23, 24)
        result.Should().HaveCount(4);
        result[0].Should().StartWith("word1");
        result[0].Should().EndWith("word10");
        result[1].Should().StartWith("word8");
        result[1].Should().EndWith("word17");
    }

    [Fact]
    public void Should_HandleDefaultParameters()
    {
        // Arrange
        var chunker = new TextChunker();

        // Act - Create text with 600 words
        var words = Enumerable.Range(1, 600).Select(i => $"word{i}").ToArray();
        var text = string.Join(' ', words);
        var result = chunker.Chunk(text);

        // Assert - With 500 chunk size and 50 overlap, step is 450
        // 600 words should create 2 chunks: [1-500], [451-600]
        result.Should().HaveCount(2);
        result[0].Should().StartWith("word1");
        result[0].Should().EndWith("word500");
        result[1].Should().StartWith("word451");
        result[1].Should().EndWith("word600");
    }

    [Theory]
    [InlineData(10, 0, 1)] // No overlap - 10 words fit in one chunk of size 10
    [InlineData(5, 1, 3)]   // Small overlap - chunk size 5, overlap 1, step 4: [0-4], [4-8], [8-9]
    [InlineData(3, 2, 8)]   // Large overlap - chunk size 3, overlap 2, step 1: each word starts a new chunk
    public void Should_CreateExpectedNumberOfChunks(int chunkSize, int overlap, int expectedChunks)
    {
        // Arrange
        var chunker = new TextChunker(chunkSizeTokens: chunkSize, chunkOverlapTokens: overlap);
        var text = "one two three four five six seven eight nine ten";

        // Act
        var result = chunker.Chunk(text);

        // Assert
        result.Should().HaveCount(expectedChunks);
    }
}
