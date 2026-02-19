namespace Krutaka.Memory;

/// <summary>
/// Splits text into chunks with overlap for better search recall.
/// Uses word-based chunking as a proxy for token chunking.
/// </summary>
public sealed class TextChunker
{
    private readonly int _chunkSizeTokens;
    private readonly int _chunkOverlapTokens;

    /// <summary>
    /// Initializes a new instance of the <see cref="TextChunker"/> class.
    /// </summary>
    /// <param name="chunkSizeTokens">Target chunk size in tokens (approximated by words).</param>
    /// <param name="chunkOverlapTokens">Overlap size in tokens between consecutive chunks.</param>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when chunk size or overlap is invalid.</exception>
    public TextChunker(int chunkSizeTokens = 500, int chunkOverlapTokens = 50)
    {
        if (chunkSizeTokens <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(chunkSizeTokens), "Chunk size must be positive.");
        }

        if (chunkOverlapTokens < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(chunkOverlapTokens), "Chunk overlap cannot be negative.");
        }

        if (chunkOverlapTokens >= chunkSizeTokens)
        {
            throw new ArgumentOutOfRangeException(nameof(chunkOverlapTokens), "Chunk overlap must be less than chunk size.");
        }

        _chunkSizeTokens = chunkSizeTokens;
        _chunkOverlapTokens = chunkOverlapTokens;
    }

    /// <summary>
    /// Chunks the given text into overlapping segments.
    /// </summary>
    /// <param name="text">The text to chunk.</param>
    /// <returns>A list of text chunks.</returns>
    /// <exception cref="ArgumentNullException">Thrown when text is null.</exception>
    public IReadOnlyList<string> Chunk(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        if (string.IsNullOrWhiteSpace(text))
        {
            return [];
        }

        // Split text into words (whitespace-separated tokens)
        // This is a simple approximation; real tokenization would use BPE/WordPiece
        var words = text.Split(
            [' ', '\t', '\n', '\r'],
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        if (words.Length == 0)
        {
            return [];
        }

        // If the entire text fits in one chunk, return it normalized
        if (words.Length <= _chunkSizeTokens)
        {
            return [string.Join(' ', words)];
        }

        var chunks = new List<string>();
        var stepSize = _chunkSizeTokens - _chunkOverlapTokens;

        for (int start = 0; start < words.Length; start += stepSize)
        {
            var end = Math.Min(start + _chunkSizeTokens, words.Length);
            var chunkWords = words[start..end];
            var chunk = string.Join(' ', chunkWords);
            chunks.Add(chunk);

            // If this chunk includes the last word, we're done
            if (end >= words.Length)
            {
                break;
            }
        }

        return chunks;
    }
}
