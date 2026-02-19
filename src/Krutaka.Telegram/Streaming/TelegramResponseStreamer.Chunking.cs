using System.Text;

namespace Krutaka.Telegram;

/// <summary>
/// Message chunking partial for TelegramResponseStreamer.
/// </summary>
public sealed partial class TelegramResponseStreamer
{
    /// <summary>
    /// Splits text into chunks, tracking code fences to avoid breaking markdown.
    /// Ensures chunks don't break inside ``` fenced code blocks.
    /// </summary>
    private static List<string> SplitIntoChunks(string text, int maxLength)
    {
        var chunks = new List<string>();

        if (text.Length <= maxLength)
        {
            chunks.Add(text);
            return chunks;
        }

        var currentChunk = new StringBuilder();
        var lines = text.Split('\n');
        var inCodeBlock = false;
        string? codeFenceOpener = null;

        foreach (var line in lines)
        {
            // Detect code fence toggles (``` or ~~~)
            var trimmed = line.TrimStart();
            if (trimmed.StartsWith("```", StringComparison.Ordinal))
            {
                if (!inCodeBlock)
                {
                    codeFenceOpener = line;
                }
                else
                {
                    codeFenceOpener = null;
                }

                inCodeBlock = !inCodeBlock;
            }

            // If a single line exceeds maxLength, we need to split it
            if (line.Length > maxLength)
            {
                // Flush current chunk first, closing code fence if needed
                if (currentChunk.Length > 0)
                {
                    if (inCodeBlock)
                    {
                        currentChunk.Append("\n```");
                    }

                    chunks.Add(currentChunk.ToString());
                    currentChunk.Clear();

                    // Reopen code fence in next chunk
                    if (inCodeBlock && codeFenceOpener != null)
                    {
                        currentChunk.Append(codeFenceOpener).Append('\n');
                    }
                }

                // Split the long line
                chunks.AddRange(SplitLongLine(line, maxLength));
                continue;
            }

            // Check if adding this line would exceed the limit
            if (currentChunk.Length + line.Length + 1 > maxLength)
            {
                // Close code fence if we're inside one
                if (inCodeBlock)
                {
                    currentChunk.Append("\n```");
                }

                // Flush current chunk
                chunks.Add(currentChunk.ToString());
                currentChunk.Clear();

                // Reopen code fence in next chunk
                if (inCodeBlock && codeFenceOpener != null)
                {
                    currentChunk.Append(codeFenceOpener).Append('\n');
                }
            }

            if (currentChunk.Length > 0)
            {
                currentChunk.Append('\n');
            }

            currentChunk.Append(line);
        }

        // Add final chunk
        if (currentChunk.Length > 0)
        {
            chunks.Add(currentChunk.ToString());
        }

        return chunks;
    }

    private static List<string> SplitLongLine(string line, int maxLength)
    {
        var chunks = new List<string>();
        var remaining = line;

        while (remaining.Length > maxLength)
        {
            // Try to split at a space near maxLength
            var splitIndex = remaining.LastIndexOf(' ', maxLength);
            if (splitIndex <= 0)
            {
                splitIndex = maxLength;
            }

            chunks.Add(remaining[..splitIndex]);
            remaining = remaining[splitIndex..].TrimStart();
        }

        if (remaining.Length > 0)
        {
            chunks.Add(remaining);
        }

        return chunks;
    }
}
