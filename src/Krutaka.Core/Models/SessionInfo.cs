namespace Krutaka.Core;

/// <summary>
/// Metadata about a session file.
/// </summary>
/// <param name="SessionId">The unique session identifier.</param>
/// <param name="FilePath">Full path to the session .jsonl file.</param>
/// <param name="LastModified">When the session was last modified.</param>
/// <param name="MessageCount">Number of non-metadata messages in the session.</param>
/// <param name="FirstUserMessage">Preview of the first user message (truncated to 50 chars).</param>
public sealed record SessionInfo(
    Guid SessionId,
    string FilePath,
    DateTimeOffset LastModified,
    int MessageCount,
    string? FirstUserMessage
);
