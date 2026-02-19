namespace Krutaka.Core;

/// <summary>
/// Manages JSONL-based session persistence for conversation history.
/// Each session is stored as a UUID-named JSONL file with one event per line.
/// </summary>
public interface ISessionStore
{
    /// <summary>
    /// Appends a session event to the JSONL file.
    /// </summary>
    /// <param name="sessionEvent">The event to append.</param>
    /// <param name="cancellationToken">Cancellation token for async operation.</param>
    Task AppendAsync(SessionEvent sessionEvent, CancellationToken cancellationToken = default);

    /// <summary>
    /// Loads all events from the session JSONL file.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token for async operation.</param>
    /// <returns>An async stream of session events.</returns>
    IAsyncEnumerable<SessionEvent> LoadAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Reconstructs the message list from session events.
    /// Converts SessionEvent records back into Claude API message format.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token for async operation.</param>
    /// <returns>The reconstructed message list.</returns>
    Task<IReadOnlyList<object>> ReconstructMessagesAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Saves session metadata (start time, project path, model used).
    /// </summary>
    /// <param name="projectPath">The project path for this session.</param>
    /// <param name="modelId">The model identifier used in this session.</param>
    /// <param name="cancellationToken">Cancellation token for async operation.</param>
    Task SaveMetadataAsync(string projectPath, string modelId, CancellationToken cancellationToken = default);
}
