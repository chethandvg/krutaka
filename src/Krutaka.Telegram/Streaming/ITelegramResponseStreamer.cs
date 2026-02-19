using Krutaka.Core;

namespace Krutaka.Telegram;

/// <summary>
/// Streams agent events to Telegram messages with rate limiting and formatting.
/// </summary>
public interface ITelegramResponseStreamer
{
    /// <summary>
    /// Streams agent events to a Telegram chat, translating events into message edits and status updates.
    /// </summary>
    /// <param name="chatId">The Telegram chat ID to send messages to.</param>
    /// <param name="events">The stream of agent events to process.</param>
    /// <param name="onInteractiveEvent">Optional callback invoked when an interactive event (HumanApprovalRequired, DirectoryAccessRequested, CommandApprovalRequested) is encountered. The callback receives the event for external handling.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task that completes when streaming is finished.</returns>
    Task StreamResponseAsync(
        long chatId,
        IAsyncEnumerable<AgentEvent> events,
        Func<AgentEvent, Task>? onInteractiveEvent,
        CancellationToken cancellationToken);
}
