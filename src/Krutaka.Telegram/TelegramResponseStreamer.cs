using System.Text;
using Krutaka.Core;
using Microsoft.Extensions.Logging;
using Telegram.Bot;
using Telegram.Bot.Types.Enums;

namespace Krutaka.Telegram;

/// <summary>
/// Streams agent events to Telegram messages with token buffering, rate limiting, and message chunking.
/// </summary>
public sealed class TelegramResponseStreamer : ITelegramResponseStreamer
{
    private readonly ITelegramBotClient _botClient;
    private readonly ILogger<TelegramResponseStreamer> _logger;

    // Telegram allows ~30 message edits per minute per chat
    private const int MaxEditsPerMinute = 30;
    private const int EditRateLimitWindowMs = 60_000; // 1 minute

    // TextDelta buffering configuration
    private const int BufferFlushIntervalMs = 500; // 500ms
    private const int BufferFlushThresholdChars = 200; // chars

    // Telegram message length limit
    private const int TelegramMaxMessageLength = 4096;

    /// <summary>
    /// Initializes a new instance of the <see cref="TelegramResponseStreamer"/> class.
    /// </summary>
    /// <param name="botClient">The Telegram bot client.</param>
    /// <param name="logger">The logger.</param>
    public TelegramResponseStreamer(
        ITelegramBotClient botClient,
        ILogger<TelegramResponseStreamer> logger)
    {
        ArgumentNullException.ThrowIfNull(botClient);
        ArgumentNullException.ThrowIfNull(logger);

        _botClient = botClient;
        _logger = logger;
    }

    /// <inheritdoc/>
    public async Task StreamResponseAsync(
        long chatId,
        IAsyncEnumerable<AgentEvent> events,
        Func<AgentEvent, Task>? onInteractiveEvent,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(events);

        var textBuffer = new StringBuilder();
        int? currentMessageId = null;
        int? currentToolMessageId = null;
        var lastFlushTime = DateTimeOffset.UtcNow;
        using (var editTracker = new RateLimitTracker(MaxEditsPerMinute, EditRateLimitWindowMs))
        {
            try
            {
                await foreach (var evt in events.WithCancellation(cancellationToken).ConfigureAwait(false))
                {
                    switch (evt)
                    {
                        case TextDelta delta:
                            textBuffer.Append(delta.Text);

                            // Flush buffer if threshold exceeded or timeout elapsed
                            var timeSinceFlush = (DateTimeOffset.UtcNow - lastFlushTime).TotalMilliseconds;
                            if (textBuffer.Length >= BufferFlushThresholdChars || timeSinceFlush >= BufferFlushIntervalMs)
                            {
                                currentMessageId = await FlushTextBufferAsync(
                                    chatId,
                                    textBuffer,
                                    currentMessageId,
                                    editTracker,
                                    cancellationToken).ConfigureAwait(false);

                                lastFlushTime = DateTimeOffset.UtcNow;
                            }

                            break;

                        case ToolCallStarted tool:
                            // Send a new message for tool call status
                            var toolStartText = $"⚙️ Running `{EscapeMarkdownV2(tool.ToolName)}`\\.\\.\\.";
                            var toolMessage = await _botClient.SendMessage(
                                chatId,
                                toolStartText,
                                parseMode: ParseMode.MarkdownV2,
                                cancellationToken: cancellationToken).ConfigureAwait(false);

                            currentToolMessageId = toolMessage.MessageId;
                            break;

                        case ToolCallCompleted tool:
                            // Edit the tool status message to show completion
                            if (currentToolMessageId.HasValue)
                            {
                                var toolCompleteText = $"✅ `{EscapeMarkdownV2(tool.ToolName)}` complete";
                                await EditMessageSafeAsync(
                                    chatId,
                                    currentToolMessageId.Value,
                                    toolCompleteText,
                                    editTracker,
                                    cancellationToken).ConfigureAwait(false);
                            }

                            break;

                        case ToolCallFailed tool:
                            // Edit the tool status message to show failure
                            if (currentToolMessageId.HasValue)
                            {
                                var errorSnippet = tool.Error.Length > 100
                                    ? tool.Error[..100] + "..."
                                    : tool.Error;
                                var toolFailedText = $"❌ `{EscapeMarkdownV2(tool.ToolName)}` failed: {EscapeMarkdownV2(errorSnippet)}";

                                await EditMessageSafeAsync(
                                    chatId,
                                    currentToolMessageId.Value,
                                    toolFailedText,
                                    editTracker,
                                    cancellationToken).ConfigureAwait(false);
                            }

                            break;

                        case FinalResponse final:
                            // Flush any remaining text buffer first
                            if (textBuffer.Length > 0)
                            {
                                await FlushTextBufferAsync(
                                    chatId,
                                    textBuffer,
                                    currentMessageId,
                                    editTracker,
                                    cancellationToken).ConfigureAwait(false);
                            }

                            // Send the final response (may not be in buffer if no TextDeltas were emitted)
                            if (!string.IsNullOrWhiteSpace(final.Content))
                            {
                                await SendChunkedMessageAsync(
                                    chatId,
                                    final.Content,
                                    cancellationToken).ConfigureAwait(false);
                            }

                            break;

                        case HumanApprovalRequired:
                        case DirectoryAccessRequested:
                        case CommandApprovalRequested:
                            // Delegate interactive events to the caller via callback
                            if (onInteractiveEvent != null)
                            {
                                await onInteractiveEvent(evt).ConfigureAwait(false);
                            }

                            break;

                        case RequestIdCaptured:
                            // Silently consumed - used internally by CorrelationContext
                            break;
                    }
                }

                // Final flush if there's any remaining buffered text
                if (textBuffer.Length > 0)
                {
                    await FlushTextBufferAsync(
                        chatId,
                        textBuffer,
                        currentMessageId,
                        editTracker,
                        cancellationToken).ConfigureAwait(false);
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
#pragma warning disable CA1848 // Use the LoggerMessage delegates
                _logger.LogError(ex, "Error streaming response to chat {ChatId}", chatId);
#pragma warning restore CA1848 // Use the LoggerMessage delegates
                throw;
            }
        }
    }

    private async Task<int?> FlushTextBufferAsync(
        long chatId,
        StringBuilder buffer,
        int? messageId,
        RateLimitTracker editTracker,
        CancellationToken cancellationToken)
    {
        if (buffer.Length == 0)
        {
            return messageId;
        }

        var text = buffer.ToString();
        buffer.Clear();

        var formatted = TelegramMarkdownV2Formatter.Format(text);

        if (messageId.HasValue)
        {
            // Edit existing message
            await EditMessageSafeAsync(chatId, messageId.Value, formatted, editTracker, cancellationToken).ConfigureAwait(false);
            return messageId;
        }
        else
        {
            // Send new message
            var message = await _botClient.SendMessage(
                chatId,
                formatted,
                parseMode: ParseMode.MarkdownV2,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            return message.MessageId;
        }
    }

    private async Task EditMessageSafeAsync(
        long chatId,
        int messageId,
        string text,
        RateLimitTracker editTracker,
        CancellationToken cancellationToken)
    {
        // Wait if we're approaching the rate limit
        await editTracker.WaitIfNeededAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            await _botClient.EditMessageText(
                chatId,
                messageId,
                text,
                parseMode: ParseMode.MarkdownV2,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            editTracker.RecordEdit();
        }
#pragma warning disable CA1848 // Use LoggerMessage for performance (acceptable in non-critical error path)
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException or HttpRequestException)
        {
            _logger.LogWarning(ex, "Failed to edit message {MessageId} in chat {ChatId}", messageId, chatId);
            // Continue streaming even if edit fails
        }
#pragma warning restore CA1848
    }

    private async Task SendChunkedMessageAsync(
        long chatId,
        string content,
        CancellationToken cancellationToken)
    {
        var formatted = TelegramMarkdownV2Formatter.Format(content);

        if (formatted.Length <= TelegramMaxMessageLength)
        {
            await _botClient.SendMessage(
                chatId,
                formatted,
                parseMode: ParseMode.MarkdownV2,
                cancellationToken: cancellationToken).ConfigureAwait(false);
            return;
        }

        // Split into chunks, preserving code blocks
        var chunks = SplitIntoChunks(formatted, TelegramMaxMessageLength);

        foreach (var chunk in chunks)
        {
            await _botClient.SendMessage(
                chatId,
                chunk,
                parseMode: ParseMode.MarkdownV2,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            // Brief delay between chunks to avoid rate limiting
            await Task.Delay(100, cancellationToken).ConfigureAwait(false);
        }
    }

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

        foreach (var line in lines)
        {
            // If a single line exceeds maxLength, we need to split it
            if (line.Length > maxLength)
            {
                // Flush current chunk first
                if (currentChunk.Length > 0)
                {
                    chunks.Add(currentChunk.ToString());
                    currentChunk.Clear();
                }

                // Split the long line
                var lineChunks = SplitLongLine(line, maxLength);
                chunks.AddRange(lineChunks);
                continue;
            }

            // Check if adding this line would exceed the limit
            if (currentChunk.Length + line.Length + 1 > maxLength)
            {
                // Flush current chunk
                chunks.Add(currentChunk.ToString());
                currentChunk.Clear();
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

    private static string EscapeMarkdownV2(string text)
    {
        // Use a simple escape for tool names and short strings
        return text.Replace("_", "\\_", StringComparison.Ordinal)
                   .Replace("*", "\\*", StringComparison.Ordinal)
                   .Replace("[", "\\[", StringComparison.Ordinal)
                   .Replace("]", "\\]", StringComparison.Ordinal)
                   .Replace("(", "\\(", StringComparison.Ordinal)
                   .Replace(")", "\\)", StringComparison.Ordinal)
                   .Replace("~", "\\~", StringComparison.Ordinal)
                   .Replace(">", "\\>", StringComparison.Ordinal)
                   .Replace("#", "\\#", StringComparison.Ordinal)
                   .Replace("+", "\\+", StringComparison.Ordinal)
                   .Replace("-", "\\-", StringComparison.Ordinal)
                   .Replace("=", "\\=", StringComparison.Ordinal)
                   .Replace("|", "\\|", StringComparison.Ordinal)
                   .Replace("{", "\\{", StringComparison.Ordinal)
                   .Replace("}", "\\}", StringComparison.Ordinal)
                   .Replace(".", "\\.", StringComparison.Ordinal)
                   .Replace("!", "\\!", StringComparison.Ordinal);
    }

    /// <summary>
    /// Tracks edit operations to enforce Telegram's rate limit of ~30 edits/minute/chat.
    /// </summary>
    private sealed class RateLimitTracker : IDisposable
    {
        private readonly int _maxEdits;
        private readonly int _windowMs;
        private readonly Queue<DateTimeOffset> _editTimestamps = new();
        private readonly SemaphoreSlim _semaphore = new(1, 1);
        private bool _disposed;

        public RateLimitTracker(int maxEdits, int windowMs)
        {
            _maxEdits = maxEdits;
            _windowMs = windowMs;
        }

        public void RecordEdit()
        {
            _editTimestamps.Enqueue(DateTimeOffset.UtcNow);
        }

        public async Task WaitIfNeededAsync(CancellationToken cancellationToken)
        {
            await _semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                // Remove old timestamps outside the window
                var cutoff = DateTimeOffset.UtcNow.AddMilliseconds(-_windowMs);
                while (_editTimestamps.Count > 0 && _editTimestamps.Peek() < cutoff)
                {
                    _editTimestamps.Dequeue();
                }

                // If we're at the limit, wait until the oldest edit expires
                if (_editTimestamps.Count >= _maxEdits)
                {
                    var oldestEdit = _editTimestamps.Peek();
                    var waitTime = oldestEdit.AddMilliseconds(_windowMs) - DateTimeOffset.UtcNow;

                    if (waitTime > TimeSpan.Zero)
                    {
                        await Task.Delay(waitTime, cancellationToken).ConfigureAwait(false);

                        // Remove the expired edit
                        _editTimestamps.Dequeue();
                    }
                }
            }
            finally
            {
                _semaphore.Release();
            }
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _semaphore.Dispose();
            _disposed = true;
        }
    }
}
