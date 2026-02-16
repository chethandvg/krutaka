using System.Text;
using Krutaka.Core;
using Microsoft.Extensions.Logging;
using Telegram.Bot;
using Telegram.Bot.Types.Enums;

namespace Krutaka.Telegram;

/// <summary>
/// Streams agent events to Telegram messages with token buffering, rate limiting, and message chunking.
/// </summary>
public sealed partial class TelegramResponseStreamer : ITelegramResponseStreamer
{
    private readonly ITelegramBotClient _botClient;
    private readonly ILogger<TelegramResponseStreamer> _logger;

    // Telegram allows ~30 message edits per minute per chat
    private const int MaxEditsPerMinute = 30;
    private const int EditRateLimitWindowMs = 60_000; // 1 minute

    // TextDelta buffering configuration
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
        cancellationToken.ThrowIfCancellationRequested();

        var textBuffer = new StringBuilder();
        var fullAccumulatedText = new StringBuilder();
        int? currentMessageId = null;
        var toolStatusMessages = new Dictionary<string, int>();
        
        // Get or create per-chat rate limiter (shared across all concurrent calls for this chat)
        var editTracker = _perChatRateLimiters.GetOrAdd(chatId, _ => new RateLimitTracker(MaxEditsPerMinute, EditRateLimitWindowMs));

        try
        {
            await foreach (var evt in events.WithCancellation(cancellationToken).ConfigureAwait(false))
            {
                switch (evt)
                {
                    case TextDelta delta:
                        textBuffer.Append(delta.Text);

                        // Flush buffer if threshold exceeded
                        if (textBuffer.Length >= BufferFlushThresholdChars)
                        {
                            currentMessageId = await FlushTextBufferAsync(
                                chatId,
                                textBuffer,
                                fullAccumulatedText,
                                currentMessageId,
                                editTracker,
                                cancellationToken).ConfigureAwait(false);
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

                        toolStatusMessages[tool.ToolUseId] = toolMessage.MessageId;
                        break;

                    case ToolCallCompleted tool:
                        // Edit the tool status message to show completion
                        if (toolStatusMessages.TryGetValue(tool.ToolUseId, out var completedMessageId))
                        {
                            var toolCompleteText = $"✅ `{EscapeMarkdownV2(tool.ToolName)}` complete";
                            await EditMessageSafeAsync(
                                chatId,
                                completedMessageId,
                                toolCompleteText,
                                editTracker,
                                cancellationToken).ConfigureAwait(false);
                        }

                        break;

                    case ToolCallFailed tool:
                        // Edit the tool status message to show failure
                        if (toolStatusMessages.TryGetValue(tool.ToolUseId, out var failedMessageId))
                        {
                            var errorSnippet = tool.Error.Length > 100
                                ? tool.Error[..100] + "..."
                                : tool.Error;
                            var toolFailedText = $"❌ `{EscapeMarkdownV2(tool.ToolName)}` failed: {EscapeMarkdownV2(errorSnippet)}";

                            await EditMessageSafeAsync(
                                chatId,
                                failedMessageId,
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
                                fullAccumulatedText,
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
                    fullAccumulatedText,
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

    /// <summary>
    /// Flushes the text buffer to Telegram, editing the existing message with the full accumulated text.
    /// </summary>
    private async Task<int?> FlushTextBufferAsync(
        long chatId,
        StringBuilder buffer,
        StringBuilder fullAccumulatedText,
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

        // Append to full accumulated text
        fullAccumulatedText.Append(text);

        var formatted = TelegramMarkdownV2Formatter.Format(fullAccumulatedText.ToString()) ?? string.Empty;

        if (messageId.HasValue)
        {
            // Edit existing message with full accumulated text
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
        var formatted = TelegramMarkdownV2Formatter.Format(content) ?? content;

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
}
