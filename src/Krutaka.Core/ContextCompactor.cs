using System.Globalization;

namespace Krutaka.Core;

/// <summary>
/// Provides context window compaction when token count exceeds threshold.
/// Uses the configured Claude client to generate conversation summaries and replaces old messages
/// with summary + acknowledgment + last N message pairs.
/// </summary>
public sealed class ContextCompactor
{
    private readonly IClaudeClient _claudeClient;
    private readonly IClaudeClient _compactionClient;
    private readonly IAuditLogger? _auditLogger;
    private readonly CorrelationContext? _correlationContext;
    private readonly int _maxTokens;
    private readonly double _compactionThreshold;
    private readonly int _messagesToKeep;

    /// <summary>
    /// Initializes a new instance of the <see cref="ContextCompactor"/> class.
    /// </summary>
    /// <param name="claudeClient">The Claude API client used for token counting.</param>
    /// <param name="maxTokens">Maximum context window size (default: 200,000).</param>
    /// <param name="compactionThreshold">Threshold percentage for compaction (default: 0.80 = 80%).</param>
    /// <param name="messagesToKeep">Number of recent messages to keep after compaction (default: 6 = 3 pairs).</param>
    /// <param name="auditLogger">Optional audit logger for structured logging.</param>
    /// <param name="correlationContext">Optional correlation context for request tracing.</param>
    /// <param name="compactionClient">Optional separate Claude client for generating summaries (e.g., using a cheaper model). Defaults to the main client.</param>
    public ContextCompactor(
        IClaudeClient claudeClient,
        int maxTokens = 200_000,
        double compactionThreshold = 0.80,
        int messagesToKeep = 6,
        IAuditLogger? auditLogger = null,
        CorrelationContext? correlationContext = null,
        IClaudeClient? compactionClient = null)
    {
        _claudeClient = claudeClient ?? throw new ArgumentNullException(nameof(claudeClient));
        _compactionClient = compactionClient ?? claudeClient;
        _auditLogger = auditLogger;
        _correlationContext = correlationContext;
        _maxTokens = maxTokens;
        _compactionThreshold = compactionThreshold;
        _messagesToKeep = messagesToKeep;
    }

    /// <summary>
    /// Checks if compaction is needed based on current token count.
    /// </summary>
    /// <param name="currentTokenCount">The current token count.</param>
    /// <returns>True if compaction should be triggered, false otherwise.</returns>
    public bool ShouldCompact(int currentTokenCount)
    {
        var threshold = (int)(_maxTokens * _compactionThreshold);
        return currentTokenCount > threshold;
    }

    /// <summary>
    /// Compacts the conversation history by summarizing old messages and keeping recent ones.
    /// </summary>
    /// <param name="messages">The current conversation messages.</param>
    /// <param name="systemPrompt">The system prompt used for the conversation.</param>
    /// <param name="currentTokenCount">The current token count before compaction.</param>
    /// <param name="cancellationToken">Cancellation token for async operation.</param>
    /// <returns>The compacted message list with metadata about the compaction operation.</returns>
    public async Task<CompactionResult> CompactAsync(
        IReadOnlyList<object> messages,
        string systemPrompt,
        int currentTokenCount,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(messages);
        ArgumentNullException.ThrowIfNull(systemPrompt);

        // Short-circuit if there are no messages to summarize
        if (messages.Count <= _messagesToKeep)
        {
            return new CompactionResult(
                OriginalMessageCount: messages.Count,
                CompactedMessageCount: messages.Count,
                MessagesRemoved: 0,
                OriginalTokenCount: currentTokenCount,
                CompactedTokenCount: currentTokenCount,
                Summary: string.Empty,
                CompactedMessages: messages);
        }

        // Keep last N messages
        var messagesToSummarize = messages.Take(messages.Count - _messagesToKeep).ToList();
        var messagesToKeep = messages.Skip(messagesToSummarize.Count).ToList();

        // Generate summary using configured model
        var summary = await GenerateSummaryAsync(messagesToSummarize, cancellationToken).ConfigureAwait(false);

        // Build compacted message list
        var compactedMessages = new List<object>();

        // Add summary as user message
        compactedMessages.Add(new
        {
            role = "user",
            content = $"[Previous conversation summary]\n{summary}"
        });

        // Check the role of the first kept message to maintain alternation
        var firstKeptRole = GetMessageRole(messagesToKeep[0]);

        // Only add assistant acknowledgment if the first kept message is from user
        // This prevents consecutive assistant messages
        if (firstKeptRole == "user")
        {
            compactedMessages.Add(new
            {
                role = "assistant",
                content = "Understood. I have the context from our previous discussion."
            });
        }

        // Add recent messages
        compactedMessages.AddRange(messagesToKeep);

        // Count tokens in compacted conversation
        var newTokenCount = await _claudeClient.CountTokensAsync(compactedMessages, systemPrompt, cancellationToken).ConfigureAwait(false);

        // Calculate messages removed (from the original conversation, not counting added summary messages)
        var messagesRemoved = messagesToSummarize.Count;

        // Log compaction event (only if audit logger and correlation context are provided)
        if (_auditLogger != null && _correlationContext != null)
        {
            _auditLogger.LogCompaction(
                _correlationContext,
                currentTokenCount,
                newTokenCount,
                messagesRemoved);
        }

        return new CompactionResult(
            OriginalMessageCount: messages.Count,
            CompactedMessageCount: compactedMessages.Count,
            MessagesRemoved: messagesRemoved,
            OriginalTokenCount: currentTokenCount,
            CompactedTokenCount: newTokenCount,
            Summary: summary,
            CompactedMessages: compactedMessages);
    }

    /// <summary>
    /// Gets the role from a message object.
    /// </summary>
    private static string GetMessageRole(object message)
    {
        var roleProperty = message.GetType().GetProperty("role");
        return roleProperty?.GetValue(message)?.ToString() ?? "user";
    }

    /// <summary>
    /// Generates a conversation summary using the configured Claude client.
    /// Focuses on preserving file paths, action items, technical decisions, and error context.
    /// </summary>
    private async Task<string> GenerateSummaryAsync(
        IReadOnlyList<object> messages,
        CancellationToken cancellationToken)
    {
        var summaryPrompt = @"Summarize the key points, decisions, and context from the provided conversation history. 

Focus on preserving:
1. **File paths** mentioned or modified
2. **Action items** and tasks completed or pending
3. **Technical decisions** made (architecture, design, implementation choices)
4. **Error context** and debugging insights
5. **Key outcomes** from tool executions

Provide a concise but comprehensive summary that captures all essential information needed to continue the conversation effectively.";

        // Create a single-turn conversation for summarization
        var summarizationMessages = new List<object>
        {
            new
            {
                role = "user",
                content = $"{summaryPrompt}\n\n<untrusted_content>\n<conversation_to_summarize>\n{FormatMessagesForSummary(messages)}\n</conversation_to_summarize>\n</untrusted_content>"
            }
        };

        // Call SendMessageAsync using the compaction client (may be a cheaper model)
        var textContent = new System.Text.StringBuilder();

        await foreach (var evt in _compactionClient.SendMessageAsync(
            summarizationMessages,
            "You are a helpful assistant that creates concise, accurate summaries of technical conversations.",
            tools: null,
            cancellationToken).ConfigureAwait(false))
        {
            if (evt is TextDelta delta)
            {
                textContent.Append(delta.Text);
            }
            else if (evt is FinalResponse final && !string.IsNullOrEmpty(final.Content))
            {
                // Use final response if available
                return final.Content;
            }
        }

        return textContent.ToString();
    }

    /// <summary>
    /// Formats messages for summarization by extracting role and content.
    /// </summary>
    private static string FormatMessagesForSummary(IReadOnlyList<object> messages)
    {
        var formatted = new System.Text.StringBuilder();

        foreach (var msg in messages)
        {
            var msgType = msg.GetType();
            var roleProperty = msgType.GetProperty("role");
            var contentProperty = msgType.GetProperty("content");

            if (roleProperty != null && contentProperty != null)
            {
                var role = roleProperty.GetValue(msg)?.ToString() ?? "unknown";
                var content = contentProperty.GetValue(msg);

                // Handle both string content and complex content structures
                var contentStr = content is string str ? str : System.Text.Json.JsonSerializer.Serialize(content);

                formatted.AppendLine(CultureInfo.InvariantCulture, $"[{role.ToUpperInvariant()}]");
                formatted.AppendLine(contentStr);
                formatted.AppendLine();
            }
        }

        return formatted.ToString();
    }
}

/// <summary>
/// Result of a context compaction operation.
/// </summary>
/// <param name="OriginalMessageCount">Number of messages before compaction.</param>
/// <param name="CompactedMessageCount">Number of messages after compaction.</param>
/// <param name="MessagesRemoved">Number of messages removed during compaction.</param>
/// <param name="OriginalTokenCount">Token count before compaction.</param>
/// <param name="CompactedTokenCount">Token count after compaction.</param>
/// <param name="Summary">The generated conversation summary.</param>
/// <param name="CompactedMessages">The compacted message list.</param>
public sealed record CompactionResult(
    int OriginalMessageCount,
    int CompactedMessageCount,
    int MessagesRemoved,
    int OriginalTokenCount,
    int CompactedTokenCount,
    string Summary,
    IReadOnlyList<object> CompactedMessages);
