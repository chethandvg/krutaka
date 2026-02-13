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
    /// Gets the configured maximum token limit for the context window.
    /// Used by the orchestrator for hard-limit enforcement after compaction.
    /// </summary>
    public int MaxTokens => _maxTokens;

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
    /// Checks if the token count exceeds the absolute hard limit for the context window.
    /// This is used as a safety net after compaction to prevent API errors.
    /// </summary>
    /// <param name="tokenCount">The current token count.</param>
    /// <returns>True if the token count exceeds the hard limit.</returns>
    public bool ExceedsHardLimit(int tokenCount)
    {
        return tokenCount > _maxTokens;
    }

    /// <summary>
    /// Performs emergency truncation by progressively dropping the oldest messages
    /// (keeping the most recent ones) until the token count is under the hard limit.
    /// This is a last-resort safety net when compaction alone is not enough.
    /// </summary>
    /// <param name="messages">The current conversation messages.</param>
    /// <param name="systemPrompt">The system prompt used for the conversation.</param>
    /// <param name="cancellationToken">Cancellation token for async operation.</param>
    /// <returns>The truncated message list that fits within the hard limit.</returns>
    public async Task<IReadOnlyList<object>> TruncateToFitAsync(
        IReadOnlyList<object> messages,
        string systemPrompt,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(messages);
        ArgumentNullException.ThrowIfNull(systemPrompt);

        // Minimum: keep at least 2 messages (one user + one assistant) for a valid conversation
        // Only drop complete pairs to maintain the alternating role pattern
        const int absoluteMinimumMessages = 2;
        const int pairSize = 2;
        var current = messages.ToList();

        while (current.Count >= absoluteMinimumMessages + pairSize)
        {
            // After dropping, ensure the first message is not an orphaned tool_result.
            // A user message with tool_result blocks requires a preceding assistant message
            // with the corresponding tool_use blocks — drop extra messages to maintain this invariant.
            DropOrphanedToolResultPrefix(current);

            var tokenCount = await _claudeClient.CountTokensAsync(current, systemPrompt, cancellationToken).ConfigureAwait(false);

            if (!ExceedsHardLimit(tokenCount))
            {
                return current.AsReadOnly();
            }

            // Drop the oldest 2 messages (one user-assistant pair) from the front
            current.RemoveRange(0, pairSize);
        }

        // Final cleanup after the loop exits
        DropOrphanedToolResultPrefix(current);

        return current.AsReadOnly();
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
        var splitIndex = messages.Count - _messagesToKeep;
        var messagesToSummarize = messages.Take(splitIndex).ToList();
        var messagesToKeep = messages.Skip(splitIndex).ToList();

        // If the first kept message is a user message containing tool_result blocks,
        // it needs a preceding assistant message with the corresponding tool_use.
        // Pull the preceding assistant message from the summarize set into the keep set.
        while (messagesToKeep.Count > 0 && HasToolResultContent(messagesToKeep[0])
            && messagesToSummarize.Count > 0)
        {
            // Move the preceding assistant message (tool_use) into the keep set
            var preceding = messagesToSummarize[^1];
            messagesToSummarize.RemoveAt(messagesToSummarize.Count - 1);
            messagesToKeep.Insert(0, preceding);
        }

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
    /// Checks if a message contains tool_result content blocks.
    /// A user message with tool_result blocks requires a preceding assistant message
    /// with the corresponding tool_use blocks per Claude API requirements.
    /// </summary>
    private static bool HasToolResultContent(object message)
    {
        var role = GetMessageRole(message);
        if (role != "user")
        {
            return false;
        }

        var contentProperty = message.GetType().GetProperty("content");
        var content = contentProperty?.GetValue(message);

        // If content is a string, it's plain text, not tool_result
        if (content is null or string)
        {
            return false;
        }

        // Content is a collection of blocks — check if any are tool_result
        if (content is System.Collections.IEnumerable enumerable)
        {
            foreach (var block in enumerable)
            {
                var typeProperty = block.GetType().GetProperty("type");
                var typeValue = typeProperty?.GetValue(block)?.ToString();
                if (typeValue == "tool_result")
                {
                    return true;
                }
            }
        }

        return false;
    }

    /// <summary>
    /// Drops messages from the front of the list until the first message is not an orphaned
    /// tool_result. An orphaned tool_result is a user message with tool_result blocks that
    /// has no preceding assistant message with the corresponding tool_use blocks.
    /// Note: The subsequent assistant message is also dropped because in Claude's protocol,
    /// the assistant always responds immediately after receiving tool results, so the assistant
    /// message following a tool_result is always its direct response.
    /// </summary>
    private static void DropOrphanedToolResultPrefix(List<object> messages)
    {
        while (messages.Count > 0 && HasToolResultContent(messages[0]))
        {
            messages.RemoveAt(0);
            // Also remove the subsequent assistant message to maintain pair structure
            if (messages.Count > 0 && GetMessageRole(messages[0]) == "assistant")
            {
                messages.RemoveAt(0);
            }
        }
    }

    /// <summary>
    /// Generates a conversation summary using the configured Claude client.
    /// Focuses on preserving file paths, action items, technical decisions, and error context.
    /// </summary>
    private async Task<string> GenerateSummaryAsync(
        IReadOnlyList<object> messages,
        CancellationToken cancellationToken)
    {
        var summaryPrompt = @"Summarize the conversation with MAXIMUM DETAIL preservation. This summary will REPLACE the original messages, so every critical detail must be retained.

CRITICAL — Preserve EXACT VALUES for:
1. **File paths** — Include full absolute paths, not just directory names
2. **Code snippets** — Preserve key function signatures, class names, variable names, and short code blocks
3. **Technical decisions** — Include BOTH what was chosen AND what was rejected (and why)
4. **Error messages** — Include exact error text, stack traces, and resolution steps
5. **Tool execution results** — Preserve actual command output and outcomes, not just summaries
6. **User corrections** — When the user said ""no, not that way"", preserve both the rejected and accepted versions
7. **Configuration values** — Port numbers, env vars, connection strings, model names, thresholds
8. **Action items** — Tasks completed and tasks still pending

Structure as:
## Completed Work
[detailed list with exact paths, commands, and outcomes]

## Rejected Approaches
[what was tried, what failed, and why — so these are not repeated]

## Current State
[files modified with paths, current values, pending tasks]

## Key Decisions & User Preferences
[explicit requirements, style choices, constraints, rejected alternatives]";

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
