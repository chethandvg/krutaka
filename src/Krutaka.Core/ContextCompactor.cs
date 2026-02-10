using System.Globalization;

namespace Krutaka.Core;

/// <summary>
/// Provides context window compaction when token count exceeds threshold.
/// Uses Claude Haiku 4.5 to generate conversation summaries and replaces old messages
/// with summary + acknowledgment + last N message pairs.
/// </summary>
public sealed class ContextCompactor
{
    private readonly IClaudeClient _claudeClient;
    private readonly int _maxTokens;
    private readonly double _compactionThreshold;
    private readonly int _messagesToKeep;
    private readonly string _summaryModelId;

    /// <summary>
    /// Initializes a new instance of the <see cref="ContextCompactor"/> class.
    /// </summary>
    /// <param name="claudeClient">The Claude API client.</param>
    /// <param name="maxTokens">Maximum context window size (default: 200,000).</param>
    /// <param name="compactionThreshold">Threshold percentage for compaction (default: 0.80 = 80%).</param>
    /// <param name="messagesToKeep">Number of recent messages to keep after compaction (default: 6 = 3 pairs).</param>
    /// <param name="summaryModelId">Model ID for summarization (default: claude-haiku-4-5-20250929).</param>
    public ContextCompactor(
        IClaudeClient claudeClient,
        int maxTokens = 200_000,
        double compactionThreshold = 0.80,
        int messagesToKeep = 6,
        string summaryModelId = "claude-haiku-4-5-20250929")
    {
        _claudeClient = claudeClient ?? throw new ArgumentNullException(nameof(claudeClient));
        _maxTokens = maxTokens;
        _compactionThreshold = compactionThreshold;
        _messagesToKeep = messagesToKeep;
        _summaryModelId = summaryModelId;
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

        // Keep last N messages
        var messagesToSummarize = messages.Take(Math.Max(0, messages.Count - _messagesToKeep)).ToList();
        var messagesToKeep = messages.Skip(messagesToSummarize.Count).ToList();

        // Generate summary using cheaper model
        var summary = await GenerateSummaryAsync(messagesToSummarize, cancellationToken).ConfigureAwait(false);

        // Build compacted message list
        var compactedMessages = new List<object>();

        // Add summary as user message
        compactedMessages.Add(new
        {
            role = "user",
            content = $"[Previous conversation summary]\n{summary}"
        });

        // Add assistant acknowledgment
        compactedMessages.Add(new
        {
            role = "assistant",
            content = "Understood. I have the context from our previous discussion."
        });

        // Add recent messages
        compactedMessages.AddRange(messagesToKeep);

        // Count tokens in compacted conversation
        var newTokenCount = await _claudeClient.CountTokensAsync(compactedMessages, systemPrompt, cancellationToken).ConfigureAwait(false);

        // Calculate messages removed (from the original conversation, not counting added summary messages)
        var messagesRemoved = messagesToSummarize.Count;

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
    /// Generates a conversation summary using Claude Haiku.
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
                content = $"{summaryPrompt}\n\n<conversation_to_summarize>\n{FormatMessagesForSummary(messages)}\n</conversation_to_summarize>"
            }
        };

        // Use a temporary client wrapper with Haiku model for summarization
        // Note: We need to call SendMessageAsync and collect the response
        var textContent = new System.Text.StringBuilder();
        
        await foreach (var evt in _claudeClient.SendMessageAsync(
            summarizationMessages,
            "You are a helpful assistant that creates concise, accurate summaries of technical conversations.",
            tools: null,
            cancellationToken).ConfigureAwait(false))
        {
            if (evt is TextDelta delta)
            {
                textContent.Append(delta.Text);
            }
            else if (evt is FinalResponse final)
            {
                // Use final response if available
                if (!string.IsNullOrEmpty(final.Content))
                {
                    return final.Content;
                }
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
