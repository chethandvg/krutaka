using System.Text.Json;

namespace Krutaka.Core;

public sealed partial class AgentOrchestrator
{
    /// <summary>
    /// Creates a user message with the specified text.
    /// This is a placeholder that returns an object compatible with the Claude API.
    /// </summary>
    private static object CreateUserMessage(string text)
    {
        // Return a simple object structure that will be converted to MessageParam by the AI layer
        return new
        {
            role = "user",
            content = text
        };
    }

    /// <summary>
    /// Creates an assistant message with content and tool calls preserved.
    /// This is a placeholder that returns an object compatible with the Claude API.
    /// </summary>
    private static object CreateAssistantMessage(string? content, List<ToolCall> toolCalls, string stopReason)
    {
        var contentBlocks = new List<object>();

        // Add text content if present
        if (!string.IsNullOrEmpty(content))
        {
            contentBlocks.Add(new
            {
                type = "text",
                text = content
            });
        }

        // Add tool use blocks
        foreach (var toolCall in toolCalls)
        {
            // Parse the input string to JsonElement to avoid double-serialization issues
            // When stored as a string, the round-trip through JSONL causes double-escaping
            // that breaks RepairOrphanedToolUseBlocks and Claude API validation
            JsonElement inputElement;
            try
            {
                using var doc = JsonDocument.Parse(toolCall.Input);
                inputElement = doc.RootElement.Clone();
            }
            catch (JsonException)
            {
                // Fall back to empty JSON object if parsing fails
                using var fallbackDoc = JsonDocument.Parse("{}");
                inputElement = fallbackDoc.RootElement.Clone();
            }

            contentBlocks.Add(new
            {
                type = "tool_use",
                id = toolCall.Id,
                name = toolCall.Name,
                input = inputElement
            });
        }

        // Return a simple object structure that will be converted to MessageParam by the AI layer
        return new
        {
            role = "assistant",
            content = contentBlocks,
            stop_reason = stopReason
        };
    }

    /// <summary>
    /// Creates a tool result block.
    /// This is a placeholder that returns an object compatible with the Claude API.
    /// </summary>
    private static object CreateToolResult(string toolUseId, string content, bool isError)
    {
        return new
        {
            type = "tool_result",
            tool_use_id = toolUseId,
            content,
            is_error = isError
        };
    }

    /// <summary>
    /// Creates a user message containing tool results.
    /// Tool-result ordering invariant: tool result blocks must come first.
    /// </summary>
    private static object CreateUserMessageWithToolResults(List<object> toolResults)
    {
        return new
        {
            role = "user",
            content = toolResults
        };
    }

    /// <summary>
    /// Checks if context compaction is needed and performs it if so.
    /// Replaces conversation history with compacted version.
    /// Enforces a hard token limit after compaction as a safety net.
    /// </summary>
    private async Task<CompactionCompleted?> CompactIfNeededAsync(string systemPrompt, CancellationToken cancellationToken)
    {
        int historyCount;
        lock (_conversationHistoryLock)
        {
            historyCount = _conversationHistory.Count;
        }

        if (_contextCompactor == null || historyCount == 0)
        {
            return null;
        }

        List<object> historySnapshot;
        lock (_conversationHistoryLock)
        {
            historySnapshot = _conversationHistory.ToList();
        }

        var tokenCount = await _claudeClient.CountTokensAsync(historySnapshot, systemPrompt, cancellationToken).ConfigureAwait(false);

        if (_contextCompactor.ShouldCompact(tokenCount) || _contextCompactor.ExceedsHardLimit(tokenCount))
        {
            return await CompactAndEnforceHardLimitAsync(historySnapshot, systemPrompt, tokenCount, cancellationToken).ConfigureAwait(false);
        }

        return null;
    }

    /// <summary>
    /// Performs context compaction and enforces the hard token limit as a safety net.
    /// If compaction alone doesn't bring tokens under the max, performs emergency truncation.
    /// Returns a CompactionCompleted event with metadata for JSONL persistence.
    /// </summary>
    private async Task<CompactionCompleted> CompactAndEnforceHardLimitAsync(
        List<object> historySnapshot,
        string systemPrompt,
        int tokenCount,
        CancellationToken cancellationToken)
    {
        var result = await _contextCompactor!.CompactAsync(
            historySnapshot,
            systemPrompt,
            tokenCount,
            cancellationToken).ConfigureAwait(false);

        var compactedMessages = result.CompactedMessages;
        var finalTokenCount = result.CompactedTokenCount;

        // Safety net: if compaction didn't bring tokens under the hard limit,
        // perform emergency truncation to prevent API errors
        if (_contextCompactor.ExceedsHardLimit(result.CompactedTokenCount))
        {
            compactedMessages = await _contextCompactor.TruncateToFitAsync(
                compactedMessages,
                systemPrompt,
                cancellationToken).ConfigureAwait(false);

            // Recompute token count after emergency truncation for accurate metadata
            finalTokenCount = await _claudeClient.CountTokensAsync(
                compactedMessages,
                systemPrompt,
                cancellationToken).ConfigureAwait(false);
        }

        lock (_conversationHistoryLock)
        {
            _conversationHistory.Clear();
            _conversationHistory.AddRange(compactedMessages);
        }

        // Truncate summary to 200 chars for JSONL persistence
        var summary = result.Summary.Length > 200
            ? result.Summary[..200]
            : result.Summary;

        return new CompactionCompleted(
            summary,
            result.OriginalTokenCount,
            finalTokenCount,
            result.MessagesRemoved);
    }
}
