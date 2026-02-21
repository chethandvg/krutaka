using Krutaka.Core;
using Krutaka.Memory;

namespace Krutaka.Console;

/// <summary>
/// Wraps an agent event stream with session persistence, appending assistant responses
/// and tool events to the session store as they flow through.
/// </summary>
internal static class SessionEventPersistence
{
    internal static async IAsyncEnumerable<AgentEvent> WrapWithSessionPersistence(
        IAsyncEnumerable<AgentEvent> events,
        SessionStore sessionStore,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var textAccumulator = new System.Text.StringBuilder();

        await foreach (var evt in events.WithCancellation(cancellationToken))
        {
            switch (evt)
            {
                case TextDelta delta:
                    textAccumulator.Append(delta.Text);
                    break;

                case ToolCallStarted tool:
                    // Flush any accumulated assistant text before the tool_use event so that
                    // resume reconstructs content blocks in the same order Claude produced them
                    // (text first, then tool_use).
                    if (textAccumulator.Length > 0)
                    {
                        await sessionStore.AppendAsync(
                            new SessionEvent("assistant", "assistant", textAccumulator.ToString(), DateTimeOffset.UtcNow),
                            cancellationToken).ConfigureAwait(false);
                        textAccumulator.Clear();
                    }

                    // CRITICAL TIMING WINDOW: The tool_use event is persisted IMMEDIATELY when emitted by Claude.
                    // If the process crashes/terminates between this point and the corresponding
                    // ToolCallCompleted/ToolCallFailed event being persisted, the session will have
                    // an orphaned tool_use block. This is handled by SessionStore.RepairOrphanedToolUseBlocks()
                    // which detects missing tool_result blocks and injects synthetic error responses during resume.
                    await sessionStore.AppendAsync(
                        new SessionEvent("tool_use", "assistant", tool.Input, DateTimeOffset.UtcNow, tool.ToolName, tool.ToolUseId),
                        cancellationToken).ConfigureAwait(false);
                    break;

                case ToolCallCompleted tool:
                    await sessionStore.AppendAsync(
                        new SessionEvent("tool_result", "user", tool.Result, DateTimeOffset.UtcNow, tool.ToolName, tool.ToolUseId),
                        cancellationToken).ConfigureAwait(false);
                    break;

                case ToolCallFailed tool:
                    // Use "tool_error" type so resume can reconstruct the is_error flag
                    await sessionStore.AppendAsync(
                        new SessionEvent("tool_error", "user", tool.Error, DateTimeOffset.UtcNow, tool.ToolName, tool.ToolUseId),
                        cancellationToken).ConfigureAwait(false);
                    break;

                case FinalResponse final:
                    // Persist any remaining assistant text that wasn't flushed before a tool call.
                    // In non-tool-use turns the text is only emitted here.
                    if (textAccumulator.Length > 0 || !string.IsNullOrEmpty(final.Content))
                    {
                        var content = textAccumulator.Length > 0 ? textAccumulator.ToString() : final.Content;
                        await sessionStore.AppendAsync(
                            new SessionEvent("assistant", "assistant", content, DateTimeOffset.UtcNow),
                            cancellationToken).ConfigureAwait(false);
                    }
                    // Reset for next response in the same turn (multi-turn tool calls)
                    textAccumulator.Clear();
                    break;

                case CompactionCompleted compaction:
                    // Persist compaction event with metadata for debugging
                    await sessionStore.AppendAsync(
                        new SessionEvent(
                            Type: "compaction",
                            Role: null,
                            Content: compaction.Summary,
                            Timestamp: compaction.Timestamp,
                            TokensBefore: compaction.TokensBefore,
                            TokensAfter: compaction.TokensAfter,
                            MessagesRemoved: compaction.MessagesRemoved),
                        cancellationToken).ConfigureAwait(false);
                    break;
            }

            yield return evt;
        }
    }
}

/// <summary>
/// Represents recovery options when an API error occurs.
/// </summary>
internal enum RecoveryOption
{
    /// <summary>Reload the current session using the 2-step resume pattern.</summary>
    ReloadSession,
    /// <summary>Start a new session.</summary>
    StartNew
}
