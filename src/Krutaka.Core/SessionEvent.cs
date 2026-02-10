using System.Text.Json.Serialization;

namespace Krutaka.Core;

/// <summary>
/// Represents a single event in a session's JSONL file.
/// Each line in the JSONL file is one SessionEvent.
/// </summary>
/// <param name="Type">The event type (e.g., "user", "assistant", "tool_use", "tool_result").</param>
/// <param name="Role">The message role (user, assistant, or null for tool events).</param>
/// <param name="Content">The event content (text, JSON, or null).</param>
/// <param name="Timestamp">When the event occurred.</param>
/// <param name="ToolName">The tool name if this is a tool-related event.</param>
/// <param name="ToolUseId">The tool use identifier for correlating tool_use and tool_result.</param>
/// <param name="IsMeta">True if this is metadata (not sent to Claude API).</param>
[method: JsonConstructor]
public sealed record SessionEvent(
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("role")] string? Role,
    [property: JsonPropertyName("content")] string? Content,
    [property: JsonPropertyName("timestamp")] DateTimeOffset Timestamp,
    [property: JsonPropertyName("tool_name")] string? ToolName = null,
    [property: JsonPropertyName("tool_use_id")] string? ToolUseId = null,
    [property: JsonPropertyName("is_meta")] bool IsMeta = false
);
