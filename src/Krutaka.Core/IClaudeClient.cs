namespace Krutaka.Core;

/// <summary>
/// Abstraction over Claude API client for message streaming and token counting.
/// Implementations wrap the official Anthropic package (NuGet: Anthropic) behind this interface.
/// Note: This refers to the official Anthropic package, NOT the community Anthropic.SDK.
/// </summary>
public interface IClaudeClient
{
    /// <summary>
    /// Sends a message to Claude and streams the response events.
    /// Supports streaming text deltas, tool calls, and final responses.
    /// </summary>
    /// <param name="messages">The conversation message history.</param>
    /// <param name="systemPrompt">The system prompt defining agent behavior.</param>
    /// <param name="tools">Available tool definitions (optional).</param>
    /// <param name="cancellationToken">Cancellation token for async operation.</param>
    /// <returns>An async stream of agent events.</returns>
    IAsyncEnumerable<AgentEvent> SendMessageAsync(
        IEnumerable<object> messages,
        string systemPrompt,
        object? tools = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Counts tokens in a message sequence using Claude's tokenizer.
    /// </summary>
    /// <param name="messages">The messages to count tokens for.</param>
    /// <param name="systemPrompt">The system prompt to include in the count.</param>
    /// <param name="cancellationToken">Cancellation token for async operation.</param>
    /// <returns>The total token count.</returns>
    Task<int> CountTokensAsync(
        IEnumerable<object> messages,
        string systemPrompt,
        CancellationToken cancellationToken = default);
}
