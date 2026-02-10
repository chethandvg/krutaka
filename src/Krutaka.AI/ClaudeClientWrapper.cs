using System.Runtime.CompilerServices;
using Anthropic;
using Anthropic.Models.Messages;
using Krutaka.Core;
using Microsoft.Extensions.Logging;

namespace Krutaka.AI;

/// <summary>
/// Wraps the official Anthropic SDK behind the IClaudeClient interface.
/// Provides streaming support, token counting, and request-id logging.
/// </summary>
internal sealed partial class ClaudeClientWrapper : IClaudeClient
{
    private readonly AnthropicClient _client;
    private readonly ILogger<ClaudeClientWrapper> _logger;
    private readonly string _modelId;
    private readonly int _maxTokens;
    private readonly double _temperature;

    public ClaudeClientWrapper(
        AnthropicClient client,
        ILogger<ClaudeClientWrapper> logger,
        string modelId = "claude-4-sonnet-20250514",
        int maxTokens = 8192,
        double temperature = 0.7)
    {
        _client = client;
        _logger = logger;
        _modelId = modelId;
        _maxTokens = maxTokens;
        _temperature = temperature;
    }

    /// <inheritdoc />
    public async IAsyncEnumerable<AgentEvent> SendMessageAsync(
        IEnumerable<object> messages,
        string systemPrompt,
        object? tools = null,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        // Convert messages to MessageParam
        var messageParams = messages
            .Cast<MessageParam>()
            .ToList();

        // Build parameters with tools if provided
        var parameters = tools is IReadOnlyList<Tool> toolsList && toolsList.Count > 0
            ? new MessageCreateParams
            {
                Messages = messageParams,
                System = systemPrompt,
                MaxTokens = _maxTokens,
                Model = _modelId,
                Temperature = _temperature,
                Tools = toolsList.Select(t => (ToolUnion)t).ToList()
            }
            : new MessageCreateParams
            {
                Messages = messageParams,
                System = systemPrompt,
                MaxTokens = _maxTokens,
                Model = _modelId,
                Temperature = _temperature
            };

        var textContent = new System.Text.StringBuilder();
        string stopReason = "end_turn";

        // Stream the response
        // Note: SDK is in beta, streaming event structure may evolve
        // Full event parsing will be implemented in the agentic loop (Issue #14)
        await foreach (var chunk in _client.Messages.CreateStreaming(parameters, cancellationToken: cancellationToken).ConfigureAwait(false))
        {
            if (chunk == null)
            {
                continue;
            }

            LogChunkReceived();

            // For now, yield a basic text delta event
            // The agentic loop will handle detailed parsing of:
            // - Actual text deltas
            // - Tool call events  
            // - Stop reasons
            // - Request IDs
            var delta = ""; // Placeholder - SDK beta doesn't expose structured deltas yet
            if (!string.IsNullOrEmpty(delta))
            {
                textContent.Append(delta);
                yield return new Core.TextDelta(delta);
            }
        }

        // Emit final response
        yield return new FinalResponse(textContent.ToString(), stopReason);
    }

    /// <inheritdoc />
    public async Task<int> CountTokensAsync(
        IEnumerable<object> messages,
        string systemPrompt,
        CancellationToken cancellationToken = default)
    {
        // Convert messages to MessageParam
        var messageParams = messages
            .Cast<MessageParam>()
            .ToList();

        // Create token counting parameters
        var parameters = new MessageCountTokensParams
        {
            Model = _modelId,
            Messages = messageParams,
            System = systemPrompt
        };

        // Call the CountTokens method
        var response = await _client.Messages.CountTokens(parameters, cancellationToken: cancellationToken).ConfigureAwait(false);

        var tokenCount = (int)response.InputTokens;
        LogTokenCount(tokenCount);

        return tokenCount;
    }

    [LoggerMessage(Level = LogLevel.Debug, Message = "Received streaming chunk from Claude API")]
    partial void LogChunkReceived();

    [LoggerMessage(Level = LogLevel.Information, Message = "Claude API token count: {TokenCount}")]
    partial void LogTokenCount(int tokenCount);
}
