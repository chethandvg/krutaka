using System.Runtime.CompilerServices;
using Anthropic;
using Anthropic.Models.Messages;
using Krutaka.Core;
using Microsoft.Extensions.Logging;

namespace Krutaka.AI;

/// <summary>
/// Wraps the official Anthropic package (NuGet: Anthropic v12.4.0) behind the IClaudeClient interface.
/// Provides streaming support, token counting, and request-id logging.
/// Note: This uses the official Anthropic package, NOT the community Anthropic.SDK package.
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
        var messageParams = ConvertToMessageParams(messages);

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

        // Track tool use content block state for accumulating partial JSON input
        var toolUseBuilders = new Dictionary<long, (string Name, string Id, System.Text.StringBuilder JsonInput)>();

        // Stream the response using WithRawResponse to capture HTTP headers including request-id.
        // Note: Using official Anthropic package (v12.4.0), NOT community Anthropic.SDK
        var rawResponse = await _client.WithRawResponse.Messages.CreateStreaming(parameters, cancellationToken: cancellationToken).ConfigureAwait(false);

        // Extract and emit the request-id from the HTTP response header
        var requestId = rawResponse.RequestID;
        if (!string.IsNullOrEmpty(requestId))
        {
            LogRequestId(requestId);
            yield return new RequestIdCaptured(requestId);
        }

        await foreach (var chunk in rawResponse.Enumerate(cancellationToken).ConfigureAwait(false))
        {
            if (chunk == null)
            {
                continue;
            }

            LogChunkReceived();

            // Parse streaming events from the official Anthropic SDK (v12.4.0).
            // The SDK exposes RawMessageStreamEvent with TryPick* methods for each event type.
            if (chunk.TryPickContentBlockStart(out var contentBlockStart))
            {
                // A new content block has started - check if it's a tool_use block
                if (contentBlockStart.ContentBlock.TryPickToolUse(out var toolUseBlock))
                {
                    // Start tracking this tool use block's input JSON accumulation
                    toolUseBuilders[contentBlockStart.Index] = (
                        toolUseBlock.Name,
                        toolUseBlock.ID,
                        new System.Text.StringBuilder());
                }
            }
            else if (chunk.TryPickContentBlockDelta(out var contentBlockDelta))
            {
                // A content block delta with incremental content
                if (contentBlockDelta.Delta.TryPickText(out var textDelta))
                {
                    // Text delta - accumulate and yield
                    textContent.Append(textDelta.Text);
                    yield return new Core.TextDelta(textDelta.Text);
                }
                else if (contentBlockDelta.Delta.TryPickInputJson(out var inputJsonDelta))
                {
                    // Tool input JSON delta - accumulate partial JSON for this content block
                    if (toolUseBuilders.TryGetValue(contentBlockDelta.Index, out var builder))
                    {
                        builder.JsonInput.Append(inputJsonDelta.PartialJson);
                    }
                }
            }
            else if (chunk.TryPickContentBlockStop(out var contentBlockStop))
            {
                // Content block finished - emit ToolCallStarted if it was a tool_use block
                if (toolUseBuilders.TryGetValue(contentBlockStop.Index, out var completed))
                {
                    var inputJson = completed.JsonInput.ToString();
                    if (string.IsNullOrEmpty(inputJson))
                    {
                        inputJson = "{}";
                    }

                    yield return new ToolCallStarted(completed.Name, completed.Id, inputJson);
                    toolUseBuilders.Remove(contentBlockStop.Index);
                }
            }
            else if (chunk.TryPickDelta(out var messageDelta))
            {
                // Message-level delta with stop reason and usage.
                // StopReason is an ApiEnum<string, StopReason> which implicitly converts to string.
                var stopReasonEnum = messageDelta.Delta.StopReason;
                if (stopReasonEnum is not null)
                {
                    string reason = stopReasonEnum;
                    if (!string.IsNullOrEmpty(reason))
                    {
                        stopReason = reason;
                    }
                }
            }
        }

        // Emit final response with accumulated text and the actual stop reason
        yield return new FinalResponse(textContent.ToString(), stopReason);
    }

    /// <inheritdoc />
    public async Task<int> CountTokensAsync(
        IEnumerable<object> messages,
        string systemPrompt,
        CancellationToken cancellationToken = default)
    {
        // Convert messages to MessageParam
        var messageParams = ConvertToMessageParams(messages);

        // Create token counting parameters
        var parameters = new MessageCountTokensParams
        {
            Model = _modelId,
            Messages = messageParams,
            System = systemPrompt
        };

        // Use WithRawResponse to capture the request-id header for correlation
        var rawResponse = await _client.WithRawResponse.Messages.CountTokens(parameters, cancellationToken: cancellationToken).ConfigureAwait(false);

        var requestId = rawResponse.RequestID;
        if (!string.IsNullOrEmpty(requestId))
        {
            LogRequestId(requestId);
        }

        var response = await rawResponse.Deserialize(cancellationToken).ConfigureAwait(false);

        var tokenCount = (int)response.InputTokens;
        LogTokenCount(tokenCount);

        return tokenCount;
    }

    /// <summary>
    /// Converts objects to MessageParam instances.
    /// Handles both pre-cast MessageParam objects and anonymous objects from SessionStore.
    /// </summary>
    private static List<MessageParam> ConvertToMessageParams(IEnumerable<object> messages)
    {
        var result = new List<MessageParam>();

        foreach (var msg in messages)
        {
            if (msg is MessageParam messageParam)
            {
                // Already a MessageParam, use directly
                result.Add(messageParam);
            }
            else
            {
                // Try to extract role and content from anonymous object using reflection
                var msgType = msg.GetType();
                var roleProperty = msgType.GetProperty("role");
                var contentProperty = msgType.GetProperty("content");

                if (roleProperty != null && contentProperty != null)
                {
                    var role = roleProperty.GetValue(msg)?.ToString() ?? "user";
                    var content = contentProperty.GetValue(msg);

                    // Convert content to appropriate type
                    if (content is string textContent)
                    {
                        result.Add(new MessageParam
                        {
                            Role = role,
                            Content = textContent
                        });
                    }
                    else
                    {
                        // For complex content (arrays, objects), serialize and parse
                        // This handles tool_use and tool_result content structures
                        var contentJson = System.Text.Json.JsonSerializer.Serialize(content);
                        result.Add(new MessageParam
                        {
                            Role = role,
                            Content = contentJson
                        });
                    }
                }
                else
                {
                    throw new InvalidOperationException(
                        $"Message object must be MessageParam or have 'role' and 'content' properties. Got: {msgType.Name}");
                }
            }
        }

        return result;
    }

    [LoggerMessage(Level = LogLevel.Debug, Message = "Received streaming chunk from Claude API")]
    partial void LogChunkReceived();

    [LoggerMessage(Level = LogLevel.Information, Message = "Claude API token count: {TokenCount}")]
    partial void LogTokenCount(int tokenCount);

    [LoggerMessage(Level = LogLevel.Information, Message = "Claude API request-id: {RequestId}")]
    partial void LogRequestId(string requestId);
}
