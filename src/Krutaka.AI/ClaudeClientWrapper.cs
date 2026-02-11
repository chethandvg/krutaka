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
    private readonly IAuditLogger? _auditLogger;
    private readonly CorrelationContext? _correlationContext;
    private readonly string _modelId;
    private readonly int _maxTokens;
    private readonly double _temperature;

    public ClaudeClientWrapper(
        AnthropicClient client,
        ILogger<ClaudeClientWrapper> logger,
        string modelId = "claude-4-sonnet-20250514",
        int maxTokens = 8192,
        double temperature = 0.7,
        IAuditLogger? auditLogger = null,
        CorrelationContext? correlationContext = null)
    {
        _client = client;
        _logger = logger;
        _auditLogger = auditLogger;
        _correlationContext = correlationContext;
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

        // Stream the response
        // Note: Using official Anthropic package (v12.4.0), NOT community Anthropic.SDK
        // The official package is in GA but streaming event structure may still evolve
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
        var messageParams = ConvertToMessageParams(messages);

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
}
