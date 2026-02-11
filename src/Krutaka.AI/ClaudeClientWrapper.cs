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

        // Convert tool definitions to Anthropic SDK Tool instances
        var convertedTools = ConvertToTools(tools);

        // Build parameters with tools if provided
        var parameters = convertedTools.Count > 0
            ? new MessageCreateParams
            {
                Messages = messageParams,
                System = systemPrompt,
                MaxTokens = _maxTokens,
                Model = _modelId,
                Temperature = _temperature,
                Tools = convertedTools.Select(t => (ToolUnion)t).ToList()
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
                else if (contentBlockDelta.Delta.TryPickInputJson(out var inputJsonDelta)
                    && toolUseBuilders.TryGetValue(contentBlockDelta.Index, out var builder))
                {
                    // Tool input JSON delta - accumulate partial JSON for this content block
                    builder.JsonInput.Append(inputJsonDelta.PartialJson);
                }
            }
            else if (chunk.TryPickContentBlockStop(out var contentBlockStop))
            {
                // Content block finished - emit ToolCallStarted if it was a tool_use block
                if (toolUseBuilders.TryGetValue(contentBlockStop.Index, out var completed))
                {
                    var inputJson = completed.JsonInput.ToString();
                    // Some tools may be called with no parameters (e.g., a tool that takes no input),
                    // in which case the accumulated JSON input is empty. Default to "{}" for valid JSON.
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
    /// Handles both pre-cast MessageParam objects and anonymous objects from AgentOrchestrator/SessionStore.
    /// Properly handles complex content structures including tool_use and tool_result blocks.
    /// </summary>
    private static List<MessageParam> ConvertToMessageParams(IEnumerable<object> messages)
    {
        var result = new List<MessageParam>();

        foreach (var msg in messages)
        {
            if (msg is MessageParam messageParam)
            {
                result.Add(messageParam);
            }
            else
            {
                var msgType = msg.GetType();
                var roleProperty = msgType.GetProperty("role");
                var contentProperty = msgType.GetProperty("content");

                if (roleProperty != null && contentProperty != null)
                {
                    var role = roleProperty.GetValue(msg)?.ToString() ?? "user";
                    var content = contentProperty.GetValue(msg);

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
                        // Complex content: convert to proper ContentBlockParam list
                        var contentBlocks = ConvertToContentBlockParams(content);
                        result.Add(new MessageParam
                        {
                            Role = role,
                            Content = contentBlocks
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

    /// <summary>
    /// Converts anonymous tool definition objects (from ToolRegistry) to Anthropic SDK Tool instances.
    /// </summary>
    private static List<Tool> ConvertToTools(object? tools)
    {
        if (tools == null)
        {
            return [];
        }

        if (tools is IReadOnlyList<Tool> toolsList)
        {
            return toolsList.ToList();
        }

        var result = new List<Tool>();

        if (tools is not System.Collections.IEnumerable enumerable)
        {
            return result;
        }

        foreach (var tool in enumerable)
        {
            var toolType = tool.GetType();
            var name = toolType.GetProperty("name")?.GetValue(tool)?.ToString();
            var description = toolType.GetProperty("description")?.GetValue(tool)?.ToString();
            var inputSchema = toolType.GetProperty("input_schema")?.GetValue(tool);

            if (string.IsNullOrEmpty(name) || inputSchema == null)
            {
                continue;
            }

            // Convert JsonElement InputSchema to Anthropic InputSchema
            InputSchema apiSchema;
            if (inputSchema is System.Text.Json.JsonElement jsonElement)
            {
                var dict = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, System.Text.Json.JsonElement>>(jsonElement.GetRawText());
                apiSchema = InputSchema.FromRawUnchecked(dict!);
            }
            else
            {
                var json = System.Text.Json.JsonSerializer.Serialize(inputSchema);
                var dict = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, System.Text.Json.JsonElement>>(json);
                apiSchema = InputSchema.FromRawUnchecked(dict!);
            }

            result.Add(new Tool
            {
                Name = name,
                Description = description,
                InputSchema = apiSchema
            });
        }

        return result;
    }

    /// <summary>
    /// Converts complex content (tool_use/tool_result/text blocks) from anonymous objects
    /// to proper Anthropic SDK ContentBlockParam instances.
    /// </summary>
    private static List<ContentBlockParam> ConvertToContentBlockParams(object? content)
    {
        var blocks = new List<ContentBlockParam>();

        if (content == null)
        {
            return blocks;
        }

        if (content is not System.Collections.IEnumerable enumerable)
        {
            // Single non-list content: treat as text
            blocks.Add((ContentBlockParam)new TextBlockParam { Text = content.ToString() ?? string.Empty });
            return blocks;
        }

        foreach (var item in enumerable)
        {
            var itemType = item.GetType();
            var typeProperty = itemType.GetProperty("type")?.GetValue(item)?.ToString();

            switch (typeProperty)
            {
                case "text":
                {
                    var text = itemType.GetProperty("text")?.GetValue(item)?.ToString() ?? string.Empty;
                    blocks.Add((ContentBlockParam)new TextBlockParam { Text = text });
                    break;
                }
                case "tool_use":
                {
                    var id = itemType.GetProperty("id")?.GetValue(item)?.ToString() ?? string.Empty;
                    var name = itemType.GetProperty("name")?.GetValue(item)?.ToString() ?? string.Empty;
                    var input = itemType.GetProperty("input")?.GetValue(item);

                    // Convert input to Dictionary<string, JsonElement>
                    Dictionary<string, System.Text.Json.JsonElement> inputDict;
                    if (input is string inputStr)
                    {
                        inputDict = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, System.Text.Json.JsonElement>>(inputStr)
                            ?? new Dictionary<string, System.Text.Json.JsonElement>();
                    }
                    else
                    {
                        var json = System.Text.Json.JsonSerializer.Serialize(input);
                        inputDict = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, System.Text.Json.JsonElement>>(json)
                            ?? new Dictionary<string, System.Text.Json.JsonElement>();
                    }

                    blocks.Add((ContentBlockParam)new ToolUseBlockParam
                    {
                        ID = id,
                        Name = name,
                        Input = inputDict
                    });
                    break;
                }
                case "tool_result":
                {
                    var toolUseId = itemType.GetProperty("tool_use_id")?.GetValue(item)?.ToString() ?? string.Empty;
                    var resultContent = itemType.GetProperty("content")?.GetValue(item)?.ToString() ?? string.Empty;
                    var isError = itemType.GetProperty("is_error")?.GetValue(item) as bool? ?? false;

                    blocks.Add((ContentBlockParam)new ToolResultBlockParam
                    {
                        ToolUseID = toolUseId,
                        Content = resultContent,
                        IsError = isError
                    });
                    break;
                }
                default:
                {
                    // Unknown type: serialize to text
                    var text = System.Text.Json.JsonSerializer.Serialize(item);
                    blocks.Add((ContentBlockParam)new TextBlockParam { Text = text });
                    break;
                }
            }
        }

        return blocks;
    }

    [LoggerMessage(Level = LogLevel.Debug, Message = "Received streaming chunk from Claude API")]
    partial void LogChunkReceived();

    [LoggerMessage(Level = LogLevel.Information, Message = "Claude API token count: {TokenCount}")]
    partial void LogTokenCount(int tokenCount);

    [LoggerMessage(Level = LogLevel.Information, Message = "Claude API request-id: {RequestId}")]
    partial void LogRequestId(string requestId);
}
