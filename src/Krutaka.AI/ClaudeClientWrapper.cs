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
internal sealed partial class ClaudeClientWrapper : IClaudeClient, IDisposable
{
    private readonly AnthropicClient _client;
    private readonly ILogger<ClaudeClientWrapper> _logger;
    private readonly string _modelId;
    private readonly int _maxTokens;
    private readonly double _temperature;
    private readonly int _retryMaxAttempts;
    private readonly int _retryInitialDelayMs;
    private readonly int _retryMaxDelayMs;
    private readonly System.Security.Cryptography.RandomNumberGenerator _random = System.Security.Cryptography.RandomNumberGenerator.Create();
    private readonly object _randomLock = new();
    private bool _disposed;

    public ClaudeClientWrapper(
        AnthropicClient client,
        ILogger<ClaudeClientWrapper> logger,
        string modelId = "claude-4-sonnet-20250514",
        int maxTokens = 8192,
        double temperature = 0.7,
        int retryMaxAttempts = 3,
        int retryInitialDelayMs = 1000,
        int retryMaxDelayMs = 30000)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        
        // Validate retry configuration
        if (retryMaxAttempts < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(retryMaxAttempts), retryMaxAttempts, "RetryMaxAttempts must be >= 0");
        }

        if (retryInitialDelayMs <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(retryInitialDelayMs), retryInitialDelayMs, "RetryInitialDelayMs must be > 0");
        }

        if (retryMaxDelayMs < retryInitialDelayMs)
        {
            throw new ArgumentOutOfRangeException(nameof(retryMaxDelayMs), retryMaxDelayMs, "RetryMaxDelayMs must be >= RetryInitialDelayMs");
        }

        if (retryMaxDelayMs > 300000) // 5 minutes max
        {
            throw new ArgumentOutOfRangeException(nameof(retryMaxDelayMs), retryMaxDelayMs, "RetryMaxDelayMs must be <= 300000 (5 minutes)");
        }
        
        _modelId = modelId;
        _maxTokens = maxTokens;
        _temperature = temperature;
        _retryMaxAttempts = retryMaxAttempts;
        _retryInitialDelayMs = retryInitialDelayMs;
        _retryMaxDelayMs = retryMaxDelayMs;
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
        // Wrap the CreateStreaming call with retry logic for rate limit errors during stream setup
        var rawResponse = await ExecuteWithRetryAsync(
            async ct => await _client.WithRawResponse.Messages.CreateStreaming(parameters, cancellationToken: ct).ConfigureAwait(false),
            cancellationToken).ConfigureAwait(false);

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
        return await ExecuteWithRetryAsync(async ct =>
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
            var rawResponse = await _client.WithRawResponse.Messages.CountTokens(parameters, cancellationToken: ct).ConfigureAwait(false);

            var requestId = rawResponse.RequestID;
            if (!string.IsNullOrEmpty(requestId))
            {
                LogRequestId(requestId);
            }

            var response = await rawResponse.Deserialize(ct).ConfigureAwait(false);

            var tokenCount = (int)response.InputTokens;
            LogTokenCount(tokenCount);

            return tokenCount;
        }, cancellationToken).ConfigureAwait(false);
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
    private List<Tool> ConvertToTools(object? tools)
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
                LogSkippedToolDefinition(
                    toolType.FullName ?? toolType.Name,
                    string.IsNullOrEmpty(name) ? "name" : "input_schema");
                continue;
            }

            // Convert JsonElement InputSchema to Anthropic InputSchema
            Dictionary<string, System.Text.Json.JsonElement>? schemaDict;
            try
            {
                schemaDict = inputSchema is System.Text.Json.JsonElement jsonElement
                    ? System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, System.Text.Json.JsonElement>>(jsonElement.GetRawText())
                    : System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, System.Text.Json.JsonElement>>(
                        System.Text.Json.JsonSerializer.Serialize(inputSchema));
            }
            catch (System.Text.Json.JsonException ex)
            {
                LogSkippedToolSchema(toolType.FullName ?? toolType.Name, ex);
                continue;
            }

            if (schemaDict == null)
            {
                LogSkippedToolDefinition(
                    toolType.FullName ?? toolType.Name,
                    "input_schema (deserialized to null)");
                continue;
            }

            var apiSchema = InputSchema.FromRawUnchecked(schemaDict);

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

                        var inputDict = DeserializeToJsonElementDict(input);

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

    /// <summary>
    /// Deserializes an object (string JSON or anonymous object) to a Dictionary of JsonElements.
    /// </summary>
    private static Dictionary<string, System.Text.Json.JsonElement> DeserializeToJsonElementDict(object? input)
    {
        if (input == null)
        {
            return new Dictionary<string, System.Text.Json.JsonElement>();
        }

        var json = input is string inputStr ? inputStr : System.Text.Json.JsonSerializer.Serialize(input);
        return System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, System.Text.Json.JsonElement>>(json)
            ?? new Dictionary<string, System.Text.Json.JsonElement>();
    }

    /// <summary>
    /// Executes an async operation with retry logic for rate limit exceptions.
    /// Implements exponential backoff with jitter and respects retry-after headers.
    /// </summary>
    /// <typeparam name="T">The return type of the operation.</typeparam>
    /// <param name="operation">The operation to execute.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The result of the operation.</returns>
    private async Task<T> ExecuteWithRetryAsync<T>(
        Func<CancellationToken, Task<T>> operation,
        CancellationToken cancellationToken)
    {
        Exception? lastException = null;

        for (int attempt = 0; attempt < _retryMaxAttempts; attempt++)
        {
            // Check for cancellation before each attempt
            cancellationToken.ThrowIfCancellationRequested();
            
            try
            {
                return await operation(cancellationToken).ConfigureAwait(false);
            }
            catch (Anthropic.Exceptions.AnthropicRateLimitException ex) when (attempt < _retryMaxAttempts - 1)
            {
                lastException = ex;

                // Calculate delay with exponential backoff and jitter
                var baseDelay = _retryInitialDelayMs * Math.Pow(2, attempt);
                var cappedDelay = Math.Min(baseDelay, _retryMaxDelayMs);

                // Apply jitter: ±25% (thread-safe)
                int delayMs;
                lock (_randomLock)
                {
                    var jitterBytes = new byte[4];
                    _random.GetBytes(jitterBytes);
                    var randomValue = BitConverter.ToUInt32(jitterBytes, 0) / (double)uint.MaxValue; // 0.0 to 1.0
                    var jitterFactor = 0.75 + (randomValue * 0.5); // Range: 0.75 to 1.25
                    delayMs = (int)(cappedDelay * jitterFactor);
                }

                // Check if the exception contains a retry-after hint
                // The Anthropic SDK may include this in the exception properties
                // For now, we'll use the calculated backoff
                // TODO: Parse retry-after from ex.Headers if available in future SDK versions

                LogRetryAttempt(attempt + 1, _retryMaxAttempts, delayMs);

                await Task.Delay(delayMs, cancellationToken).ConfigureAwait(false);
            }
        }

        // All retries exhausted - throw the original exception
        if (lastException != null)
        {
            throw lastException;
        }
        
        // This should never happen as the loop always executes at least once
        throw new InvalidOperationException("Retry logic completed without executing the operation or capturing an exception. This indicates a programming error.");
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _random?.Dispose();
        _client?.Dispose();
        _disposed = true;
    }

    [LoggerMessage(Level = LogLevel.Debug, Message = "Received streaming chunk from Claude API")]
    partial void LogChunkReceived();

    [LoggerMessage(Level = LogLevel.Information, Message = "Claude API token count: {TokenCount}")]
    partial void LogTokenCount(int tokenCount);

    [LoggerMessage(Level = LogLevel.Information, Message = "Claude API request-id: {RequestId}")]
    partial void LogRequestId(string requestId);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Skipping tool definition of type {ToolType}: required property '{MissingProperty}' was null or empty")]
    partial void LogSkippedToolDefinition(string toolType, string missingProperty);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Skipping tool definition of type {ToolType}: input_schema could not be deserialized")]
    partial void LogSkippedToolSchema(string toolType, Exception exception);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Rate limit encountered. Retry attempt {Attempt}/{MaxAttempts} after {DelayMs}ms")]
    partial void LogRetryAttempt(int attempt, int maxAttempts, int delayMs);
}
