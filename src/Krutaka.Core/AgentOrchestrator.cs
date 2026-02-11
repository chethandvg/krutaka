using System.Runtime.CompilerServices;
using System.Text.Json;

namespace Krutaka.Core;

/// <summary>
/// Orchestrates the agentic loop: sends messages to Claude, processes tool calls,
/// enforces security policies, and manages conversation state.
/// Implements Pattern A (manual loop with full control) for transparency, audit logging,
/// and human-in-the-loop approvals.
/// </summary>
public sealed class AgentOrchestrator : IDisposable
{
    private readonly IClaudeClient _claudeClient;
    private readonly IToolRegistry _toolRegistry;
    private readonly ISecurityPolicy _securityPolicy;
    private readonly IAuditLogger? _auditLogger;
    private readonly CorrelationContext? _correlationContext;
    private readonly TimeSpan _toolTimeout;
    private readonly SemaphoreSlim _turnLock;
    private readonly List<object> _conversationHistory;
    private readonly Dictionary<string, bool> _approvalCache; // Tracks approved tools for session
    private TaskCompletionSource<bool>? _pendingApproval; // Blocks until approval/denial decision
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="AgentOrchestrator"/> class.
    /// </summary>
    /// <param name="claudeClient">The Claude API client.</param>
    /// <param name="toolRegistry">The tool registry for executing tools.</param>
    /// <param name="securityPolicy">The security policy for approval checks.</param>
    /// <param name="toolTimeoutSeconds">Timeout for tool execution in seconds (default: 30).</param>
    /// <param name="auditLogger">Optional audit logger for structured logging.</param>
    /// <param name="correlationContext">Optional correlation context for request tracing.</param>
    public AgentOrchestrator(
        IClaudeClient claudeClient,
        IToolRegistry toolRegistry,
        ISecurityPolicy securityPolicy,
        int toolTimeoutSeconds = 30,
        IAuditLogger? auditLogger = null,
        CorrelationContext? correlationContext = null)
    {
        _claudeClient = claudeClient ?? throw new ArgumentNullException(nameof(claudeClient));
        _toolRegistry = toolRegistry ?? throw new ArgumentNullException(nameof(toolRegistry));
        _securityPolicy = securityPolicy ?? throw new ArgumentNullException(nameof(securityPolicy));
        _auditLogger = auditLogger;
        _correlationContext = correlationContext;
        _toolTimeout = TimeSpan.FromSeconds(toolTimeoutSeconds);
        _turnLock = new SemaphoreSlim(1, 1);
        _conversationHistory = [];
        _approvalCache = [];
    }

    /// <summary>
    /// Gets the current conversation history.
    /// </summary>
    public IReadOnlyList<object> ConversationHistory => _conversationHistory.AsReadOnly();

    /// <summary>
    /// Restores conversation history from a previous session.
    /// Used by the /resume command to continue previous conversations.
    /// </summary>
    /// <param name="messages">The messages to restore from a previous session.</param>
    public void RestoreConversationHistory(IReadOnlyList<object> messages)
    {
        ArgumentNullException.ThrowIfNull(messages);
        ObjectDisposedException.ThrowIf(_disposed, this);

        _conversationHistory.Clear();
        _conversationHistory.AddRange(messages);
    }

    /// <summary>
    /// Runs the agentic loop for a single user turn.
    /// Sends the user prompt to Claude, processes tool calls, and yields events.
    /// </summary>
    /// <param name="userPrompt">The user's prompt/message.</param>
    /// <param name="systemPrompt">The system prompt defining agent behavior.</param>
    /// <param name="cancellationToken">Cancellation token for async operation.</param>
    /// <returns>An async stream of agent events.</returns>
    public async IAsyncEnumerable<AgentEvent> RunAsync(
        string userPrompt,
        string systemPrompt,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (string.IsNullOrWhiteSpace(userPrompt))
        {
            throw new ArgumentException("User prompt cannot be null or whitespace.", nameof(userPrompt));
        }

        if (string.IsNullOrWhiteSpace(systemPrompt))
        {
            throw new ArgumentException("System prompt cannot be null or whitespace.", nameof(systemPrompt));
        }

        // Acquire turn lock to serialize execution
        await _turnLock.WaitAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            // Add user message to conversation history
            var userMessage = CreateUserMessage(userPrompt);
            _conversationHistory.Add(userMessage);

            // Run the agentic loop until we get a final response
            await foreach (var evt in RunAgenticLoopAsync(systemPrompt, cancellationToken).ConfigureAwait(false))
            {
                yield return evt;
            }
        }
        finally
        {
            _turnLock.Release();
        }
    }

    /// <summary>
    /// Approves a pending tool call. This should be called in response to HumanApprovalRequired events.
    /// Unblocks the orchestrator to proceed with tool execution.
    /// </summary>
    /// <param name="toolName">The name of the tool to approve.</param>
    /// <param name="alwaysApprove">Whether to always approve this tool for the session.</param>
    public void ApproveTool(string toolName, bool alwaysApprove = false)
    {
        if (string.IsNullOrWhiteSpace(toolName))
        {
            throw new ArgumentException("Tool name cannot be null or whitespace.", nameof(toolName));
        }

        if (alwaysApprove)
        {
            _approvalCache[toolName] = true;
        }

        // Signal the pending approval to proceed
        _pendingApproval?.TrySetResult(true);
    }

    /// <summary>
    /// Denies a pending tool call. This should be called in response to HumanApprovalRequired events.
    /// The tool will not be executed and a denial message is returned to Claude.
    /// </summary>
    /// <param name="toolUseId">The tool use ID to deny.</param>
    public void DenyTool(string toolUseId)
    {
        if (string.IsNullOrWhiteSpace(toolUseId))
        {
            throw new ArgumentException("Tool use ID cannot be null or whitespace.", nameof(toolUseId));
        }

        // Signal the pending approval as denied
        _pendingApproval?.TrySetResult(false);
    }

    /// <summary>
    /// Internal agentic loop that processes tool calls until a final response is received.
    /// </summary>
    private async IAsyncEnumerable<AgentEvent> RunAgenticLoopAsync(
        string systemPrompt,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var toolDefinitions = _toolRegistry.GetToolDefinitions();

        while (true)
        {
            // Track tool calls from this response
            var toolCalls = new List<ToolCall>();
            string? finalResponseContent = null;
            string? finalStopReason = null;

            // Clear any stale request-id before starting a new Claude request
            _correlationContext?.ClearRequestId();

            // Stream the response from Claude
            await foreach (var evt in _claudeClient.SendMessageAsync(
                _conversationHistory,
                systemPrompt,
                toolDefinitions,
                cancellationToken).ConfigureAwait(false))
            {
                // Update correlation context before yielding to ensure state is set
                // even if the caller stops enumerating early
                if (evt is RequestIdCaptured requestIdCaptured)
                {
                    _correlationContext?.SetRequestId(requestIdCaptured.RequestId);
                }

                // Yield streaming events to caller
                yield return evt;

                // Track tool calls and final response
                switch (evt)
                {
                    case ToolCallStarted toolCallStarted:
                        toolCalls.Add(new ToolCall(
                            toolCallStarted.ToolName,
                            toolCallStarted.ToolUseId,
                            toolCallStarted.Input));
                        break;

                    case FinalResponse finalResponse:
                        finalResponseContent = finalResponse.Content;
                        finalStopReason = finalResponse.StopReason;
                        break;
                }
            }

            // Add assistant message to conversation history
            // Include the actual content and tool calls to preserve conversation context
            var assistantMessage = CreateAssistantMessage(finalResponseContent, toolCalls, finalStopReason ?? "end_turn");
            _conversationHistory.Add(assistantMessage);

            // Check if we're done (no tool use)
            if (finalStopReason != "tool_use" || toolCalls.Count == 0)
            {
                break;
            }

            // Process tool calls
            var toolResults = new List<object>();

            foreach (var toolCall in toolCalls)
            {
                // Check if approval is required and not already granted for this session
                var approvalRequired = _securityPolicy.IsApprovalRequired(toolCall.Name);
                var alwaysApprove = _approvalCache.ContainsKey(toolCall.Name);
                
                if (approvalRequired && !alwaysApprove)
                {
                    // Create a TaskCompletionSource to block until the caller approves or denies
                    _pendingApproval = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                    
                    yield return new HumanApprovalRequired(toolCall.Name, toolCall.Id, toolCall.Input);
                    
                    // Block until ApproveTool or DenyTool is called.
                    // Use try-finally to ensure _pendingApproval is cleaned up even on cancellation.
                    bool approved;
                    try
                    {
                        approved = await _pendingApproval.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
                    }
                    finally
                    {
                        _pendingApproval = null;
                    }
                    
                    if (!approved)
                    {
                        // Tool was denied - send denial message as tool result
                        var denialMessage = $"The user denied execution of {toolCall.Name}. The user chose not to allow this operation. Please try a different approach or ask the user for clarification.";
                        yield return new ToolCallFailed(toolCall.Name, toolCall.Id, denialMessage);
                        toolResults.Add(CreateToolResult(toolCall.Id, denialMessage, false));
                        continue;
                    }
                    
                    // Update alwaysApprove state (may have been set by ApproveTool)
                    alwaysApprove = _approvalCache.ContainsKey(toolCall.Name);
                }

                // Execute the tool with timeout
                var toolResult = await ExecuteToolAsync(toolCall, approvalRequired, alwaysApprove, cancellationToken).ConfigureAwait(false);

                // Yield the appropriate event
                if (toolResult.IsError)
                {
                    yield return new ToolCallFailed(toolCall.Name, toolCall.Id, toolResult.Content);
                }
                else
                {
                    yield return new ToolCallCompleted(toolCall.Name, toolCall.Id, toolResult.Content);
                }

                toolResults.Add(CreateToolResult(toolCall.Id, toolResult.Content, toolResult.IsError));
            }

            // Add user message with tool results
            // Tool-result ordering invariant: tool results must come first in the user message
            // Ensure exactly N results for N tool calls
            if (toolResults.Count > 0)
            {
                var userMessageWithResults = CreateUserMessageWithToolResults(toolResults);
                _conversationHistory.Add(userMessageWithResults);
            }
        }
    }

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
            contentBlocks.Add(new
            {
                type = "tool_use",
                id = toolCall.Id,
                name = toolCall.Name,
                input = toolCall.Input
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
    /// Disposes the orchestrator and releases resources.
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _turnLock.Dispose();
        _disposed = true;
    }

    /// <summary>
    /// Executes a tool and returns the result.
    /// Handles timeout and error cases, returning an appropriate result.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Tool execution errors should not crash the agentic loop - errors are returned to Claude as tool results")]
    private async Task<ToolResult> ExecuteToolAsync(ToolCall toolCall, bool approvalRequired, bool alwaysApprove, CancellationToken cancellationToken)
    {
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        
        try
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(_toolTimeout);

            JsonElement inputElement;
            try
            {
                inputElement = JsonSerializer.Deserialize<JsonElement>(toolCall.Input);
            }
            catch (JsonException ex)
            {
                var errorMessage = $"Invalid JSON input for tool {toolCall.Name}: {ex.Message}";
                stopwatch.Stop();
                
                // Log tool execution failure (only if audit logger and correlation context are provided)
                if (_auditLogger != null && _correlationContext != null)
                {
                    _auditLogger.LogToolExecution(
                        _correlationContext,
                        toolCall.Name,
                        false, // not approved (JSON parsing failed)
                        false,
                        stopwatch.ElapsedMilliseconds,
                        errorMessage.Length,
                        errorMessage);
                }
                
                return new ToolResult(errorMessage, IsError: true);
            }

            var result = await _toolRegistry.ExecuteAsync(toolCall.Name, inputElement, timeoutCts.Token).ConfigureAwait(false);
            stopwatch.Stop();
            
            // Log successful tool execution (only if audit logger and correlation context are provided)
            if (_auditLogger != null && _correlationContext != null)
            {
                _auditLogger.LogToolExecution(
                    _correlationContext,
                    toolCall.Name,
                    !approvalRequired || alwaysApprove, // approved if no approval required, or if always-approve is set
                    alwaysApprove,
                    stopwatch.ElapsedMilliseconds,
                    result.Length,
                    null);
            }

            return new ToolResult(result, IsError: false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            // Tool execution timed out
            stopwatch.Stop();
            var errorMessage = $"Tool execution timed out after {_toolTimeout.TotalSeconds} seconds";
            
            // Log timeout (only if audit logger and correlation context are provided)
            if (_auditLogger != null && _correlationContext != null)
            {
                _auditLogger.LogToolExecution(
                    _correlationContext,
                    toolCall.Name,
                    !approvalRequired || alwaysApprove, // approved if no approval required, or if always-approve is set
                    alwaysApprove,
                    stopwatch.ElapsedMilliseconds,
                    0,
                    errorMessage);
            }
            
            return new ToolResult(errorMessage, IsError: true);
        }
        catch (Exception ex)
        {
            // Tool execution failed - don't crash the loop, return error to Claude
            stopwatch.Stop();
            var errorMessage = $"Tool execution failed: {ex.Message}";
            
            // Log execution failure (only if audit logger and correlation context are provided)
            if (_auditLogger != null && _correlationContext != null)
            {
                _auditLogger.LogToolExecution(
                    _correlationContext,
                    toolCall.Name,
                    !approvalRequired || alwaysApprove, // approved if no approval required, or if always-approve is set
                    alwaysApprove,
                    stopwatch.ElapsedMilliseconds,
                    0,
                    errorMessage);
            }
            
            return new ToolResult(errorMessage, IsError: true);
        }
    }

    /// <summary>
    /// Represents a tool call extracted from the assistant's response.
    /// </summary>
    private sealed record ToolCall(string Name, string Id, string Input);

    /// <summary>
    /// Represents the result of a tool execution.
    /// </summary>
    private sealed record ToolResult(string Content, bool IsError);
}
