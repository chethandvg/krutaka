using System.Collections.Concurrent;
using System.Globalization;
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
    private readonly ISessionAccessStore? _sessionAccessStore;
    private readonly IAuditLogger? _auditLogger;
    private readonly CorrelationContext? _correlationContext;
    private readonly ContextCompactor? _contextCompactor;
    private readonly int _maxToolResultCharacters;
    private readonly TimeSpan _toolTimeout;
    private readonly TimeSpan _approvalTimeout;
    private readonly SemaphoreSlim _turnLock;
    private readonly List<object> _conversationHistory;
    private readonly object _conversationHistoryLock = new(); // Protects conversation history for thread-safe access
    private readonly ConcurrentDictionary<string, bool> _approvalCache; // Tracks approved tools for session (thread-safe)
    private readonly object _approvalStateLock = new(); // Protects approval state fields from race conditions
    private TaskCompletionSource<bool>? _pendingApproval; // Blocks until approval/denial decision for tools
    private string? _pendingToolUseId; // Tracks the tool_use_id of the pending approval request
    private string? _pendingToolName; // Tracks the tool name of the pending approval request
    private TaskCompletionSource<DirectoryAccessApprovalResult>? _pendingDirectoryApproval; // Blocks until directory access approval/denial
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="AgentOrchestrator"/> class.
    /// </summary>
    /// <param name="claudeClient">The Claude API client.</param>
    /// <param name="toolRegistry">The tool registry for executing tools.</param>
    /// <param name="securityPolicy">The security policy for approval checks.</param>
    /// <param name="toolTimeoutSeconds">Timeout for tool execution in seconds (default: 30).</param>
    /// <param name="approvalTimeoutSeconds">Timeout for human approval waits in seconds (default: 300 = 5 minutes, 0 = infinite).</param>
    /// <param name="maxToolResultCharacters">Maximum characters allowed in a single tool result before truncation. 
    /// Defaults to 200,000 (~50K tokens). Set to 0 to derive from maxTokens (maxTokens × 4).</param>
    /// <param name="sessionAccessStore">Optional session access store for directory access grants (v0.2.0).</param>
    /// <param name="auditLogger">Optional audit logger for structured logging.</param>
    /// <param name="correlationContext">Optional correlation context for request tracing.</param>
    /// <param name="contextCompactor">Optional context compactor for automatic context window management.</param>
    public AgentOrchestrator(
        IClaudeClient claudeClient,
        IToolRegistry toolRegistry,
        ISecurityPolicy securityPolicy,
        int toolTimeoutSeconds = 30,
        int approvalTimeoutSeconds = 300,
        int maxToolResultCharacters = DefaultMaxToolResultCharacters,
        ISessionAccessStore? sessionAccessStore = null,
        IAuditLogger? auditLogger = null,
        CorrelationContext? correlationContext = null,
        ContextCompactor? contextCompactor = null)
    {
        _claudeClient = claudeClient ?? throw new ArgumentNullException(nameof(claudeClient));
        _toolRegistry = toolRegistry ?? throw new ArgumentNullException(nameof(toolRegistry));
        _securityPolicy = securityPolicy ?? throw new ArgumentNullException(nameof(securityPolicy));
        _sessionAccessStore = sessionAccessStore;
        _auditLogger = auditLogger;
        _correlationContext = correlationContext;
        _contextCompactor = contextCompactor;
        _maxToolResultCharacters = maxToolResultCharacters > 0 ? maxToolResultCharacters : DefaultMaxToolResultCharacters;
        _toolTimeout = TimeSpan.FromSeconds(toolTimeoutSeconds);
        if (approvalTimeoutSeconds < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(approvalTimeoutSeconds), "Approval timeout must be non-negative (0 = infinite).");
        }

        _approvalTimeout = approvalTimeoutSeconds == 0 ? Timeout.InfiniteTimeSpan : TimeSpan.FromSeconds(approvalTimeoutSeconds);
        _turnLock = new SemaphoreSlim(1, 1);
        _conversationHistory = [];
        _approvalCache = new ConcurrentDictionary<string, bool>();
    }

    /// <summary>
    /// Gets the current conversation history.
    /// Thread-safe: Returns a defensive copy of the conversation history.
    /// Uses a dedicated lock to avoid deadlocks during event handling.
    /// </summary>
    public IReadOnlyList<object> ConversationHistory
    {
        get
        {
            lock (_conversationHistoryLock)
            {
                // Return a defensive copy to prevent concurrent modification during enumeration
                return _conversationHistory.ToList().AsReadOnly();
            }
        }
    }

    /// <summary>
    /// Restores conversation history from a previous session.
    /// Used by the /resume command to continue previous conversations.
    /// Acquires the turn lock to prevent races with concurrent RunAsync calls.
    /// </summary>
    /// <param name="messages">The messages to restore from a previous session.</param>
    public void RestoreConversationHistory(IReadOnlyList<object> messages)
    {
        ArgumentNullException.ThrowIfNull(messages);
        ObjectDisposedException.ThrowIf(_disposed, this);

        _turnLock.Wait();
        try
        {
            lock (_conversationHistoryLock)
            {
                _conversationHistory.Clear();
                _conversationHistory.AddRange(messages);
            }
        }
        finally
        {
            _turnLock.Release();
        }
    }

    /// <summary>
    /// Clears the conversation history.
    /// Used by the /new command to start a fresh session.
    /// </summary>
    public void ClearConversationHistory()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        _turnLock.Wait();
        try
        {
            lock (_conversationHistoryLock)
            {
                _conversationHistory.Clear();
            }

            _approvalCache.Clear();
        }
        finally
        {
            _turnLock.Release();
        }
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
            lock (_conversationHistoryLock)
            {
                _conversationHistory.Add(userMessage);
            }

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
    /// Thread-safe: Can be called from any thread (typically UI thread).
    /// </summary>
    /// <param name="toolUseId">The tool use ID to approve (must match the pending request).</param>
    /// <param name="alwaysApprove">Whether to always approve this tool for the session.</param>
    public void ApproveTool(string toolUseId, bool alwaysApprove = false)
    {
        if (string.IsNullOrWhiteSpace(toolUseId))
        {
            throw new ArgumentException("Tool use ID cannot be null or whitespace.", nameof(toolUseId));
        }

        // Lock to prevent race conditions between approval validation and TCS completion
        lock (_approvalStateLock)
        {
            // Validate that the approval matches the currently pending tool request
            if (_pendingToolUseId != null && _pendingToolUseId != toolUseId)
            {
                throw new InvalidOperationException(
                    $"Approval for tool use '{toolUseId}' does not match the pending request '{_pendingToolUseId}'.");
            }

            // Check if there's actually a pending approval (could be cancelled or already handled)
            if (_pendingApproval == null)
            {
                // Silently ignore - approval may have been cancelled or already completed
                return;
            }

            if (alwaysApprove && _pendingToolName != null)
            {
                _approvalCache[_pendingToolName] = true;
            }

            // Signal the pending approval to proceed
            _pendingApproval.TrySetResult(true);
        }
    }

    /// <summary>
    /// Denies a pending tool call. This should be called in response to HumanApprovalRequired events.
    /// The tool will not be executed and a denial message is returned to Claude.
    /// Thread-safe: Can be called from any thread (typically UI thread).
    /// </summary>
    /// <param name="toolUseId">The tool use ID to deny (must match the pending request).</param>
    public void DenyTool(string toolUseId)
    {
        if (string.IsNullOrWhiteSpace(toolUseId))
        {
            throw new ArgumentException("Tool use ID cannot be null or whitespace.", nameof(toolUseId));
        }

        // Lock to prevent race conditions between denial validation and TCS completion
        lock (_approvalStateLock)
        {
            // Validate that the denial matches the currently pending tool request
            if (_pendingToolUseId != null && _pendingToolUseId != toolUseId)
            {
                throw new InvalidOperationException(
                    $"Denial for tool use '{toolUseId}' does not match the pending request '{_pendingToolUseId}'.");
            }

            // Check if there's actually a pending approval (could be cancelled or already handled)
            if (_pendingApproval == null)
            {
                // Silently ignore - approval may have been cancelled or already completed
                return;
            }

            // Signal the pending approval as denied
            _pendingApproval.TrySetResult(false);
        }
    }

    /// <summary>
    /// Approves a pending directory access request. This should be called in response to DirectoryAccessRequested events.
    /// Unblocks the orchestrator to retry tool execution with the granted access.
    /// Thread-safe: Can be called from any thread (typically UI thread).
    /// </summary>
    /// <param name="grantedLevel">The access level to grant (may be downgraded from requested).</param>
    /// <param name="createSessionGrant">Whether to create a session-wide grant for this path.</param>
    public void ApproveDirectoryAccess(AccessLevel grantedLevel, bool createSessionGrant = false)
    {
        // Lock to prevent race conditions with cancellation
        lock (_approvalStateLock)
        {
            // Check if there's actually a pending directory approval
            if (_pendingDirectoryApproval == null)
            {
                // Silently ignore - approval may have been cancelled or already completed
                return;
            }

            // Signal the pending directory approval to proceed
            _pendingDirectoryApproval.TrySetResult(new DirectoryAccessApprovalResult(true, grantedLevel, createSessionGrant));
        }
    }

    /// <summary>
    /// Denies a pending directory access request. This should be called in response to DirectoryAccessRequested events.
    /// The tool will fail with a denial message.
    /// Thread-safe: Can be called from any thread (typically UI thread).
    /// </summary>
    public void DenyDirectoryAccess()
    {
        // Lock to prevent race conditions with cancellation
        lock (_approvalStateLock)
        {
            // Check if there's actually a pending directory approval
            if (_pendingDirectoryApproval == null)
            {
                // Silently ignore - approval may have been cancelled or already completed
                return;
            }

            // Signal the pending directory approval as denied
            _pendingDirectoryApproval.TrySetResult(new DirectoryAccessApprovalResult(false, null, false));
        }
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
            // Check if context compaction is needed before each Claude request
            // This ensures compaction is evaluated even after tool-call rounds grow the history
            if (_contextCompactor != null)
            {
                await CompactIfNeededAsync(systemPrompt, cancellationToken).ConfigureAwait(false);
            }

            // Track tool calls from this response
            var toolCalls = new List<ToolCall>();
            string? finalResponseContent = null;
            string? finalStopReason = null;

            // Clear any stale request-id before starting a new Claude request
            _correlationContext?.ClearRequestId();

            // Get a snapshot of conversation history for the Claude API call
            List<object> conversationSnapshot;
            lock (_conversationHistoryLock)
            {
                conversationSnapshot = _conversationHistory.ToList();
            }

            // Stream the response from Claude
            await foreach (var evt in _claudeClient.SendMessageAsync(
                conversationSnapshot,
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
            lock (_conversationHistoryLock)
            {
                _conversationHistory.Add(assistantMessage);
            }

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
                    // Lock to ensure atomic assignment of pending state
                    TaskCompletionSource<bool> approvalTcs;
                    lock (_approvalStateLock)
                    {
                        approvalTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                        _pendingApproval = approvalTcs;
                        _pendingToolUseId = toolCall.Id;
                        _pendingToolName = toolCall.Name;
                    }
                    
                    yield return new HumanApprovalRequired(toolCall.Name, toolCall.Id, toolCall.Input);
                    
                    // Block until ApproveTool or DenyTool is called.
                    // Use try-finally to ensure _pendingApproval is cleaned up even on cancellation.
                    bool approved;
                    try
                    {
                        // Apply approval timeout if configured
                        if (_approvalTimeout != Timeout.InfiniteTimeSpan)
                        {
                            using var timeoutCts = new CancellationTokenSource(_approvalTimeout);
                            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);
                            
                            try
                            {
                                approved = await approvalTcs.Task.WaitAsync(linkedCts.Token).ConfigureAwait(false);
                            }
                            catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
                            {
                                // Approval timeout occurred (not user cancellation)
                                throw new TimeoutException($"Approval timeout ({_approvalTimeout.TotalSeconds}s) exceeded for tool '{toolCall.Name}'. " +
                                    "The user did not respond to the approval request in time.");
                            }
                        }
                        else
                        {
                            // No timeout - wait indefinitely (or until user cancels)
                            approved = await approvalTcs.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
                        }
                    }
                    finally
                    {
                        // Lock to prevent race with concurrent approval/denial
                        lock (_approvalStateLock)
                        {
                            _pendingApproval = null;
                            _pendingToolUseId = null;
                            _pendingToolName = null;
                        }
                    }
                    
                    if (!approved)
                    {
                        // Tool was denied - send denial message as tool result (is_error=true to align with ToolCallFailed)
                        var denialMessage = $"The user denied execution of {toolCall.Name}. The user chose not to allow this operation. Please try a different approach or ask the user for clarification.";
                        yield return new ToolCallFailed(toolCall.Name, toolCall.Id, denialMessage);
                        toolResults.Add(CreateToolResult(toolCall.Id, denialMessage, true));
                        continue;
                    }
                    
                    // Update alwaysApprove state (may have been set by caller)
                    alwaysApprove = _approvalCache.ContainsKey(toolCall.Name);
                }

                // Execute the tool with timeout - may throw DirectoryAccessRequiredException
                ToolResult toolResult;
                DirectoryAccessRequiredException? dirAccessException = null;
                
                try
                {
                    toolResult = await ExecuteToolAsync(toolCall, approvalRequired, alwaysApprove, cancellationToken).ConfigureAwait(false);
                }
                catch (DirectoryAccessRequiredException ex)
                {
                    dirAccessException = ex;
                    // Set a placeholder result - will be replaced after approval handling
                    toolResult = new ToolResult(string.Empty, IsError: true);
                }

                // Handle directory access approval if needed
                if (dirAccessException != null)
                {
                    // Directory access requires approval - check if session access store is available
                    if (_sessionAccessStore == null)
                    {
                        // No session store available - fail with error
                        var errorMsg = $"Directory access to '{dirAccessException.Path}' requires approval, but session access store is not configured.";
                        yield return new ToolCallFailed(toolCall.Name, toolCall.Id, errorMsg);
                        toolResults.Add(CreateToolResult(toolCall.Id, errorMsg, true));
                        continue;
                    }

                    // Create a TaskCompletionSource to block until the caller approves or denies
                    // Lock to ensure atomic assignment of pending state
                    TaskCompletionSource<DirectoryAccessApprovalResult> dirApprovalTcs;
                    lock (_approvalStateLock)
                    {
                        dirApprovalTcs = new TaskCompletionSource<DirectoryAccessApprovalResult>(TaskCreationOptions.RunContinuationsAsynchronously);
                        _pendingDirectoryApproval = dirApprovalTcs;
                    }

                    // Yield DirectoryAccessRequested event
                    yield return new DirectoryAccessRequested(dirAccessException.Path, dirAccessException.RequestedLevel, dirAccessException.Justification);

                    // Block until ApproveDirectoryAccess or DenyDirectoryAccess is called
                    DirectoryAccessApprovalResult approvalResult;
                    try
                    {
                        // Apply approval timeout if configured
                        if (_approvalTimeout != Timeout.InfiniteTimeSpan)
                        {
                            using var timeoutCts = new CancellationTokenSource(_approvalTimeout);
                            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);
                            
                            try
                            {
                                approvalResult = await dirApprovalTcs.Task.WaitAsync(linkedCts.Token).ConfigureAwait(false);
                            }
                            catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
                            {
                                // Approval timeout occurred (not user cancellation)
                                throw new TimeoutException($"Directory access approval timeout ({_approvalTimeout.TotalSeconds}s) exceeded for path '{dirAccessException.Path}'. " +
                                    "The user did not respond to the approval request in time.");
                            }
                        }
                        else
                        {
                            // No timeout - wait indefinitely (or until user cancels)
                            approvalResult = await dirApprovalTcs.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
                        }
                    }
                    finally
                    {
                        // Lock to prevent race with concurrent approval/denial
                        lock (_approvalStateLock)
                        {
                            _pendingDirectoryApproval = null;
                        }
                    }

                    if (!approvalResult.Approved || approvalResult.GrantedLevel == null)
                    {
                        // Directory access was denied
                        var denialMsg = $"Access to directory '{dirAccessException.Path}' was denied by the user.";
                        yield return new ToolCallFailed(toolCall.Name, toolCall.Id, denialMsg);
                        toolResults.Add(CreateToolResult(toolCall.Id, denialMsg, true));
                        continue;
                    }

                    // Access was approved - grant it via session store
                    try
                    {
                        // Create a temporary grant for the retry
                        // For session grants, use 1-hour TTL; for single operations, use short TTL and revoke after
                        TimeSpan ttl = approvalResult.CreateSessionGrant ? TimeSpan.FromHours(1) : TimeSpan.FromSeconds(30);
                        await _sessionAccessStore.GrantAccessAsync(
                            dirAccessException.Path,
                            approvalResult.GrantedLevel.Value,
                            ttl,
                            dirAccessException.Justification,
                            GrantSource.User,
                            cancellationToken).ConfigureAwait(false);

                        try
                        {
                            // Retry the tool execution now that access is granted
                            toolResult = await ExecuteToolAsync(toolCall, approvalRequired, alwaysApprove, cancellationToken).ConfigureAwait(false);
                        }
                        finally
                        {
                            // If this was a single-operation approval, revoke the grant immediately after execution
                            if (!approvalResult.CreateSessionGrant)
                            {
                                await _sessionAccessStore.RevokeAccessAsync(dirAccessException.Path, cancellationToken).ConfigureAwait(false);
                            }
                        }
                    }
#pragma warning disable CA1031 // Catching Exception is appropriate here to handle any grant or retry failure
                    catch (Exception grantEx)
#pragma warning restore CA1031
                    {
                        // Failed to grant access or retry execution - set error result
                        toolResult = new ToolResult($"Failed to grant directory access: {grantEx.Message}", IsError: true);
                    }
                }

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
                lock (_conversationHistoryLock)
                {
                    _conversationHistory.Add(userMessageWithResults);
                }
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
    /// Checks if context compaction is needed and performs it if so.
    /// Replaces conversation history with compacted version.
    /// Enforces a hard token limit after compaction as a safety net.
    /// </summary>
    private async Task CompactIfNeededAsync(string systemPrompt, CancellationToken cancellationToken)
    {
        int historyCount;
        lock (_conversationHistoryLock)
        {
            historyCount = _conversationHistory.Count;
        }

        if (_contextCompactor == null || historyCount == 0)
        {
            return;
        }

        List<object> historySnapshot;
        lock (_conversationHistoryLock)
        {
            historySnapshot = _conversationHistory.ToList();
        }

        var tokenCount = await _claudeClient.CountTokensAsync(historySnapshot, systemPrompt, cancellationToken).ConfigureAwait(false);

        if (_contextCompactor.ShouldCompact(tokenCount) || _contextCompactor.ExceedsHardLimit(tokenCount))
        {
            await CompactAndEnforceHardLimitAsync(historySnapshot, systemPrompt, tokenCount, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Performs context compaction and enforces the hard token limit as a safety net.
    /// If compaction alone doesn't bring tokens under the max, performs emergency truncation.
    /// </summary>
    private async Task CompactAndEnforceHardLimitAsync(
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

        // Safety net: if compaction didn't bring tokens under the hard limit,
        // perform emergency truncation to prevent API errors
        if (_contextCompactor.ExceedsHardLimit(result.CompactedTokenCount))
        {
            compactedMessages = await _contextCompactor.TruncateToFitAsync(
                compactedMessages,
                systemPrompt,
                cancellationToken).ConfigureAwait(false);
        }

        lock (_conversationHistoryLock)
        {
            _conversationHistory.Clear();
            _conversationHistory.AddRange(compactedMessages);
        }
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

            // Truncate oversized tool results to prevent them from exceeding the context window.
            // A single tool result (e.g., search_files matching thousands of lines) can produce
            // millions of characters (~1M+ tokens) that would immediately blow the API limit.
            result = TruncateToolResult(result, toolCall.Name);
            
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
        catch (DirectoryAccessRequiredException)
        {
            // Directory access requires approval - rethrow to let the agentic loop handle it
            throw;
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

    /// <summary>
    /// Default maximum number of characters allowed in a single tool result before truncation.
    /// Approximately 200K characters ≈ 50K tokens, leaving ample room for the rest of the
    /// conversation, system prompt, and tool definitions within the 200K token API limit.
    /// Configurable via <c>Agent:MaxToolResultCharacters</c> in appsettings.json.
    /// </summary>
    public const int DefaultMaxToolResultCharacters = 200_000;

    /// <summary>
    /// Truncates a tool result that exceeds the configured maximum character limit.
    /// Returns the original result if it fits within the limit.
    /// When truncated, includes a clear message indicating truncation with the original size.
    /// Preserves <c>&lt;untrusted_content&gt;</c> wrapper tags when present to maintain prompt-injection mitigation.
    /// </summary>
    private string TruncateToolResult(string result, string toolName)
    {
        if (result.Length <= _maxToolResultCharacters)
        {
            return result;
        }

        // Detect if the result is wrapped in <untrusted_content> tags
        const string openTag = "<untrusted_content>";
        const string closeTag = "</untrusted_content>";
        var isWrapped = result.StartsWith(openTag, StringComparison.Ordinal)
            && result.TrimEnd().EndsWith(closeTag, StringComparison.Ordinal);

        var truncatedContent = result[.._maxToolResultCharacters];

        // Try to cut at the last newline to avoid breaking a line mid-way.
        // Only use the newline break if it's in the latter half of the content,
        // to avoid losing too much useful output.
        var lastNewline = truncatedContent.LastIndexOf('\n');
        if (lastNewline > _maxToolResultCharacters / 2)
        {
            truncatedContent = truncatedContent[..lastNewline];
        }

        var truncationNotice = string.Create(CultureInfo.InvariantCulture,
            $"\n\n[Output truncated: tool '{toolName}' returned {result.Length:N0} characters, " +
            $"which exceeds the {_maxToolResultCharacters:N0} character limit. " +
            $"Results have been truncated. Consider using more specific search criteria or narrowing the scope.]");

        // Re-wrap in <untrusted_content> tags if the original result was wrapped,
        // to preserve prompt-injection mitigation
        if (isWrapped)
        {
            // Strip both open and close tags from the truncated content
            // (open tag will always be present; close tag may also appear if truncation
            // happens to land past where it was in the original)
            if (truncatedContent.StartsWith(openTag, StringComparison.Ordinal))
            {
                truncatedContent = truncatedContent[openTag.Length..];
            }

            // Remove any close tag that may be in the truncated content
            truncatedContent = truncatedContent.Replace(closeTag, "", StringComparison.Ordinal);

            // Place both truncated content and truncation notice inside the wrapper
            return $"{openTag}\n{truncatedContent}{truncationNotice}\n{closeTag}";
        }

        return $"{truncatedContent}{truncationNotice}";
    }

    /// <summary>
    /// Represents the result of a directory access approval request.
    /// </summary>
    private sealed record DirectoryAccessApprovalResult(
        bool Approved,
        AccessLevel? GrantedLevel,
        bool CreateSessionGrant
    );
}
