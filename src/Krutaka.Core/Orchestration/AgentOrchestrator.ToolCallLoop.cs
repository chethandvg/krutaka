using System.Runtime.CompilerServices;
using System.Text.Json;

namespace Krutaka.Core;

public sealed partial class AgentOrchestrator
{
    /// <summary>
    /// Builds a command signature for approval cache lookup.
    /// Format: "executable arg1 arg2 arg3..."
    /// NOTE: This method is also present in RunCommandTool.cs and must stay in sync.
    /// </summary>
    private static string BuildCommandSignature(CommandExecutionRequest request)
    {
        var args = string.Join(" ", request.Arguments);
        return string.IsNullOrEmpty(args) ? request.Executable : $"{request.Executable} {args}";
    }

    /// <summary>
    /// Attempts to consume <paramref name="amount"/> from the given budget <paramref name="dimension"/>.
    /// Returns a <see cref="BudgetWarning"/> event if the 80% threshold was just crossed for the first time,
    /// or a <see cref="BudgetExhausted"/> event if the limit was reached.
    /// Both return values can be <see langword="null"/> if neither threshold was triggered.
    /// Thread-safe: <see cref="_budgetWarnedDimensions"/> is only accessed from the sequential agentic loop.
    /// </summary>
    private (BudgetWarning? Warning, BudgetExhausted? Exhausted) ConsumeAndCheckBudget(BudgetDimension dimension, int amount)
    {
        if (_budgetTracker == null)
        {
            return (null, null);
        }

        bool consumed = _budgetTracker.TryConsume(dimension, amount);
        if (!consumed)
        {
            _budgetExhausted = true;
            return (null, new BudgetExhausted(dimension));
        }

        // Check if we crossed the 80% warning threshold for the first time for this dimension
        if (_budgetTracker is TaskBudgetTracker concreteTracker)
        {
            double percentage = concreteTracker.GetPercentage(dimension);
            if (percentage >= 0.8 && _budgetWarnedDimensions.Add(dimension))
            {
                return (new BudgetWarning(dimension, percentage), null);
            }
        }
        else
        {
            // For non-concrete trackers: use snapshot to get percentage
            var snapshot = _budgetTracker.GetSnapshot();
            double percentage = dimension switch
            {
                BudgetDimension.Tokens => snapshot.TokensPercentage,
                BudgetDimension.ToolCalls => snapshot.ToolCallsPercentage,
                BudgetDimension.FilesModified => snapshot.FilesModifiedPercentage,
                BudgetDimension.ProcessesSpawned => snapshot.ProcessesSpawnedPercentage,
                _ => 0.0
            };

            if (percentage >= 0.8 && _budgetWarnedDimensions.Add(dimension))
            {
                return (new BudgetWarning(dimension, percentage), null);
            }
        }

        return (null, null);
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
            // Enforce terminal Aborted state — must block all Claude API calls.
            // This ensures no tokens are consumed and no assistant output is emitted
            // after an abort command (deadman switch, anomaly stop, or user abort).
            // Also guard against a budget that was fully consumed in a prior iteration:
            // IsExhausted covers the case where a dimension just reached its cap (counter == limit),
            // while _budgetExhausted handles mid-batch TryConsume failures (no state manager needed).
            if (_stateManager?.CurrentState == AgentState.Aborted ||
                _budgetTracker?.IsExhausted == true ||
                _budgetExhausted)
            {
                break;
            }

            // Check if context compaction is needed before each Claude request
            // This ensures compaction is evaluated even after tool-call rounds grow the history
            // Wrap in try-catch to prevent compaction failures from crashing the agentic loop
            CompactionCompleted? compactionEvent = null;
            if (_contextCompactor != null)
            {
                try
                {
                    compactionEvent = await CompactIfNeededAsync(systemPrompt, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    // Rethrow cancellation to allow proper shutdown
                    throw;
                }
#pragma warning disable CA1031 // Intentionally catch all non-cancellation exceptions — compaction failure must not crash the agentic loop
                catch (Exception ex)
#pragma warning restore CA1031
                {
                    // Log compaction failure for diagnostics
                    System.Diagnostics.Debug.WriteLine($"WARNING: Context compaction failed: {ex.Message}");
                    // Compaction is optimization, not correctness — continue without it
                }
            }

            // Yield compaction event outside try-catch (C# constraint: cannot yield in try-catch)
            if (compactionEvent != null)
            {
                yield return compactionEvent;
            }

            // Track tool calls from this response
            var toolCalls = new List<ToolCall>();
            string? finalResponseContent = null;
            string? finalStopReason = null;
            int finalResponseInputTokens = 0;
            int finalResponseOutputTokens = 0;

            // Clear any stale request-id before starting a new Claude request
            _correlationContext?.ClearRequestId();

            // Get a snapshot of conversation history for the Claude API call
            List<object> conversationSnapshot;
            lock (_conversationHistoryLock)
            {
                conversationSnapshot = _conversationHistory.ToList();
            }

            // Calculate current turn index (count of non-tool-result user messages in history)
            var currentTurnIndex = conversationSnapshot.Count(msg =>
            {
                var msgJson = JsonSerializer.Serialize(msg);
                using var msgDoc = JsonDocument.Parse(msgJson);
                if (!msgDoc.RootElement.TryGetProperty("role", out var roleElement) ||
                    roleElement.GetString() != "user")
                {
                    return false;
                }

                // Check if this is a tool_result message
                if (msgDoc.RootElement.TryGetProperty("content", out var contentElement) &&
                    contentElement.ValueKind == JsonValueKind.Array)
                {
                    foreach (var block in contentElement.EnumerateArray())
                    {
                        if (block.TryGetProperty("type", out var typeElement) &&
                            typeElement.GetString() == "tool_result")
                        {
                            return false; // This is a tool_result message, don't count it
                        }
                    }
                }

                return true; // This is a regular user message
            });

            // Apply tool result pruning to reduce token waste from old tool outputs
            // This creates a new list and NEVER modifies the original conversation history or JSONL
            conversationSnapshot = PruneOldToolResults(
                conversationSnapshot,
                currentTurnIndex,
                _pruneToolResultsAfterTurns,
                _pruneToolResultMinChars);

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
                        finalResponseInputTokens = finalResponse.InputTokens;
                        finalResponseOutputTokens = finalResponse.OutputTokens;
                        break;
                }
            }

            // Consume token budget for this API call (v0.5.0).
            // Tokens are reported in FinalResponse populated by ClaudeClientWrapper from the streaming API.
            // NOTE: If the AI layer reports 0 tokens (e.g., in tests using mock clients), consumption is skipped.
            if (_budgetTracker != null)
            {
                int totalTokens = finalResponseInputTokens + finalResponseOutputTokens;
                if (totalTokens > 0)
                {
                    var (tokenWarning, tokenExhausted) = ConsumeAndCheckBudget(BudgetDimension.Tokens, totalTokens);
                    if (tokenWarning != null)
                    {
                        yield return tokenWarning;
                    }

                    if (tokenExhausted != null)
                    {
                        yield return tokenExhausted;
                        _stateManager?.RequestAbort("Token budget exhausted.");
                        break;
                    }
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

            // Process tool calls through the per-tool-call pipeline
            var toolResults = new List<object>();

            foreach (var toolCall in toolCalls)
            {
                await foreach (var evt in ProcessSingleToolCallAsync(toolCall, toolResults, cancellationToken).ConfigureAwait(false))
                {
                    yield return evt;
                }

                // Exit tool call loop if agent was aborted or budget was exhausted during processing.
                // The budget check covers the case where _stateManager is null (normal session wiring).
                if (_stateManager?.CurrentState == AgentState.Aborted || _budgetExhausted)
                {
                    break;
                }
            }

            // Exit agentic loop if agent was aborted or budget was exhausted during tool processing (including budget exhaustion)
            if (_stateManager?.CurrentState == AgentState.Aborted || _budgetExhausted)
            {
                break;
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
    /// Processes a single tool call through the per-tool-call pipeline:
    /// state check → pause/resume → budget check → approval → execution → directory/command approval → event emission.
    /// Yields appropriate <see cref="AgentEvent"/> values and populates <paramref name="toolResults"/>.
    /// Terminates early (via <c>yield break</c>) on abort or denial.
    /// </summary>
    private async IAsyncEnumerable<AgentEvent> ProcessSingleToolCallAsync(
        ToolCall toolCall,
        List<object> toolResults,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        // Check agent state before executing each tool (v0.5.0)
        if (_stateManager != null)
        {
            if (_stateManager.CurrentState == AgentState.Paused)
            {
                // Emit AgentPaused immediately so callers can notify the user before blocking
                yield return new AgentPaused(_stateManager.PauseReason ?? "Agent is paused.");

                // Block until state leaves Paused (uses WaitWhilePausedAsync in StateMachine partial)
                await WaitWhilePausedAsync(cancellationToken).ConfigureAwait(false);

                if (_stateManager.CurrentState == AgentState.Running)
                {
                    yield return new AgentResumed();
                }
            }

            if (_stateManager.CurrentState == AgentState.Aborted)
            {
                yield break;
            }
        }

        // Check ToolCalls budget before executing each tool (v0.5.0, S10)
        if (_budgetTracker != null)
        {
            var (toolCallWarning, toolCallExhausted) = ConsumeAndCheckBudget(BudgetDimension.ToolCalls, 1);
            if (toolCallWarning != null)
            {
                yield return toolCallWarning;
            }

            if (toolCallExhausted != null)
            {
                var exhaustMsg = "Tool call budget exhausted. The agent has reached the maximum number of allowed tool invocations.";
                yield return toolCallExhausted;
                _stateManager?.RequestAbort("ToolCalls budget exhausted.");
                yield return new ToolCallFailed(toolCall.Name, toolCall.Id, exhaustMsg);
                toolResults.Add(CreateToolResult(toolCall.Id, exhaustMsg, true));
                yield break;
            }

            // Pre-check FilesModified/ProcessesSpawned budget before tools that cause side effects (v0.5.0, S10).
            // This prevents exceeding the cap by one extra mutation/spawn when the limit is already reached.
            BudgetDimension? secondaryDimension = toolCall.Name switch
            {
                "write_file" or "edit_file" => BudgetDimension.FilesModified,
                "run_command" => BudgetDimension.ProcessesSpawned,
                _ => null
            };

            if (secondaryDimension.HasValue)
            {
                var (secWarning, secExhausted) = ConsumeAndCheckBudget(secondaryDimension.Value, 1);
                if (secWarning != null)
                {
                    yield return secWarning;
                }

                if (secExhausted != null)
                {
                    var exhaustMsg = $"{secondaryDimension.Value} budget exhausted. The agent has reached the maximum allowed limit.";
                    yield return secExhausted;
                    _stateManager?.RequestAbort($"{secondaryDimension.Value} budget exhausted.");
                    yield return new ToolCallFailed(toolCall.Name, toolCall.Id, exhaustMsg);
                    toolResults.Add(CreateToolResult(toolCall.Id, exhaustMsg, true));
                    yield break;
                }
            }
        }

        // Check if approval is required and not already granted for this session
        var approvalRequired = _securityPolicy.IsApprovalRequired(toolCall.Name);
        var alwaysApprove = _approvalCache.ContainsKey(toolCall.Name);

        // Determine effective approval requirement considering autonomy level (v0.5.0).
        // With a provider: ShouldAutoApprove drives the decision for ALL tiers including Safe,
        // so Supervised (Level 0) will prompt even for tools the security policy marks as Safe.
        // Without a provider: fall back to existing binary behavior (backward compatible).
        bool isAutoApproved = false;
        bool needsHumanApproval;

        if (alwaysApprove)
        {
            needsHumanApproval = false;
        }
        else if (_autonomyLevelProvider != null)
        {
            isAutoApproved = _autonomyLevelProvider.ShouldAutoApprove(toolCall.Name, approvalRequired);
            needsHumanApproval = !isAutoApproved;
        }
        else
        {
            // No provider: existing behavior — only prompt when security policy requires it
            needsHumanApproval = approvalRequired;
        }

        if (isAutoApproved)
        {
            _auditLogger?.Log(new ToolAutoApprovedEvent
            {
                SessionId = _correlationContext?.SessionId ?? Guid.Empty,
                TurnId = _correlationContext?.TurnId ?? 0,
                RequestId = _correlationContext?.RequestId,
                ToolName = toolCall.Name,
                Level = _autonomyLevelProvider!.GetLevel(),
                WasApprovalRequired = approvalRequired
            });
        }
        else if (needsHumanApproval)
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
                yield break;
            }

            // Update alwaysApprove state (may have been set by caller)
            alwaysApprove = _approvalCache.ContainsKey(toolCall.Name);
        }

        // Execute the tool with timeout - may throw DirectoryAccessRequiredException or CommandApprovalRequiredException
        ToolResult toolResult;
        DirectoryAccessRequiredException? dirAccessException = null;
        CommandApprovalRequiredException? cmdApprovalException = null;

        try
        {
            toolResult = await ExecuteToolAsync(toolCall, approvalRequired, alwaysApprove, isAutoApproved, cancellationToken).ConfigureAwait(false);
        }
        catch (DirectoryAccessRequiredException ex)
        {
            dirAccessException = ex;
            // Set a placeholder result - will be replaced after approval handling
            toolResult = new ToolResult(string.Empty, IsError: true);
        }
        catch (CommandApprovalRequiredException ex)
        {
            cmdApprovalException = ex;
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
                yield break;
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
                yield break;
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
                    toolResult = await ExecuteToolAsync(toolCall, approvalRequired, alwaysApprove, false, cancellationToken).ConfigureAwait(false);
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

        // Handle command approval if needed (v0.3.0)
        if (cmdApprovalException != null)
        {
            // Check if this command was previously approved with "Always" (session-level)
            var commandSignature = BuildCommandSignature(cmdApprovalException.Request);
            if (_sessionCommandApprovals.ContainsKey(commandSignature))
            {
                // Command was approved with "Always" - auto-approve and retry execution without prompting
                _commandApprovalCache?.AddApproval(commandSignature, TimeSpan.FromSeconds(30)); // Short TTL for single execution

                try
                {
                    toolResult = await ExecuteToolAsync(toolCall, approvalRequired: false, alwaysApprove, false, cancellationToken).ConfigureAwait(false);
                    _commandApprovalCache?.RemoveApproval(commandSignature);
                }
#pragma warning disable CA1031 // Catching Exception is appropriate here to handle any retry failure
                catch (Exception retryEx)
#pragma warning restore CA1031
                {
                    _commandApprovalCache?.RemoveApproval(commandSignature);
                    toolResult = new ToolResult($"Failed to execute command after auto-approval: {retryEx.Message}", IsError: true);
                }
            }
            else
            {
                // Command execution requires approval - create a TaskCompletionSource to block
                TaskCompletionSource<bool> cmdApprovalTcs;
                lock (_approvalStateLock)
                {
                    cmdApprovalTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                    _pendingCommandApproval = cmdApprovalTcs;
                    _pendingCommandAlwaysApprove = false; // Reset flag
                }

                // Yield CommandApprovalRequested event
                yield return new CommandApprovalRequested(cmdApprovalException.Request, cmdApprovalException.Decision);

                // Block until ApproveCommand or DenyCommand is called
                bool commandApproved;
                bool alwaysApproveCommand;
                try
                {
                    // Apply approval timeout if configured
                    if (_approvalTimeout != Timeout.InfiniteTimeSpan)
                    {
                        using var timeoutCts = new CancellationTokenSource(_approvalTimeout);
                        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);

                        try
                        {
                            commandApproved = await cmdApprovalTcs.Task.WaitAsync(linkedCts.Token).ConfigureAwait(false);
                        }
                        catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
                        {
                            // Approval timeout occurred (not user cancellation)
                            throw new TimeoutException($"Command approval timeout ({_approvalTimeout.TotalSeconds}s) exceeded for command '{cmdApprovalException.Request.Executable}'. " +
                                "The user did not respond to the approval request in time.");
                        }
                    }
                    else
                    {
                        // No timeout - wait indefinitely (or until user cancels)
                        commandApproved = await cmdApprovalTcs.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
                    }

                    // Capture alwaysApprove flag before clearing pending state
                    lock (_approvalStateLock)
                    {
                        alwaysApproveCommand = _pendingCommandAlwaysApprove;
                    }
                }
                finally
                {
                    // Lock to prevent race with concurrent approval/denial
                    lock (_approvalStateLock)
                    {
                        _pendingCommandApproval = null;
                        _pendingCommandAlwaysApprove = false;
                    }
                }

                if (!commandApproved)
                {
                    // Command execution was denied
                    var denialMsg = $"Command execution '{cmdApprovalException.Request.Executable} {string.Join(" ", cmdApprovalException.Request.Arguments)}' was denied by the user.";
                    yield return new ToolCallFailed(toolCall.Name, toolCall.Id, denialMsg);
                    toolResults.Add(CreateToolResult(toolCall.Id, denialMsg, true));
                    yield break;
                }

                // Command was approved - add to session cache if "Always" was selected
                if (alwaysApproveCommand)
                {
                    _sessionCommandApprovals.TryAdd(commandSignature, true);
                }

                // Add to approval cache before retry (short TTL for single execution)
                _commandApprovalCache?.AddApproval(commandSignature, TimeSpan.FromSeconds(30));

                // Retry execution
                try
                {
                    toolResult = await ExecuteToolAsync(toolCall, approvalRequired: false, alwaysApprove, false, cancellationToken).ConfigureAwait(false);

                    // Remove approval from cache after successful execution
                    _commandApprovalCache?.RemoveApproval(commandSignature);
                }
#pragma warning disable CA1031 // Catching Exception is appropriate here to handle any retry failure
                catch (Exception retryEx)
#pragma warning restore CA1031
                {
                    // Remove approval from cache even on failure
                    _commandApprovalCache?.RemoveApproval(commandSignature);

                    // Failed to retry execution - set error result
                    toolResult = new ToolResult($"Failed to execute command after approval: {retryEx.Message}", IsError: true);
                }
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
}
