using System.Globalization;
using System.Text.Json;

namespace Krutaka.Core;

public sealed partial class AgentOrchestrator
{
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
        catch (CommandApprovalRequiredException)
        {
            // Command execution requires approval - rethrow to let the agentic loop handle it
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
    /// Prunes large tool results from older conversation turns to reduce token waste.
    /// Only affects the snapshot sent to Claude API — original conversation history is NEVER modified.
    /// </summary>
    /// <param name="messages">The conversation messages to prune (typically a snapshot).</param>
    /// <param name="currentTurnIndex">The current turn index (0-based count of user messages).</param>
    /// <param name="pruneAfterTurns">Number of turns after which tool results are eligible for pruning.</param>
    /// <param name="pruneMinChars">Minimum character count for pruning eligibility.</param>
    /// <returns>A new list with pruned messages. The input list is never modified.</returns>
    private static List<object> PruneOldToolResults(
        List<object> messages,
        int currentTurnIndex,
        int pruneAfterTurns,
        int pruneMinChars)
    {
        // Return a new list to ensure immutability of the input
        var prunedMessages = new List<object>(messages.Count);

        // Track turn index - starts at -1, incremented when we see a new user prompt
        var turnIndex = -1;

        foreach (var message in messages)
        {
            // Parse the message as a dynamic object to read its properties
            var messageJson = JsonSerializer.Serialize(message);
            using var messageDoc = JsonDocument.Parse(messageJson);
            var root = messageDoc.RootElement;

            // Get role — skip if not present (shouldn't happen but be defensive)
            if (!root.TryGetProperty("role", out var roleElement))
            {
                prunedMessages.Add(message);
                continue;
            }

            var role = roleElement.GetString();

            // Track turn index for user messages
            if (role == "user")
            {
                // Check if this is a tool_result message or a regular user prompt
                // Tool result messages don't advance the turn counter
                bool isToolResultMessage = false;
                if (root.TryGetProperty("content", out var checkContent) &&
                    checkContent.ValueKind == JsonValueKind.Array)
                {
                    foreach (var checkBlock in checkContent.EnumerateArray())
                    {
                        if (checkBlock.TryGetProperty("type", out var checkType) &&
                            checkType.GetString() == "tool_result")
                        {
                            isToolResultMessage = true;
                            break;
                        }
                    }
                }

                // For regular user messages, increment turn index BEFORE calculating age
                // This ensures tool_result messages (which come after) belong to the same turn
                if (!isToolResultMessage)
                {
                    turnIndex++;
                }

                // Calculate age of this turn relative to current
                // Tool_result messages use the just-incremented turnIndex (they belong to that turn)
                var age = currentTurnIndex - turnIndex;

                // Only prune if age exceeds threshold
                if (age > pruneAfterTurns && root.TryGetProperty("content", out var contentElement))
                {
                    // Check if content is an array of content blocks
                    if (contentElement.ValueKind == JsonValueKind.Array)
                    {
                        var contentBlocks = new List<object>();
                        var hasToolResults = false;

                        foreach (var block in contentElement.EnumerateArray())
                        {
                            if (block.TryGetProperty("type", out var typeElement) &&
                                typeElement.GetString() == "tool_result")
                            {
                                hasToolResults = true;

                                // Extract properties
                                var toolUseId = block.TryGetProperty("tool_use_id", out var idElement)
                                    ? idElement.GetString() ?? ""
                                    : "";

                                var content = block.TryGetProperty("content", out var contentProp)
                                    ? contentProp.GetString() ?? ""
                                    : "";

                                var isError = block.TryGetProperty("is_error", out var isErrorElement) &&
                                              isErrorElement.GetBoolean();

                                // Prune if content exceeds minimum character threshold
                                if (content.Length > pruneMinChars)
                                {
                                    string replacementContent;
                                    if (isError)
                                    {
                                        var ageText = age == 1 ? "1 turn ago" : string.Create(CultureInfo.InvariantCulture, $"{age} turns ago");
                                        replacementContent = string.Create(CultureInfo.InvariantCulture,
                                            $"[Previous tool error truncated — {content.Length:N0} chars. Original error occurred {ageText}.]");
                                    }
                                    else
                                    {
                                        replacementContent = string.Create(CultureInfo.InvariantCulture,
                                            $"[Previous tool result truncated — {content.Length:N0} chars. Use read_file to re-read if needed.]");
                                    }

                                    // Create pruned tool result
                                    contentBlocks.Add(new
                                    {
                                        type = "tool_result",
                                        tool_use_id = toolUseId,
                                        content = replacementContent,
                                        is_error = isError
                                    });
                                }
                                else
                                {
                                    // Keep small tool results as-is - reconstruct as anonymous object to preserve type information
                                    // Using JsonSerializer.Deserialize<object> creates JsonElement which loses type reflection
                                    contentBlocks.Add(new
                                    {
                                        type = "tool_result",
                                        tool_use_id = toolUseId,
                                        content,
                                        is_error = isError
                                    });
                                }
                            }
                            else
                            {
                                // Keep non-tool_result blocks as-is - reconstruct to preserve type information
                                // Check if it's a text block or tool_use block
                                if (block.TryGetProperty("type", out var blockType))
                                {
                                    var blockTypeStr = blockType.GetString();
                                    if (blockTypeStr == "text")
                                    {
                                        var text = block.TryGetProperty("text", out var textProp)
                                            ? textProp.GetString() ?? ""
                                            : "";
                                        contentBlocks.Add(new { type = "text", text });
                                    }
                                    else if (blockTypeStr == "tool_use")
                                    {
                                        var id = block.TryGetProperty("id", out var idProp)
                                            ? idProp.GetString() ?? ""
                                            : "";
                                        var name = block.TryGetProperty("name", out var nameProp)
                                            ? nameProp.GetString() ?? ""
                                            : "";
                                        
                                        // For tool_use input, we need to preserve the JsonElement
                                        JsonElement input;
                                        if (block.TryGetProperty("input", out var inputProp))
                                        {
                                            input = inputProp;
                                        }
                                        else
                                        {
                                            using var emptyDoc = JsonDocument.Parse("{}");
                                            input = emptyDoc.RootElement.Clone();
                                        }
                                        
                                        contentBlocks.Add(new
                                        {
                                            type = "tool_use",
                                            id,
                                            name,
                                            input
                                        });
                                    }
                                    else
                                    {
                                        // Unknown block type - deserialize as fallback
                                        contentBlocks.Add(JsonSerializer.Deserialize<object>(block.GetRawText())!);
                                    }
                                }
                                else
                                {
                                    // No type property - deserialize as fallback
                                    contentBlocks.Add(JsonSerializer.Deserialize<object>(block.GetRawText())!);
                                }
                            }
                        }

                        // If we found and modified tool results, create a new message object
                        if (hasToolResults)
                        {
                            prunedMessages.Add(new
                            {
                                role = "user",
                                content = contentBlocks
                            });
                        }
                        else
                        {
                            // No tool results, keep original message
                            prunedMessages.Add(message);
                        }
                    }
                    else
                    {
                        // Content is not an array (simple string), keep as-is
                        prunedMessages.Add(message);
                    }
                }
                else
                {
                    // Age within threshold or no content, keep original message
                    prunedMessages.Add(message);
                }
            }
            else
            {
                // Not a user message, keep as-is
                prunedMessages.Add(message);
            }
        }

        return prunedMessages;
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
