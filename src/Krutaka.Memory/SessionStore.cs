using System.Runtime.CompilerServices;
using System.Text.Json;
using Krutaka.Core;

namespace Krutaka.Memory;

/// <summary>
/// JSONL-based session persistence implementation.
/// Each session is stored as a UUID-named JSONL file with one event per line.
/// Storage path: ~/.krutaka/sessions/{encoded-project-path}/{session-id}.jsonl
/// </summary>
public sealed class SessionStore : ISessionStore, IDisposable
{
    private readonly string _sessionPath;
    private readonly string _metadataPath;
    private readonly DateTimeOffset _startedAt;
    private readonly SemaphoreSlim _fileLock = new(1, 1);
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = false
    };
    private static readonly JsonSerializerOptions MetadataJsonOptions = new()
    {
        WriteIndented = true
    };

    /// <summary>
    /// Creates a new SessionStore instance for the specified project and session.
    /// </summary>
    /// <param name="projectPath">The project directory path (will be encoded for safe storage).</param>
    /// <param name="sessionId">The session identifier (creates new if null).</param>
    public SessionStore(string projectPath, Guid? sessionId = null)
        : this(projectPath, sessionId, null)
    {
    }

    /// <summary>
    /// Creates a new SessionStore instance with an optional custom storage root (primarily for testing).
    /// </summary>
    /// <param name="projectPath">The project directory path (will be encoded for safe storage).</param>
    /// <param name="sessionId">The session identifier (creates new if null).</param>
    /// <param name="storageRoot">Custom storage root directory (defaults to ~/.krutaka if null).</param>
    public SessionStore(string projectPath, Guid? sessionId, string? storageRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(projectPath, nameof(projectPath));

        _startedAt = DateTimeOffset.UtcNow;

        var encodedPath = EncodeProjectPath(projectPath);
        var baseDir = storageRoot ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".krutaka");

        var sessionDir = Path.Combine(baseDir, "sessions", encodedPath);

        // Ensure directory exists
        Directory.CreateDirectory(sessionDir);

        var id = sessionId ?? Guid.NewGuid();
        _sessionPath = Path.Combine(sessionDir, $"{id}.jsonl");
        _metadataPath = Path.Combine(sessionDir, $"{id}.meta.json");
    }

    /// <summary>
    /// Appends a session event to the JSONL file.
    /// Thread-safe with SemaphoreSlim.
    /// </summary>
    public async Task AppendAsync(SessionEvent sessionEvent, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(sessionEvent);

        await _fileLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var json = JsonSerializer.Serialize(sessionEvent, JsonOptions);
            await File.AppendAllTextAsync(_sessionPath, json + "\n", cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _fileLock.Release();
        }
    }

    /// <summary>
    /// Loads all events from the session JSONL file.
    /// </summary>
    public async IAsyncEnumerable<SessionEvent> LoadAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        if (!File.Exists(_sessionPath))
        {
            yield break;
        }

        // Read all lines under lock, then release before yielding
        string[] lines;
        await _fileLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            lines = await File.ReadAllLinesAsync(_sessionPath, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _fileLock.Release();
        }

        // Now yield events without holding the lock
        foreach (var line in lines)
        {
            if (!string.IsNullOrWhiteSpace(line))
            {
                var evt = JsonSerializer.Deserialize<SessionEvent>(line, JsonOptions);
                if (evt is not null)
                {
                    yield return evt;
                }
            }
        }
    }

    /// <summary>
    /// Reconstructs the message list from session events.
    /// Groups content blocks by role so that assistant text + tool_use blocks
    /// appear in a single message, and consecutive tool_result blocks appear
    /// in a single user message — as required by the Claude API.
    /// </summary>
    public async Task<IReadOnlyList<object>> ReconstructMessagesAsync(
        CancellationToken cancellationToken = default)
    {
        var messages = new List<object>();
        string? currentRole = null;
        var currentBlocks = new List<object>();

        await foreach (var evt in LoadAsync(cancellationToken).ConfigureAwait(false))
        {
            if (evt.IsMeta)
            {
                continue;
            }

            string role;
            object block;

            if (evt.Type == "user")
            {
                role = "user";
                block = new { type = "text", text = evt.Content ?? string.Empty };
            }
            else if (evt.Type == "assistant")
            {
                role = "assistant";
                block = new { type = "text", text = evt.Content ?? string.Empty };
            }
            else if (evt.Type == "tool_use")
            {
                role = "assistant";
                // Parse input JSON back to JsonElement so serialization preserves the object structure
                object inputObj = ParseToolInput(evt.Content);
                block = new { type = "tool_use", id = evt.ToolUseId, name = evt.ToolName, input = inputObj };
            }
            else if (evt.Type is "tool_result" or "tool_error")
            {
                role = "user";
                block = new
                {
                    type = "tool_result",
                    tool_use_id = evt.ToolUseId,
                    content = evt.Content ?? string.Empty,
                    is_error = evt.Type == "tool_error"
                };
            }
            else
            {
                continue;
            }

            // Flush accumulated blocks when the role changes
            if (currentRole != null && currentRole != role)
            {
                messages.Add(BuildMessage(currentRole, currentBlocks));
                currentBlocks = [];
            }

            currentRole = role;
            currentBlocks.Add(block);
        }

        // Flush any remaining blocks
        if (currentRole != null && currentBlocks.Count > 0)
        {
            messages.Add(BuildMessage(currentRole, currentBlocks));
        }

        // Validate and repair orphaned tool_use blocks
        // If a tool_use appears in an assistant message without a matching tool_result in a subsequent user message,
        // inject a synthetic tool_result to satisfy Claude API requirements
        RepairOrphanedToolUseBlocks(messages);

        // Post-repair validation: verify the invariant holds
        // Every tool_use block must have a matching tool_result block
        // If the invariant still doesn't hold, drop orphaned assistant messages as last resort
        ValidateAndRemoveOrphanedAssistantMessages(messages);

        return messages.AsReadOnly();
    }

    /// <summary>
    /// Builds a single message object with role and content array.
    /// </summary>
    private static object BuildMessage(string role, List<object> contentBlocks)
    {
        return new { role, content = contentBlocks.ToArray() };
    }

    /// <summary>
    /// Validates that all tool_use blocks have matching tool_result blocks.
    /// If orphaned tool_use blocks are found (tool_use without matching tool_result),
    /// injects synthetic tool_result messages to satisfy Claude API requirements.
    /// This can happen when a session is interrupted between tool_use and tool_result events.
    /// </summary>
    private static void RepairOrphanedToolUseBlocks(List<object> messages)
    {
        // Track all tool_use IDs seen in assistant messages
        var toolUseIds = new HashSet<string>(StringComparer.Ordinal);
        
        // Track all tool_result IDs seen in user messages
        var toolResultIds = new HashSet<string>(StringComparer.Ordinal);
        
        // Track indices of assistant messages with tool_use blocks
        var assistantMessageIndices = new List<int>();

        // First pass: collect all tool_use and tool_result IDs
        for (int i = 0; i < messages.Count; i++)
        {
            var messageJson = JsonSerializer.Serialize(messages[i]);
            var messageDoc = JsonDocument.Parse(messageJson);
            var root = messageDoc.RootElement;

            if (!root.TryGetProperty("role", out var roleElement) ||
                !root.TryGetProperty("content", out var contentElement))
            {
                continue;
            }

            var role = roleElement.GetString();
            
            if (role == "assistant")
            {
                assistantMessageIndices.Add(i);
                
                // Check for tool_use blocks
                if (contentElement.ValueKind == JsonValueKind.Array)
                {
                    foreach (var block in contentElement.EnumerateArray())
                    {
                        if (block.TryGetProperty("type", out var typeElement) &&
                            typeElement.GetString() == "tool_use" &&
                            block.TryGetProperty("id", out var idElement))
                        {
                            var id = idElement.GetString();
                            if (!string.IsNullOrEmpty(id))
                            {
                                toolUseIds.Add(id);
                            }
                        }
                    }
                }
            }
            else if (role == "user")
            {
                // Check for tool_result blocks
                if (contentElement.ValueKind == JsonValueKind.Array)
                {
                    foreach (var block in contentElement.EnumerateArray())
                    {
                        if (block.TryGetProperty("type", out var typeElement) &&
                            typeElement.GetString() == "tool_result" &&
                            block.TryGetProperty("tool_use_id", out var toolUseIdElement))
                        {
                            var toolUseId = toolUseIdElement.GetString();
                            if (!string.IsNullOrEmpty(toolUseId))
                            {
                                toolResultIds.Add(toolUseId);
                            }
                        }
                    }
                }
            }
        }

        // Find orphaned tool_use IDs (in toolUseIds but not in toolResultIds)
        var orphanedToolUseIds = toolUseIds.Except(toolResultIds).ToList();

        if (orphanedToolUseIds.Count == 0)
        {
            return; // No orphaned tool_use blocks
        }

        // Second pass: inject synthetic tool_result blocks for orphaned tool_use blocks
        // If a user message already exists after the assistant message, augment it with synthetic results
        // Otherwise, create a new user message
        int insertOffset = 0; // Track how many messages we've inserted (to adjust indices)

        foreach (var assistantMessageIndex in assistantMessageIndices)
        {
            var adjustedIndex = assistantMessageIndex + insertOffset;
            
            if (adjustedIndex >= messages.Count)
            {
                break; // Safety check
            }

            var messageJson = JsonSerializer.Serialize(messages[adjustedIndex]);
            var messageDoc = JsonDocument.Parse(messageJson);
            var root = messageDoc.RootElement;

            if (!root.TryGetProperty("content", out var contentElement) ||
                contentElement.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            // Find orphaned tool_use IDs in this message
            var orphanedIdsInMessage = new List<string>();
            foreach (var block in contentElement.EnumerateArray())
            {
                if (block.TryGetProperty("type", out var typeElement) &&
                    typeElement.GetString() == "tool_use" &&
                    block.TryGetProperty("id", out var idElement))
                {
                    var id = idElement.GetString();
                    if (!string.IsNullOrEmpty(id) && orphanedToolUseIds.Contains(id))
                    {
                        orphanedIdsInMessage.Add(id);
                    }
                }
            }

            if (orphanedIdsInMessage.Count > 0)
            {
                // Create synthetic tool_result blocks for all orphaned tool_use IDs in this message
                var syntheticBlocks = orphanedIdsInMessage.Select(id => new
                {
                    type = "tool_result",
                    tool_use_id = id,
                    content = "Session was interrupted before tool execution completed",
                    is_error = true
                }).ToList();

                // Check if there's already a user message immediately after this assistant message
                var nextMessageIndex = adjustedIndex + 1;
                if (nextMessageIndex < messages.Count)
                {
                    var nextMessageJson = JsonSerializer.Serialize(messages[nextMessageIndex]);
                    var nextMessageDoc = JsonDocument.Parse(nextMessageJson);
                    var nextRoot = nextMessageDoc.RootElement;

                    if (nextRoot.TryGetProperty("role", out var nextRoleElement) &&
                        nextRoleElement.GetString() == "user" &&
                        nextRoot.TryGetProperty("content", out var nextContentElement) &&
                        nextContentElement.ValueKind == JsonValueKind.Array)
                    {
                        // User message exists - augment it with synthetic tool_results
                        // Parse existing content blocks
                        var existingBlocks = new List<object>();
                        foreach (var block in nextContentElement.EnumerateArray())
                        {
                            // Reconstruct each block as an anonymous object
                            if (block.TryGetProperty("type", out var blockTypeElement))
                            {
                                var blockType = blockTypeElement.GetString();
                                if (blockType == "tool_result")
                                {
                                    // Reconstruct tool_result block
                                    var toolUseId = block.TryGetProperty("tool_use_id", out var idElem) ? idElem.GetString() : "";
                                    var content = block.TryGetProperty("content", out var contentElem) ? contentElem.GetString() : "";
                                    var isError = block.TryGetProperty("is_error", out var errorElem) && errorElem.GetBoolean();
                                    
                                    existingBlocks.Add(new
                                    {
                                        type = "tool_result",
                                        tool_use_id = toolUseId,
                                        content = content ?? string.Empty,
                                        is_error = isError
                                    });
                                }
                                else if (blockType == "text")
                                {
                                    // Reconstruct text block
                                    var text = block.TryGetProperty("text", out var textElem) ? textElem.GetString() : "";
                                    existingBlocks.Add(new
                                    {
                                        type = "text",
                                        text = text ?? string.Empty
                                    });
                                }
                                else
                                {
                                    // Handle any other block types by preserving raw JSON
                                    // This ensures forward compatibility with new Claude API content block types
                                    existingBlocks.Add(JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(block.GetRawText()) ?? new Dictionary<string, JsonElement>());
                                }
                            }
                        }

                        // Add synthetic blocks to existing blocks
                        existingBlocks.AddRange(syntheticBlocks);

                        // Replace the existing user message with augmented version
                        var augmentedMessage = new
                        {
                            role = "user",
                            content = existingBlocks.ToArray()
                        };

                        messages[nextMessageIndex] = augmentedMessage;
                        // No need to adjust insertOffset since we replaced rather than inserted
                    }
                    else
                    {
                        // Next message is not a user message - insert new synthetic user message
                        var syntheticMessage = new
                        {
                            role = "user",
                            content = syntheticBlocks.ToArray()
                        };

                        messages.Insert(nextMessageIndex, syntheticMessage);
                        insertOffset++; // Adjust for the newly inserted message
                    }
                }
                else
                {
                    // No message after assistant - insert new synthetic user message at the end
                    var syntheticMessage = new
                    {
                        role = "user",
                        content = syntheticBlocks.ToArray()
                    };

                    messages.Insert(nextMessageIndex, syntheticMessage);
                    insertOffset++; // Adjust for the newly inserted message
                }
            }
        }

        // Safety check: verify all orphaned tool_use IDs were repaired
        // Re-scan messages to check if any orphaned IDs still remain
        var remainingToolResultIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var message in messages)
        {
            var messageJson = JsonSerializer.Serialize(message);
            var messageDoc = JsonDocument.Parse(messageJson);
            var root = messageDoc.RootElement;

            if (root.TryGetProperty("role", out var roleElement) &&
                roleElement.GetString() == "user" &&
                root.TryGetProperty("content", out var contentElement) &&
                contentElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var block in contentElement.EnumerateArray())
                {
                    if (block.TryGetProperty("type", out var typeElement) &&
                        typeElement.GetString() == "tool_result" &&
                        block.TryGetProperty("tool_use_id", out var toolUseIdElement))
                    {
                        var toolUseId = toolUseIdElement.GetString();
                        if (!string.IsNullOrEmpty(toolUseId))
                        {
                            remainingToolResultIds.Add(toolUseId);
                        }
                    }
                }
            }
        }

        var stillOrphanedIds = orphanedToolUseIds.Except(remainingToolResultIds).ToList();
        if (stillOrphanedIds.Count > 0)
        {
            // Log warning - this should not happen, but provides a safety net
            // In production, this would go to structured logging
            System.Diagnostics.Debug.WriteLine(
                $"WARNING: RepairOrphanedToolUseBlocks failed to repair {stillOrphanedIds.Count} tool_use IDs: {string.Join(", ", stillOrphanedIds)}");
        }
    }

    /// <summary>
    /// Post-repair validation: ensures all tool_use blocks have matching tool_result blocks.
    /// If any orphaned tool_use blocks remain after RepairOrphanedToolUseBlocks,
    /// drops the orphaned assistant messages entirely as a last-resort safety net.
    /// Also removes any tool_result blocks that would become orphaned by this removal.
    /// This prevents the Claude API from rejecting the conversation history.
    /// </summary>
    private static void ValidateAndRemoveOrphanedAssistantMessages(List<object> messages)
    {
        // Collect all tool_use IDs and tool_result IDs
        var toolUseIds = new HashSet<string>(StringComparer.Ordinal);
        var toolResultIds = new HashSet<string>(StringComparer.Ordinal);
        var assistantMessageIndicesWithToolUse = new Dictionary<int, List<string>>();

        for (int i = 0; i < messages.Count; i++)
        {
            var messageJson = JsonSerializer.Serialize(messages[i]);
            var messageDoc = JsonDocument.Parse(messageJson);
            var root = messageDoc.RootElement;

            if (!root.TryGetProperty("role", out var roleElement) ||
                !root.TryGetProperty("content", out var contentElement))
            {
                continue;
            }

            var role = roleElement.GetString();

            if (role == "assistant" && contentElement.ValueKind == JsonValueKind.Array)
            {
                var toolUseIdsInMessage = new List<string>();
                foreach (var block in contentElement.EnumerateArray())
                {
                    if (block.TryGetProperty("type", out var typeElement) &&
                        typeElement.GetString() == "tool_use" &&
                        block.TryGetProperty("id", out var idElement))
                    {
                        var id = idElement.GetString();
                        if (!string.IsNullOrEmpty(id))
                        {
                            toolUseIds.Add(id);
                            toolUseIdsInMessage.Add(id);
                        }
                    }
                }

                if (toolUseIdsInMessage.Count > 0)
                {
                    assistantMessageIndicesWithToolUse[i] = toolUseIdsInMessage;
                }
            }
            else if (role == "user" && contentElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var block in contentElement.EnumerateArray())
                {
                    if (block.TryGetProperty("type", out var typeElement) &&
                        typeElement.GetString() == "tool_result" &&
                        block.TryGetProperty("tool_use_id", out var toolUseIdElement))
                    {
                        var toolUseId = toolUseIdElement.GetString();
                        if (!string.IsNullOrEmpty(toolUseId))
                        {
                            toolResultIds.Add(toolUseId);
                        }
                    }
                }
            }
        }

        // Find orphaned tool_use IDs (still without matching tool_result)
        var orphanedIds = toolUseIds.Except(toolResultIds).ToList();

        if (orphanedIds.Count == 0)
        {
            return; // All tool_use blocks have matching tool_result blocks
        }

        // Critical: orphaned tool_use blocks remain after repair
        // Log critical warning and drop assistant messages with orphaned tool_use blocks
        System.Diagnostics.Debug.WriteLine(
            $"CRITICAL: {orphanedIds.Count} orphaned tool_use IDs remain after repair: {string.Join(", ", orphanedIds)}");

        // Find assistant messages to remove
        var indicesToRemove = new List<int>();
        var toolUseIdsToRemove = new HashSet<string>(StringComparer.Ordinal);
        
        foreach (var (index, toolUseIdsInMessage) in assistantMessageIndicesWithToolUse)
        {
            if (toolUseIdsInMessage.Any(id => orphanedIds.Contains(id)))
            {
                indicesToRemove.Add(index);
                // Track ALL tool_use IDs from this message (including non-orphaned ones)
                // because we're removing the entire message
                foreach (var id in toolUseIdsInMessage)
                {
                    toolUseIdsToRemove.Add(id);
                }
            }
        }

        // Remove messages in reverse order to preserve indices
        indicesToRemove.Sort();
        indicesToRemove.Reverse();
        foreach (var index in indicesToRemove)
        {
            System.Diagnostics.Debug.WriteLine(
                $"Removing orphaned assistant message at index {index}");
            messages.RemoveAt(index);
        }

        // Now remove any tool_result blocks that reference the removed tool_use IDs
        // to prevent orphaned tool_result blocks
        if (toolUseIdsToRemove.Count > 0)
        {
            for (int i = messages.Count - 1; i >= 0; i--)
            {
                var messageJson = JsonSerializer.Serialize(messages[i]);
                var messageDoc = JsonDocument.Parse(messageJson);
                var root = messageDoc.RootElement;

                if (!root.TryGetProperty("role", out var roleElement) ||
                    roleElement.GetString() != "user" ||
                    !root.TryGetProperty("content", out var contentElement) ||
                    contentElement.ValueKind != JsonValueKind.Array)
                {
                    continue;
                }

                // Filter out tool_result blocks that reference removed tool_use IDs
                var filteredBlocks = new List<object>();
                var hasRemovedBlocks = false;

                foreach (var block in contentElement.EnumerateArray())
                {
                    if (block.TryGetProperty("type", out var typeElement) &&
                        typeElement.GetString() == "tool_result" &&
                        block.TryGetProperty("tool_use_id", out var toolUseIdElement))
                    {
                        var toolUseId = toolUseIdElement.GetString();
                        if (!string.IsNullOrEmpty(toolUseId) && toolUseIdsToRemove.Contains(toolUseId))
                        {
                            hasRemovedBlocks = true;
                            continue; // Skip this tool_result block
                        }
                    }

                    // Preserve all other blocks
                    if (block.TryGetProperty("type", out var blockTypeElement))
                    {
                        var blockType = blockTypeElement.GetString();
                        if (blockType == "tool_result")
                        {
                            var toolUseId = block.TryGetProperty("tool_use_id", out var idElem) ? idElem.GetString() : "";
                            var content = block.TryGetProperty("content", out var contentElem) ? contentElem.GetString() : "";
                            var isError = block.TryGetProperty("is_error", out var errorElem) && errorElem.GetBoolean();
                            
                            filteredBlocks.Add(new
                            {
                                type = "tool_result",
                                tool_use_id = toolUseId,
                                content = content ?? string.Empty,
                                is_error = isError
                            });
                        }
                        else if (blockType == "text")
                        {
                            var text = block.TryGetProperty("text", out var textElem) ? textElem.GetString() : "";
                            filteredBlocks.Add(new
                            {
                                type = "text",
                                text = text ?? string.Empty
                            });
                        }
                        else
                        {
                            // Preserve unknown block types
                            filteredBlocks.Add(JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(block.GetRawText()) ?? new Dictionary<string, JsonElement>());
                        }
                    }
                }

                if (hasRemovedBlocks)
                {
                    if (filteredBlocks.Count == 0)
                    {
                        // If the user message now has no content blocks, remove it entirely
                        System.Diagnostics.Debug.WriteLine(
                            $"Removing empty user message at index {i} after tool_result cleanup");
                        messages.RemoveAt(i);
                    }
                    else
                    {
                        // Replace with filtered version
                        messages[i] = new
                        {
                            role = "user",
                            content = filteredBlocks.ToArray()
                        };
                    }
                }
            }
        }
    }

    /// <summary>
    /// Parses a JSON string into a JsonElement for proper nested serialization.
    /// Falls back to an empty JSON object if parsing fails, to avoid crashing
    /// downstream deserialization (ClaudeClientWrapper expects a valid JSON object).
    /// </summary>
    private static JsonElement ParseToolInput(string? json)
    {
        if (string.IsNullOrEmpty(json))
        {
            using var emptyDoc = JsonDocument.Parse("{}");
            return emptyDoc.RootElement.Clone();
        }

        try
        {
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.Clone();
        }
        catch (JsonException)
        {
            // If the content isn't valid JSON, return an empty object so
            // tool_use.input remains a valid JSON object for the AI layer
            using var fallbackDoc = JsonDocument.Parse("{}");
            return fallbackDoc.RootElement.Clone();
        }
    }

    /// <summary>
    /// Saves session metadata (start time, project path, model used).
    /// </summary>
    public async Task SaveMetadataAsync(
        string projectPath,
        string modelId,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(projectPath, nameof(projectPath));
        ArgumentException.ThrowIfNullOrWhiteSpace(modelId, nameof(modelId));

        var metadata = new
        {
            started_at = _startedAt,
            project_path = projectPath,
            model = modelId
        };

        await _fileLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var json = JsonSerializer.Serialize(metadata, MetadataJsonOptions);
            await File.WriteAllTextAsync(_metadataPath, json, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _fileLock.Release();
        }
    }

    /// <summary>
    /// Disposes resources held by this instance.
    /// </summary>
    public void Dispose()
    {
        _fileLock.Dispose();
    }

    /// <summary>
    /// Finds the most recently modified session for the given project.
    /// </summary>
    /// <param name="projectPath">The project directory path.</param>
    /// <param name="storageRoot">Optional storage root (defaults to ~/.krutaka).</param>
    /// <returns>The session ID of the most recent session, or null if none exist.</returns>
    public static Guid? FindMostRecentSession(string projectPath, string? storageRoot = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(projectPath, nameof(projectPath));

        var encodedPath = EncodeProjectPath(projectPath);
        var baseDir = storageRoot ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".krutaka");

        var sessionDir = Path.Combine(baseDir, "sessions", encodedPath);

        if (!Directory.Exists(sessionDir))
        {
            return null;
        }

        IEnumerable<FileInfo> sessionFiles;
        try
        {
            sessionFiles = Directory.GetFiles(sessionDir, "*.jsonl")
                .Select(f => new FileInfo(f))
                .Where(fi => fi.Length > 0) // Ignore empty files
                .OrderByDescending(fi => fi.LastWriteTimeUtc);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Directory enumeration failed - return null to allow fallback to new session
            return null;
        }

        // Iterate through files to find the first valid session
        foreach (var sessionFile in sessionFiles)
        {
            var fileName = Path.GetFileNameWithoutExtension(sessionFile.Name);
            if (!Guid.TryParse(fileName, out var sessionId))
            {
                // Skip files with non-GUID names
                continue;
            }

            // Validate that the file contains parseable JSONL
            try
            {
                foreach (var line in File.ReadLines(sessionFile.FullName))
                {
                    if (string.IsNullOrWhiteSpace(line))
                    {
                        continue;
                    }

                    // Probe the first non-empty line to ensure it is valid JSON
                    using var _ = JsonDocument.Parse(line);
                    // File is valid, return this session ID
                    return sessionId;
                }
            }
            catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
            {
                // Corrupted or unreadable file - skip and try next candidate
                continue;
            }
        }

        return null;
    }

    /// <summary>
    /// Gets all sessions for a project, ordered by last modification time (newest first).
    /// </summary>
    /// <param name="projectPath">The project directory path.</param>
    /// <param name="limit">Maximum number of sessions to return (default: 10).</param>
    /// <param name="storageRoot">Optional storage root (defaults to ~/.krutaka).</param>
    /// <returns>List of session metadata.</returns>
    public static IReadOnlyList<SessionInfo> ListSessions(
        string projectPath,
        int limit = 10,
        string? storageRoot = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(projectPath, nameof(projectPath));

        var encodedPath = EncodeProjectPath(projectPath);
        var baseDir = storageRoot ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".krutaka");

        var sessionDir = Path.Combine(baseDir, "sessions", encodedPath);

        if (!Directory.Exists(sessionDir))
        {
            return [];
        }

        IEnumerable<FileInfo> sessionFiles;
        try
        {
            sessionFiles = Directory.GetFiles(sessionDir, "*.jsonl")
                .Select(f => new FileInfo(f))
                .Where(fi => fi.Length > 0) // Ignore empty files
                .OrderByDescending(fi => fi.LastWriteTimeUtc);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Directory enumeration failed - return empty list
            return [];
        }

        return sessionFiles
            .Select(fi =>
            {
                var fileName = Path.GetFileNameWithoutExtension(fi.Name);
                if (!Guid.TryParse(fileName, out var sessionId))
                {
                    return null;
                }

                // Count messages and get first user message
                int messageCount = 0;
                string? firstUserMessage = null;

                try
                {
                    // Use streaming to avoid loading entire file into memory
                    foreach (var line in File.ReadLines(fi.FullName))
                    {
                        if (string.IsNullOrWhiteSpace(line))
                        {
                            continue;
                        }

                        var evt = JsonSerializer.Deserialize<SessionEvent>(line);
                        if (evt != null && !evt.IsMeta)
                        {
                            messageCount++;
                            if (firstUserMessage == null && evt.Type == "user")
                            {
                                firstUserMessage = evt.Content?.Length > 50
                                    ? string.Concat(evt.Content.AsSpan(0, 50), "...")
                                    : evt.Content;
                            }
                        }
                    }
                }
                catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
                {
                    // Corrupted file or access denied - skip
                    return null;
                }

                return new SessionInfo(
                    sessionId,
                    fi.FullName,
                    new DateTimeOffset(fi.LastWriteTimeUtc),
                    messageCount,
                    firstUserMessage
                );
            })
            .Where(s => s != null)
            .Select(s => s!)
            .Take(limit) // Apply limit after filtering to ensure we get requested number of valid sessions
            .ToList()
            .AsReadOnly();
    }

    /// <summary>
    /// Encodes a project path for safe file system storage.
    /// Replaces directory separators and colons with dashes, trims leading dashes.
    /// </summary>
    public static string EncodeProjectPath(string projectPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(projectPath, nameof(projectPath));

        // Replace all path separators and colons with dashes
        var encoded = projectPath
            .Replace('\\', '-')
            .Replace('/', '-')
            .Replace(':', '-');

        // Remove consecutive dashes
        while (encoded.Contains("--", StringComparison.Ordinal))
        {
            encoded = encoded.Replace("--", "-", StringComparison.Ordinal);
        }

        // Trim leading and trailing dashes
        encoded = encoded.Trim('-');

        // If the result is empty (path was all special chars), use a placeholder
        if (string.IsNullOrWhiteSpace(encoded))
        {
            encoded = "root";
        }

        return encoded;
    }
}
