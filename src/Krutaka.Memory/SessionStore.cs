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
