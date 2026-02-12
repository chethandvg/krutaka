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
    /// Converts SessionEvent records back into Claude API message format.
    /// </summary>
    public async Task<IReadOnlyList<object>> ReconstructMessagesAsync(
        CancellationToken cancellationToken = default)
    {
        var messages = new List<object>();

        await foreach (var evt in LoadAsync(cancellationToken).ConfigureAwait(false))
        {
            // Skip metadata events (not sent to Claude)
            if (evt.IsMeta)
            {
                continue;
            }

            // Reconstruct message objects based on event type
            // For now, we create simple message objects
            // The actual format depends on the Claude API client implementation
            if (evt.Type == "user" || evt.Type == "assistant")
            {
                messages.Add(new
                {
                    role = evt.Role,
                    content = evt.Content
                });
            }
            else if (evt.Type == "tool_use")
            {
                // Tool use events are part of assistant messages
                // This is a simplified reconstruction - actual implementation
                // may need more sophisticated handling based on Claude API format
                messages.Add(new
                {
                    role = "assistant",
                    content = new[]
                    {
                        new
                        {
                            type = "tool_use",
                            id = evt.ToolUseId,
                            name = evt.ToolName,
                            input = evt.Content
                        }
                    }
                });
            }
            else if (evt.Type == "tool_result" || evt.Type == "tool_error")
            {
                // Tool results are sent as user messages
                // "tool_error" events carry is_error=true so Claude knows the tool failed
                messages.Add(new
                {
                    role = "user",
                    content = new[]
                    {
                        new
                        {
                            type = "tool_result",
                            tool_use_id = evt.ToolUseId,
                            content = evt.Content,
                            is_error = evt.Type == "tool_error"
                        }
                    }
                });
            }
        }

        return messages.AsReadOnly();
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

        var sessionFiles = Directory.GetFiles(sessionDir, "*.jsonl")
            .Select(f => new FileInfo(f))
            .Where(fi => fi.Length > 0) // Ignore empty files
            .OrderByDescending(fi => fi.LastWriteTimeUtc)
            .FirstOrDefault();

        if (sessionFiles == null)
        {
            return null;
        }

        var fileName = Path.GetFileNameWithoutExtension(sessionFiles.Name);
        if (Guid.TryParse(fileName, out var sessionId))
        {
            return sessionId;
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

        return Directory.GetFiles(sessionDir, "*.jsonl")
            .Select(f => new FileInfo(f))
            .Where(fi => fi.Length > 0) // Ignore empty files
            .OrderByDescending(fi => fi.LastWriteTimeUtc)
            .Take(limit)
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
                    var lines = File.ReadAllLines(fi.FullName);
                    foreach (var line in lines)
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
