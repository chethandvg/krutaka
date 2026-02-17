using Krutaka.Core;
using Krutaka.Memory;
using Microsoft.Extensions.Logging;
using Telegram.Bot.Types.Enums;

#pragma warning disable CA1848 // Use LoggerMessage delegates for improved performance
#pragma warning disable CA1873 // Evaluation of logging arguments may be expensive when logging is disabled

namespace Krutaka.Telegram;

/// <summary>
/// Maps Telegram chat IDs to managed sessions via ISessionManager.
/// DM chats create user-scoped sessions, group chats create chat-scoped sessions.
/// Handles project path resolution, auto-resume on bot restart, and session lifecycle commands.
/// </summary>
public sealed class TelegramSessionBridge : ITelegramSessionBridge
{
    private readonly ISessionManager _sessionManager;
    private readonly ISessionFactory _sessionFactory;
    private readonly TelegramSecurityConfig _config;
    private readonly ILogger<TelegramSessionBridge>? _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="TelegramSessionBridge"/> class.
    /// </summary>
    /// <param name="sessionManager">The session manager for creating and managing sessions.</param>
    /// <param name="sessionFactory">The session factory for creating sessions with preserved IDs during restart.</param>
    /// <param name="config">The Telegram security configuration containing user-specific settings.</param>
    /// <param name="logger">Optional logger for diagnostics.</param>
    public TelegramSessionBridge(
        ISessionManager sessionManager,
        ISessionFactory sessionFactory,
        TelegramSecurityConfig config,
        ILogger<TelegramSessionBridge>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(sessionManager);
        ArgumentNullException.ThrowIfNull(sessionFactory);
        ArgumentNullException.ThrowIfNull(config);

        _sessionManager = sessionManager;
        _sessionFactory = sessionFactory;
        _config = config;
        _logger = logger;
    }

    /// <inheritdoc/>
    public async Task<ManagedSession> GetOrCreateSessionAsync(
        long chatId,
        long userId,
        ChatType chatType,
        CancellationToken cancellationToken)
    {
        var externalKey = BuildExternalKey(chatId, userId, chatType);
        var projectPath = ResolveProjectPath(userId, externalKey);

        // Check if JSONL exists on disk for this session
        Guid? existingSessionId = null;
        try
        {
            existingSessionId = SessionStore.FindMostRecentSession(projectPath);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger?.LogWarning(ex, "Failed to discover existing sessions for project path '{ProjectPath}', will create new session", projectPath);
        }

        ManagedSession session;

        if (existingSessionId.HasValue)
        {
            _logger?.LogInformation(
                "Found existing JSONL for external key '{ExternalKey}' with session ID {SessionId}. Executing three-step resume pattern.",
                externalKey, existingSessionId.Value);

            // Three-step resume pattern:
            // Step 1: Create session with preserved ID via SessionFactory (not SessionManager.Resume)
            // After a process restart, SessionManager won't have this session in its suspended map,
            // so we use SessionFactory directly to create with the preserved ID
            var request = new SessionRequest(
                ProjectPath: projectPath,
                ExternalKey: externalKey,
                UserId: userId.ToString(System.Globalization.CultureInfo.InvariantCulture),
                MaxTokenBudget: 200_000,
                MaxToolCallBudget: 1000);

            session = _sessionFactory.Create(request, existingSessionId.Value);

            // Step 2: Load conversation history from JSONL
            try
            {
                using var sessionStore = new SessionStore(projectPath, existingSessionId.Value);
                var messages = await sessionStore.ReconstructMessagesAsync(cancellationToken).ConfigureAwait(false);

                // Step 3: Restore history into orchestrator
                if (messages.Count > 0)
                {
                    session.Orchestrator.RestoreConversationHistory(messages);
                    _logger?.LogInformation(
                        "Restored {MessageCount} messages into session {SessionId} orchestrator.",
                        messages.Count, session.SessionId);
                }
            }
            catch (Exception ex) when (ex is IOException or System.Text.Json.JsonException or UnauthorizedAccessException)
            {
                // Best-effort: log and continue with empty in-memory history (like Console does)
                _logger?.LogWarning(ex, "Failed to reconstruct conversation history from JSONL for session {SessionId}. Starting with empty history.", session.SessionId);
            }
        }
        else
        {
            // No JSONL on disk — use GetOrCreateByKeyAsync to create or retrieve existing in-memory session
            var request = new SessionRequest(
                ProjectPath: projectPath,
                ExternalKey: externalKey,
                UserId: userId.ToString(System.Globalization.CultureInfo.InvariantCulture),
                MaxTokenBudget: 200_000,
                MaxToolCallBudget: 1000);

            session = await _sessionManager.GetOrCreateByKeyAsync(
                externalKey,
                request,
                cancellationToken).ConfigureAwait(false);

            _logger?.LogInformation(
                "Created or retrieved session {SessionId} for external key '{ExternalKey}'.",
                session.SessionId, externalKey);
        }

        return session;
    }

    /// <inheritdoc/>
    public async Task<ManagedSession> CreateNewSessionAsync(
        long chatId,
        long userId,
        ChatType chatType,
        CancellationToken cancellationToken)
    {
        var externalKey = BuildExternalKey(chatId, userId, chatType);
        var projectPath = ResolveProjectPath(userId, externalKey);

        // Check if there's an existing session for this chat
        var existingSession = _sessionManager.ListActiveSessions()
            .FirstOrDefault(s => string.Equals(s.ExternalKey, externalKey, StringComparison.Ordinal));

        if (existingSession is not null)
        {
            _logger?.LogInformation(
                "Terminating existing session {SessionId} for external key '{ExternalKey}' before creating new session.",
                existingSession.SessionId, externalKey);

            await _sessionManager.TerminateSessionAsync(existingSession.SessionId, cancellationToken).ConfigureAwait(false);
        }

        // Create a fresh session
        var request = new SessionRequest(
            ProjectPath: projectPath,
            ExternalKey: externalKey,
            UserId: userId.ToString(System.Globalization.CultureInfo.InvariantCulture),
            MaxTokenBudget: 200_000,
            MaxToolCallBudget: 1000);

        var newSession = await _sessionManager.CreateSessionAsync(request, cancellationToken).ConfigureAwait(false);

        _logger?.LogInformation(
            "Created new session {SessionId} for external key '{ExternalKey}'.",
            newSession.SessionId, externalKey);

        return newSession;
    }

    /// <inheritdoc/>
    public Task<IReadOnlyList<SessionSummary>> ListSessionsAsync(
        long userId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        
        var userIdString = userId.ToString(System.Globalization.CultureInfo.InvariantCulture);

        // Filter active sessions to those belonging to this user
        var userSessions = _sessionManager.ListActiveSessions()
            .Where(s => string.Equals(s.UserId, userIdString, StringComparison.Ordinal))
            .ToList();

        _logger?.LogDebug("Found {SessionCount} active sessions for user {UserId}.", userSessions.Count, userId);

        return Task.FromResult<IReadOnlyList<SessionSummary>>(userSessions);
    }

    /// <inheritdoc/>
    public Task<ManagedSession?> SwitchSessionAsync(
        long chatId,
        long userId,
        Guid sessionId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        
        var userIdString = userId.ToString(System.Globalization.CultureInfo.InvariantCulture);

        // Verify the session exists and belongs to this user
        var targetSession = _sessionManager.ListActiveSessions()
            .FirstOrDefault(s => s.SessionId == sessionId);

        if (targetSession is null)
        {
            _logger?.LogWarning("Session {SessionId} not found for user {UserId}.", sessionId, userId);
            return Task.FromResult<ManagedSession?>(null);
        }

        if (!string.Equals(targetSession.UserId, userIdString, StringComparison.Ordinal))
        {
            _logger?.LogWarning(
                "Session {SessionId} does not belong to user {UserId}. Actual owner: {ActualUserId}.",
                sessionId, userId, targetSession.UserId);
            return Task.FromResult<ManagedSession?>(null);
        }

        var session = _sessionManager.GetSession(sessionId);

        if (session is null)
        {
            _logger?.LogWarning("Session {SessionId} is no longer active.", sessionId);
            return Task.FromResult<ManagedSession?>(null);
        }

        _logger?.LogInformation(
            "Retrieved session {SessionId} for user {UserId}. Note: External key remapping not currently supported by ISessionManager.",
            sessionId, userId);

        return Task.FromResult<ManagedSession?>(session);
    }

    /// <summary>
    /// Builds the external key for the specified chat and user.
    /// DM (Private) chat → telegram:dm:{userId}
    /// Group/Supergroup chat → telegram:group:{chatId}
    /// </summary>
    private static string BuildExternalKey(long chatId, long userId, ChatType chatType)
    {
        return chatType switch
        {
            ChatType.Private => $"telegram:dm:{userId}",
            ChatType.Group => $"telegram:group:{chatId}",
            ChatType.Supergroup => $"telegram:group:{chatId}",
            _ => throw new ArgumentException($"Unsupported chat type: {chatType}", nameof(chatType))
        };
    }

    /// <summary>
    /// Resolves the project path for the specified user and external key.
    /// If TelegramUserConfig.ProjectPath is set for this user, uses it.
    /// Otherwise, defaults to {UserProfile}\KrutakaProjects\{sanitizedKey}\ (auto-created).
    /// </summary>
    private string ResolveProjectPath(long userId, string externalKey)
    {
        // Check if user has a configured project path
        var userConfig = _config.AllowedUsers
            .FirstOrDefault(u => u.UserId == userId);

        if (userConfig?.ProjectPath is not null)
        {
            _logger?.LogDebug("Using configured project path '{ProjectPath}' for user {UserId}.", userConfig.ProjectPath, userId);
            return userConfig.ProjectPath;
        }

        // Default: {UserProfile}\KrutakaProjects\{sanitizedKey}\
        // Sanitize external key to be filesystem-safe (replace ':' with '-')
        var sanitizedKey = externalKey.Replace(":", "-", StringComparison.Ordinal);
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var defaultProjectPath = Path.Combine(userProfile, "KrutakaProjects", sanitizedKey);

        // Ensure directory exists
        if (!Directory.Exists(defaultProjectPath))
        {
            Directory.CreateDirectory(defaultProjectPath);
            _logger?.LogInformation("Created default project directory '{ProjectPath}' for external key '{ExternalKey}'.",
                defaultProjectPath, externalKey);
        }

        return defaultProjectPath;
    }
}
