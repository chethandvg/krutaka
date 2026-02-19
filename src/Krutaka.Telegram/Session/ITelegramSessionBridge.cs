using Krutaka.Core;
using Telegram.Bot.Types.Enums;

namespace Krutaka.Telegram;

/// <summary>
/// Maps Telegram chat IDs to managed sessions via ISessionManager.
/// DM chats create user-scoped sessions, group chats create chat-scoped sessions.
/// Handles project path resolution, auto-resume on bot restart, and session lifecycle commands.
/// </summary>
public interface ITelegramSessionBridge
{
    /// <summary>
    /// Gets an existing session for the specified chat, or creates a new one if none exists.
    /// Automatically resumes suspended sessions from disk using the three-step resume pattern.
    /// </summary>
    /// <param name="chatId">The Telegram chat ID.</param>
    /// <param name="userId">The Telegram user ID.</param>
    /// <param name="chatType">The type of chat (Private, Group, Supergroup, Channel).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The existing or newly created managed session.</returns>
    /// <remarks>
    /// External key format:
    /// - DM (Private) chat → telegram:dm:{userId}
    /// - Group/Supergroup chat → telegram:group:{chatId}
    /// 
    /// If an existing JSONL file is found for the session, the three-step resume pattern is executed:
    /// 1. ISessionManager.ResumeSessionAsync (preserves session ID)
    /// 2. SessionStore.ReconstructMessagesAsync (loads conversation history)
    /// 3. session.Orchestrator.RestoreConversationHistory (populates orchestrator)
    /// </remarks>
    Task<ManagedSession> GetOrCreateSessionAsync(
        long chatId,
        long userId,
        ChatType chatType,
        CancellationToken cancellationToken);

    /// <summary>
    /// Terminates the current session for the specified chat and creates a fresh one.
    /// Used by the /new command to start over with a clean conversation history.
    /// </summary>
    /// <param name="chatId">The Telegram chat ID.</param>
    /// <param name="userId">The Telegram user ID.</param>
    /// <param name="chatType">The type of chat (Private, Group, Supergroup, Channel).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The newly created managed session.</returns>
    Task<ManagedSession> CreateNewSessionAsync(
        long chatId,
        long userId,
        ChatType chatType,
        CancellationToken cancellationToken);

    /// <summary>
    /// Lists all active sessions for the specified user.
    /// Used by the /sessions command.
    /// </summary>
    /// <param name="userId">The Telegram user ID.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A read-only list of session summaries for the user.</returns>
    Task<IReadOnlyList<SessionSummary>> ListSessionsAsync(
        long userId,
        CancellationToken cancellationToken);

    /// <summary>
    /// Switches the specified chat to a different session.
    /// Used by the /session &lt;id&gt; command to resume a previous session.
    /// </summary>
    /// <param name="chatId">The Telegram chat ID.</param>
    /// <param name="userId">The Telegram user ID.</param>
    /// <param name="sessionId">The session ID to switch to.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The switched session if successful, or null if the session does not belong to the user or does not exist.</returns>
    Task<ManagedSession?> SwitchSessionAsync(
        long chatId,
        long userId,
        Guid sessionId,
        CancellationToken cancellationToken);
}
