using System.Collections.Concurrent;
using System.Security.Cryptography;
using Krutaka.Core;
using Microsoft.Extensions.Logging;
using Telegram.Bot;
using Telegram.Bot.Types;
using Telegram.Bot.Types.Enums;
using Telegram.Bot.Types.ReplyMarkups;

namespace Krutaka.Telegram;

/// <summary>
/// Handles Telegram inline keyboard approval flow for human-in-the-loop approvals.
/// Sends approval panels with HMAC-signed callbacks and processes button presses.
/// Stores approval contexts server-side to keep callback data under Telegram's 64-byte limit.
/// </summary>
public sealed partial class TelegramApprovalHandler : ITelegramApprovalHandler, IDisposable
{
    private readonly ITelegramBotClient _botClient;
    private readonly ISessionManager _sessionManager;
    private readonly IAuditLogger _auditLogger;
    private readonly CallbackDataSigner _signer;
    private readonly ILogger<TelegramApprovalHandler> _logger;
    private readonly ConcurrentDictionary<string, byte> _usedNonces;
    private readonly ConcurrentDictionary<string, ApprovalContext> _approvalContexts;
    private readonly TimeSpan _callbackTimeout;
    private readonly System.Threading.Timer _cleanupTimer;
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="TelegramApprovalHandler"/> class.
    /// </summary>
    /// <param name="botClient">The Telegram bot client.</param>
    /// <param name="sessionManager">The session manager for looking up sessions.</param>
    /// <param name="auditLogger">The audit logger for recording approval decisions.</param>
    /// <param name="signer">The callback data signer for HMAC verification.</param>
    /// <param name="logger">The logger.</param>
    public TelegramApprovalHandler(
        ITelegramBotClient botClient,
        ISessionManager sessionManager,
        IAuditLogger auditLogger,
        CallbackDataSigner signer,
        ILogger<TelegramApprovalHandler> logger)
    {
        ArgumentNullException.ThrowIfNull(botClient);
        ArgumentNullException.ThrowIfNull(sessionManager);
        ArgumentNullException.ThrowIfNull(auditLogger);
        ArgumentNullException.ThrowIfNull(signer);
        ArgumentNullException.ThrowIfNull(logger);

        _botClient = botClient;
        _sessionManager = sessionManager;
        _auditLogger = auditLogger;
        _signer = signer;
        _logger = logger;
        _usedNonces = new ConcurrentDictionary<string, byte>();
        _approvalContexts = new ConcurrentDictionary<string, ApprovalContext>();
        _callbackTimeout = TimeSpan.FromMinutes(5); // 5 minute timeout for approval

        // Start cleanup timer to remove expired nonces and contexts every minute
        _cleanupTimer = new System.Threading.Timer(
            CleanupExpiredEntries,
            null,
            TimeSpan.FromMinutes(1),
            TimeSpan.FromMinutes(1));
    }

    /// <summary>
    /// Sends an approval request message with inline keyboard buttons to Telegram.
    /// </summary>
    /// <param name="chatId">The Telegram chat ID to send the approval panel to.</param>
    /// <param name="approvalEvent">The agent event requiring approval (HumanApprovalRequired, DirectoryAccessRequested, or CommandApprovalRequested).</param>
    /// <param name="session">The managed session for accessing the orchestrator.</param>
    /// <param name="userId">The Telegram user ID authorized to respond to this approval.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The sent Telegram message.</returns>
    public async Task<Message> SendApprovalRequestAsync(
        long chatId,
        AgentEvent approvalEvent,
        ManagedSession session,
        long userId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(approvalEvent);
        ArgumentNullException.ThrowIfNull(session);

        var (messageText, keyboard) = approvalEvent switch
        {
            HumanApprovalRequired toolApproval => BuildToolApprovalPanel(toolApproval, session.SessionId, userId),
            DirectoryAccessRequested dirAccess => BuildDirectoryAccessPanel(dirAccess, session.SessionId, userId),
            CommandApprovalRequested cmdApproval => BuildCommandApprovalPanel(cmdApproval, session.SessionId, userId),
            _ => throw new ArgumentException($"Unsupported approval event type: {approvalEvent.GetType().Name}", nameof(approvalEvent))
        };

        var message = await _botClient.SendMessage(
            chatId,
            messageText,
            parseMode: ParseMode.Html,
            replyMarkup: keyboard,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        // Start timeout handler - uses CancellationToken.None to avoid premature cancellation
        // This is intentionally fire-and-forget as the timeout task needs to outlive the current request
        _ = Task.Run(async () => await HandleApprovalTimeoutAsync(message, session, approvalEvent).ConfigureAwait(false), CancellationToken.None);

        return message;
    }

    /// <summary>
    /// Cleans up expired nonces and approval contexts to prevent memory leak.
    /// Called periodically by timer.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Timer callback must not throw")]
    private void CleanupExpiredEntries(object? state)
    {
        try
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var expiryCutoff = now - (long)_callbackTimeout.TotalSeconds;

            // Clean up expired approval contexts
            foreach (var kvp in _approvalContexts)
            {
                if (kvp.Value.Timestamp < expiryCutoff)
                {
                    _approvalContexts.TryRemove(kvp.Key, out _);
                    // Also remove the associated nonce
                    _usedNonces.TryRemove(kvp.Value.Nonce, out _);
                }
            }

            LogCleanupCompleted(_approvalContexts.Count, _usedNonces.Count);
        }
        catch (Exception ex)
        {
            LogCleanupError(ex);
        }
    }

    /// <summary>
    /// Disposes the approval handler and stops the cleanup timer.
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _cleanupTimer?.Dispose();
        _disposed = true;
    }

    /// <summary>
    /// Escapes HTML special characters for Telegram message text (including quotes for defense in depth).
    /// </summary>
    private static string EscapeHtml(string text)
    {
        return text
            .Replace("&", "&amp;", StringComparison.Ordinal)
            .Replace("<", "&lt;", StringComparison.Ordinal)
            .Replace(">", "&gt;", StringComparison.Ordinal)
            .Replace("\"", "&quot;", StringComparison.Ordinal)
            .Replace("'", "&#39;", StringComparison.Ordinal);
    }

    /// <summary>
    /// Generates a cryptographically secure nonce for replay prevention.
    /// </summary>
    private static string GenerateNonce()
    {
        var bytes = RandomNumberGenerator.GetBytes(16);
        return Convert.ToBase64String(bytes);
    }

    /// <summary>
    /// Generates a short approval ID (12 chars) for callback data.
    /// </summary>
    private static string GenerateApprovalId()
    {
        var bytes = RandomNumberGenerator.GetBytes(9); // 9 bytes = 12 base64 chars
        return Convert.ToBase64String(bytes).TrimEnd('='); // Remove padding
    }
}
