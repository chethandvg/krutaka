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
/// </summary>
public sealed partial class TelegramApprovalHandler : ITelegramApprovalHandler
{
    private readonly ITelegramBotClient _botClient;
    private readonly ISessionManager _sessionManager;
    private readonly IAuditLogger _auditLogger;
    private readonly CallbackDataSigner _signer;
    private readonly ILogger<TelegramApprovalHandler> _logger;
    private readonly ConcurrentDictionary<string, byte> _usedNonces;
    private readonly TimeSpan _callbackTimeout;

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
        _callbackTimeout = TimeSpan.FromMinutes(5); // 5 minute timeout for approval
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

        // Start timeout timer to auto-deny if no response
        _ = Task.Run(async () => await HandleApprovalTimeoutAsync(message, session, approvalEvent, cancellationToken).ConfigureAwait(false), cancellationToken);

        return message;
    }

    /// <summary>
    /// Escapes HTML special characters for Telegram message text.
    /// </summary>
    private static string EscapeHtml(string text)
    {
        return text
            .Replace("&", "&amp;", StringComparison.Ordinal)
            .Replace("<", "&lt;", StringComparison.Ordinal)
            .Replace(">", "&gt;", StringComparison.Ordinal);
    }

    /// <summary>
    /// Generates a cryptographically secure nonce for replay prevention.
    /// </summary>
    private static string GenerateNonce()
    {
        var bytes = RandomNumberGenerator.GetBytes(16);
        return Convert.ToBase64String(bytes);
    }
}
