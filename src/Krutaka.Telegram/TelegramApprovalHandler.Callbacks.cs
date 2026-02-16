using Krutaka.Core;
using Telegram.Bot;
using Telegram.Bot.Types;
using Telegram.Bot.Types.Enums;
using Telegram.Bot.Types.ReplyMarkups;

namespace Krutaka.Telegram;

/// <summary>
/// TelegramApprovalHandler - Callback handling partial.
/// </summary>
public sealed partial class TelegramApprovalHandler
{
    /// <summary>
    /// Handles an inline keyboard callback button press.
    /// Verifies HMAC signature, checks user authorization, prevents replay attacks,
    /// and routes to the appropriate orchestrator approval method.
    /// </summary>
    /// <param name="callback">The Telegram callback query from the button press.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Top-level handler must catch all exceptions to prevent crash")]
    public async Task HandleCallbackAsync(
        CallbackQuery callback,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(callback);

        if (string.IsNullOrWhiteSpace(callback.Data) || callback.From == null || callback.Message == null)
        {
            LogCallbackMissingData();
            return;
        }

        // Step 1: Verify HMAC signature
        var payload = _signer.Verify(callback.Data);
        if (payload == null)
        {
            LogHmacVerificationFailed(callback.From.Id);
            await AnswerCallbackWithError(callback, "⚠️ Invalid signature. Request may have been tampered with.", cancellationToken).ConfigureAwait(false);
            
            // Log security incident
            LogSecurityIncident(callback.From.Id, IncidentType.CallbackTampering);
            return;
        }

        // Step 2: Verify user ID matches
        if (payload.UserId != callback.From.Id)
        {
            LogUserIdMismatch(callback.From.Id, payload.UserId);
            await AnswerCallbackWithError(callback, "⚠️ This approval is not for you.", cancellationToken).ConfigureAwait(false);
            
            // Log security incident
            LogSecurityIncident(callback.From.Id, IncidentType.CallbackTampering);
            return;
        }

        // Step 3: Verify timestamp (not expired)
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var age = now - payload.Timestamp;
        if (age > _callbackTimeout.TotalSeconds || age < 0)
        {
            LogExpiredCallback(callback.From.Id, age);
            await AnswerCallbackWithError(callback, "⏰ This approval request has expired.", cancellationToken).ConfigureAwait(false);
            await EditMessageToExpired(callback.Message, cancellationToken).ConfigureAwait(false);
            return;
        }

        // Step 4: Verify nonce (prevent replay)
        if (!_usedNonces.TryAdd(payload.Nonce, 0))
        {
            LogReplayAttempt(payload.Nonce, callback.From.Id);
            await AnswerCallbackWithError(callback, "⚠️ This approval has already been processed.", cancellationToken).ConfigureAwait(false);
            
            // Log security incident
            LogSecurityIncident(callback.From.Id, IncidentType.ReplayAttempt);
            return;
        }

        // Step 5: Look up session
        var session = _sessionManager.GetSession(payload.SessionId);
        if (session == null)
        {
            LogSessionNotFound(payload.SessionId, callback.From.Id);
            await AnswerCallbackWithError(callback, "⚠️ Session not found or terminated.", cancellationToken).ConfigureAwait(false);
            return;
        }

        // Step 6: Route to orchestrator method
        var approved = payload.Action is "approve" or "always";
        var alwaysApprove = payload.Action == "always";

        try
        {
            // Determine approval type based on payload structure
            if (!string.IsNullOrWhiteSpace(payload.ToolUseId))
            {
                // Tool approval
                if (approved)
                {
                    session.Orchestrator.ApproveTool(payload.ToolUseId, alwaysApprove);
                }
                else
                {
                    session.Orchestrator.DenyTool(payload.ToolUseId);
                }

                // Log audit event
                _auditLogger.LogTelegramApproval(
                    session.CorrelationContext,
                    new TelegramApprovalEvent
                    {
                        SessionId = session.SessionId,
                        TurnId = session.CorrelationContext.TurnId,
                        Timestamp = DateTimeOffset.UtcNow,
                        TelegramUserId = callback.From.Id,
                        TelegramChatId = callback.Message.Chat.Id,
                        ToolName = "tool", // We don't have the tool name in the payload, but orchestrator tracks it
                        ToolUseId = payload.ToolUseId,
                        Approved = approved
                    });
            }
            else if (payload.Action.StartsWith("dir_", StringComparison.Ordinal))
            {
                // Directory access approval
                if (approved)
                {
                    // Extract access level from action (dir_readonly, dir_readwrite, dir_execute)
                    var level = payload.Action switch
                    {
                        "dir_readonly" => AccessLevel.ReadOnly,
                        "dir_readwrite" => AccessLevel.ReadWrite,
                        "dir_execute" => AccessLevel.Execute,
                        _ => AccessLevel.ReadOnly
                    };
                    session.Orchestrator.ApproveDirectoryAccess(level, createSessionGrant: alwaysApprove);
                }
                else
                {
                    session.Orchestrator.DenyDirectoryAccess();
                }
            }
            else if (payload.Action.StartsWith("cmd_", StringComparison.Ordinal))
            {
                // Command approval
                if (approved)
                {
                    session.Orchestrator.ApproveCommand(alwaysApprove);
                }
                else
                {
                    session.Orchestrator.DenyCommand();
                }
            }
            else
            {
                LogUnknownAction(payload.Action);
                await AnswerCallbackWithError(callback, "⚠️ Unknown approval action.", cancellationToken).ConfigureAwait(false);
                return;
            }

            // Step 7: Edit message to show decision
            var username = callback.From.Username ?? callback.From.FirstName ?? "User";
            var decisionEmoji = approved ? "✅" : "❌";
            var decisionText = approved ? "Approved" : "Denied";
            var alwaysText = alwaysApprove ? " (Always)" : "";

            await _botClient.EditMessageText(
                callback.Message.Chat.Id,
                callback.Message.MessageId,
                $"{callback.Message.Text}\n\n{decisionEmoji} <b>{decisionText}{alwaysText}</b> by @{username}",
                parseMode: ParseMode.Html,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            // Answer callback to remove loading state
            await _botClient.AnswerCallbackQuery(callback.Id, cancellationToken: cancellationToken).ConfigureAwait(false);

            LogApprovalProcessed(payload.Action, callback.From.Id, payload.SessionId);
        }
        catch (Exception ex)
        {
            LogCallbackProcessingError(ex, payload.SessionId);
            await AnswerCallbackWithError(callback, "⚠️ Error processing approval.", cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Answers a callback query with an error message.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Error handler must not throw")]
    private async Task AnswerCallbackWithError(CallbackQuery callback, string errorText, CancellationToken cancellationToken)
    {
        try
        {
            await _botClient.AnswerCallbackQuery(
                callback.Id,
                errorText,
                showAlert: true,
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            LogAnswerCallbackError(ex);
        }
    }

    /// <summary>
    /// Edits a message to show it has expired.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Error handler must not throw")]
    private async Task EditMessageToExpired(Message message, CancellationToken cancellationToken)
    {
        try
        {
            await _botClient.EditMessageText(
                message.Chat.Id,
                message.MessageId,
                $"{message.Text}\n\n⏰ <b>Expired</b>",
                parseMode: ParseMode.Html,
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            LogEditMessageError(ex);
        }
    }

    /// <summary>
    /// Logs a security incident to the audit log.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Error handler must not throw")]
    private void LogSecurityIncident(long userId, IncidentType incidentType)
    {
        try
        {
            _auditLogger.LogTelegramSecurityIncident(
                new CorrelationContext(Guid.NewGuid()), // No session context for security incidents
                new TelegramSecurityIncidentEvent
                {
                    SessionId = Guid.Empty,
                    TurnId = 0,
                    Timestamp = DateTimeOffset.UtcNow,
                    TelegramUserId = userId,
                    Type = incidentType,
                    Details = $"Callback security incident: {incidentType}"
                });
        }
        catch (Exception ex)
        {
            LogAuditLoggingError(ex);
        }
    }
}
