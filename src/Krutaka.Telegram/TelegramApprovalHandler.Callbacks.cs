using Krutaka.Core;
using Telegram.Bot;
using Telegram.Bot.Types;
using Telegram.Bot.Types.Enums;

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

        // Step 2: Retrieve approval context from server-side store
        if (!_approvalContexts.TryGetValue(payload.ApprovalId, out var context))
        {
            LogApprovalContextNotFound(payload.ApprovalId, callback.From.Id);
            await AnswerCallbackWithError(callback, "⚠️ Approval request expired or not found.", cancellationToken).ConfigureAwait(false);
            return;
        }

        // Step 3: Verify user ID matches
        if (context.UserId != callback.From.Id)
        {
            LogUserIdMismatch(callback.From.Id, context.UserId);
            await AnswerCallbackWithError(callback, "⚠️ This approval is not for you.", cancellationToken).ConfigureAwait(false);
            
            // Log security incident
            LogSecurityIncident(callback.From.Id, IncidentType.CallbackTampering);
            return;
        }

        // Step 4: Verify timestamp (not expired)
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var age = now - context.Timestamp;
        if (age > _callbackTimeout.TotalSeconds || age < 0)
        {
            LogExpiredCallback(callback.From.Id, age);
            await AnswerCallbackWithError(callback, "⏰ This approval request has expired.", cancellationToken).ConfigureAwait(false);
            await EditMessageToExpired(callback.Message, cancellationToken).ConfigureAwait(false);
            
            // Clean up expired context
            _approvalContexts.TryRemove(payload.ApprovalId, out _);
            _usedNonces.TryRemove(context.Nonce, out _);
            return;
        }

        // Step 5: Verify nonce (prevent replay)
        if (!_usedNonces.TryAdd(context.Nonce, 0))
        {
            LogReplayAttempt(context.Nonce, callback.From.Id);
            await AnswerCallbackWithError(callback, "⚠️ This approval has already been processed.", cancellationToken).ConfigureAwait(false);
            
            // Log security incident
            LogSecurityIncident(callback.From.Id, IncidentType.ReplayAttempt);
            return;
        }

        // Step 6: Look up session
        var session = _sessionManager.GetSession(context.SessionId);
        if (session == null)
        {
            LogSessionNotFound(context.SessionId, callback.From.Id);
            await AnswerCallbackWithError(callback, "⚠️ Session not found or terminated.", cancellationToken).ConfigureAwait(false);
            
            // Clean up context
            _approvalContexts.TryRemove(payload.ApprovalId, out _);
            return;
        }

        // Step 7: Parse action and route to orchestrator
        var (actionType, approved, alwaysApprove, accessLevel) = ParseAction(context.Action);

        try
        {
            // Route based on action type and tool use ID presence
            if (!string.IsNullOrWhiteSpace(context.ToolUseId))
            {
                // Tool approval
                if (approved)
                {
                    session.Orchestrator.ApproveTool(context.ToolUseId, alwaysApprove);
                }
                else
                {
                    session.Orchestrator.DenyTool(context.ToolUseId);
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
                        ToolName = "tool",
                        ToolUseId = context.ToolUseId,
                        Approved = approved
                    });
            }
            else if (actionType == "directory")
            {
                // Directory access approval
                if (approved)
                {
                    session.Orchestrator.ApproveDirectoryAccess(accessLevel, createSessionGrant: alwaysApprove);
                }
                else
                {
                    session.Orchestrator.DenyDirectoryAccess();
                }

                // Log audit event for directory access
                _auditLogger.LogTelegramApproval(
                    session.CorrelationContext,
                    new TelegramApprovalEvent
                    {
                        SessionId = session.SessionId,
                        TurnId = session.CorrelationContext.TurnId,
                        Timestamp = DateTimeOffset.UtcNow,
                        TelegramUserId = callback.From.Id,
                        TelegramChatId = callback.Message.Chat.Id,
                        ToolName = $"directory_access_{accessLevel}",
                        ToolUseId = "",
                        Approved = approved
                    });
            }
            else if (actionType == "command")
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

                // Log audit event for command
                _auditLogger.LogTelegramApproval(
                    session.CorrelationContext,
                    new TelegramApprovalEvent
                    {
                        SessionId = session.SessionId,
                        TurnId = session.CorrelationContext.TurnId,
                        Timestamp = DateTimeOffset.UtcNow,
                        TelegramUserId = callback.From.Id,
                        TelegramChatId = callback.Message.Chat.Id,
                        ToolName = "command_execution",
                        ToolUseId = "",
                        Approved = approved
                    });
            }
            else
            {
                LogUnknownAction(context.Action);
                await AnswerCallbackWithError(callback, "⚠️ Unknown approval action.", cancellationToken).ConfigureAwait(false);
                return;
            }

            // Step 8: Edit message to show decision
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

            // Clean up approval context after successful processing
            _approvalContexts.TryRemove(payload.ApprovalId, out _);

            LogApprovalProcessed(context.Action, callback.From.Id, context.SessionId);
        }
        catch (Exception ex)
        {
            LogCallbackProcessingError(ex, context.SessionId);
            await AnswerCallbackWithError(callback, "⚠️ Error processing approval.", cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Parses an action string to determine action type, approval status, and parameters.
    /// </summary>
    /// <returns>Tuple of (actionType, approved, alwaysApprove, accessLevel)</returns>
    private static (string ActionType, bool Approved, bool AlwaysApprove, AccessLevel AccessLevel) ParseAction(string action)
    {
        return action switch
        {
            // Tool actions
            "approve" => ("tool", true, false, AccessLevel.ReadOnly),
            "always" => ("tool", true, true, AccessLevel.ReadOnly),
            "deny" => ("tool", false, false, AccessLevel.ReadOnly),

            // Directory actions - one-time
            "dir_readonly" => ("directory", true, false, AccessLevel.ReadOnly),
            "dir_readwrite" => ("directory", true, false, AccessLevel.ReadWrite),
            "dir_execute" => ("directory", true, false, AccessLevel.Execute),

            // Directory actions - session grant
            "dir_readonly_session" => ("directory", true, true, AccessLevel.ReadOnly),
            "dir_readwrite_session" => ("directory", true, true, AccessLevel.ReadWrite),
            "dir_execute_session" => ("directory", true, true, AccessLevel.Execute),

            // Command actions
            "cmd_approve" => ("command", true, false, AccessLevel.ReadOnly),
            "cmd_always" => ("command", true, true, AccessLevel.ReadOnly),

            // Default for unknown
            _ => ("unknown", false, false, AccessLevel.ReadOnly)
        };
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
