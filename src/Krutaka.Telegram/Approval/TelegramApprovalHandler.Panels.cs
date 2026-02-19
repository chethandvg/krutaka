using Krutaka.Core;
using Telegram.Bot;
using Telegram.Bot.Types;
using Telegram.Bot.Types.Enums;
using Telegram.Bot.Types.ReplyMarkups;

namespace Krutaka.Telegram;

/// <summary>
/// TelegramApprovalHandler - Approval panel builders partial.
/// </summary>
public sealed partial class TelegramApprovalHandler
{
    /// <summary>
    /// Builds the tool approval panel with [✅ Approve] [❌ Deny] [🔄 Always] buttons.
    /// </summary>
    private (string MessageText, InlineKeyboardMarkup Keyboard) BuildToolApprovalPanel(
        HumanApprovalRequired approval,
        Guid sessionId,
        long userId)
    {
        var inputPreview = approval.Input.Length > 200
            ? approval.Input[..200] + "..."
            : approval.Input;

        var messageText = $"<b>🔐 Tool Approval Required</b>\n\n" +
                         $"<b>Tool:</b> {EscapeHtml(approval.ToolName)}\n" +
                         $"<b>Input preview:</b>\n<code>{EscapeHtml(inputPreview)}</code>";

        var keyboard = CreateKeyboard(
            sessionId,
            userId,
            approval.ToolUseId,
            approveAction: "approve",
            denyAction: "deny",
            alwaysAction: "always",
            showAlways: true);

        return (messageText, keyboard);
    }

    /// <summary>
    /// Builds the directory access approval panel with [✅ Grant] [❌ Deny] [📂 Session] buttons.
    /// </summary>
    private (string MessageText, InlineKeyboardMarkup Keyboard) BuildDirectoryAccessPanel(
        DirectoryAccessRequested approval,
        Guid sessionId,
        long userId)
    {
        var levelEmoji = approval.AccessLevel switch
        {
            AccessLevel.ReadOnly => "👀",
            AccessLevel.ReadWrite => "✏️",
            AccessLevel.Execute => "⚙️",
            _ => "❓"
        };

        var messageText = $"<b>📂 Directory Access Request</b>\n\n" +
                         $"<b>Path:</b> <code>{EscapeHtml(approval.Path)}</code>\n" +
                         $"<b>Access Level:</b> {levelEmoji} {approval.AccessLevel}\n" +
                         $"<b>Justification:</b> {EscapeHtml(approval.Justification)}";

        // Use distinct action strings for one-time vs session grants
        var approveAction = approval.AccessLevel switch
        {
            AccessLevel.ReadOnly => "dir_readonly",
            AccessLevel.ReadWrite => "dir_readwrite",
            AccessLevel.Execute => "dir_execute",
            _ => "dir_readonly"
        };

        var sessionAction = approval.AccessLevel switch
        {
            AccessLevel.ReadOnly => "dir_readonly_session",
            AccessLevel.ReadWrite => "dir_readwrite_session",
            AccessLevel.Execute => "dir_execute_session",
            _ => "dir_readonly_session"
        };

        var keyboard = CreateKeyboard(
            sessionId,
            userId,
            toolUseId: "", // Directory approvals don't have a tool use ID
            approveAction: approveAction,
            denyAction: "deny",
            alwaysAction: sessionAction,
            showAlways: true,
            approveLabel: "✅ Grant",
            alwaysLabel: "📂 Session");

        return (messageText, keyboard);
    }

    /// <summary>
    /// Builds the command approval panel with tier-aware buttons.
    /// [✅ Approve] [❌ Deny] [🔄 Always] for Moderate tier.
    /// [✅ Approve] [❌ Deny] for Elevated tier.
    /// </summary>
    private (string MessageText, InlineKeyboardMarkup Keyboard) BuildCommandApprovalPanel(
        CommandApprovalRequested approval,
        Guid sessionId,
        long userId)
    {
        var tierEmoji = approval.Decision.Tier switch
        {
            CommandRiskTier.Moderate => "🟡",
            CommandRiskTier.Elevated => "🔴",
            _ => "⚪"
        };

        var commandDisplay = $"{approval.Request.Executable} {string.Join(" ", approval.Request.Arguments)}";
        if (commandDisplay.Length > 200)
        {
            commandDisplay = commandDisplay[..200] + "...";
        }

        var messageText = $"<b>⚙️ Command Approval Required</b>\n\n" +
                         $"<b>Command:</b> <code>{EscapeHtml(commandDisplay)}</code>\n" +
                         $"<b>Tier:</b> {tierEmoji} {approval.Decision.Tier}\n" +
                         $"<b>Directory:</b> <code>{EscapeHtml(approval.Request.WorkingDirectory ?? ".")}</code>\n" +
                         $"<b>Reason:</b> {EscapeHtml(approval.Decision.Reason)}";

        // Only show "Always" for Moderate tier
        var showAlways = approval.Decision.Tier == CommandRiskTier.Moderate;

        var keyboard = CreateKeyboard(
            sessionId,
            userId,
            toolUseId: "", // Command approvals don't have a tool use ID
            approveAction: "cmd_approve",
            denyAction: "deny",
            alwaysAction: "cmd_always",
            showAlways: showAlways);

        return (messageText, keyboard);
    }

    /// <summary>
    /// Creates an inline keyboard with approval buttons and signed callback data.
    /// Uses server-side context storage to keep callback data under 64 bytes.
    /// </summary>
    private InlineKeyboardMarkup CreateKeyboard(
        Guid sessionId,
        long userId,
        string toolUseId,
        string approveAction,
        string denyAction,
        string alwaysAction,
        bool showAlways,
        string approveLabel = "✅ Approve",
        string denyLabel = "❌ Deny",
        string alwaysLabel = "🔄 Always")
    {
        var buttons = new List<InlineKeyboardButton[]>();
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        // First row: Approve and Deny
        var approveId = StoreApprovalContext(sessionId, userId, toolUseId, approveAction, timestamp);
        var denyId = StoreApprovalContext(sessionId, userId, toolUseId, denyAction, timestamp);

        buttons.Add(
        [
            InlineKeyboardButton.WithCallbackData(approveLabel, _signer.Sign(new CallbackPayload(approveId, null))),
            InlineKeyboardButton.WithCallbackData(denyLabel, _signer.Sign(new CallbackPayload(denyId, null)))
        ]);

        // Second row: Always (if applicable)
        if (showAlways)
        {
            var alwaysId = StoreApprovalContext(sessionId, userId, toolUseId, alwaysAction, timestamp);

            buttons.Add(
            [
                InlineKeyboardButton.WithCallbackData(alwaysLabel, _signer.Sign(new CallbackPayload(alwaysId, null)))
            ]);
        }

        return new InlineKeyboardMarkup(buttons);
    }

    /// <summary>
    /// Stores approval context server-side and returns the approval ID.
    /// </summary>
    private string StoreApprovalContext(Guid sessionId, long userId, string toolUseId, string action, long timestamp)
    {
        var approvalId = GenerateApprovalId();
        var nonce = GenerateNonce();

        var context = new ApprovalContext(
            SessionId: sessionId,
            UserId: userId,
            Action: action,
            ToolUseId: toolUseId,
            Timestamp: timestamp,
            Nonce: nonce);

        _approvalContexts[approvalId] = context;

        return approvalId;
    }

    /// <summary>
    /// Handles approval timeout by auto-denying and editing the message.
    /// Also calls the orchestrator's deny method to ensure consistent state.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Background task must not throw")]
    private async Task HandleApprovalTimeoutAsync(
        Message message,
        ManagedSession session,
        AgentEvent approvalEvent)
    {
        try
        {
            await Task.Delay(_callbackTimeout).ConfigureAwait(false);

            // Check if session still exists
            var currentSession = _sessionManager.GetSession(session.SessionId);
            if (currentSession == null)
            {
                return; // Session terminated, no need to handle timeout
            }

            // Call orchestrator deny method based on event type
            try
            {
                switch (approvalEvent)
                {
                    case HumanApprovalRequired toolApproval:
                        currentSession.Orchestrator.DenyTool(toolApproval.ToolUseId);
                        break;
                    case DirectoryAccessRequested:
                        currentSession.Orchestrator.DenyDirectoryAccess();
                        break;
                    case CommandApprovalRequested:
                        currentSession.Orchestrator.DenyCommand();
                        break;
                }
            }
            catch (Exception ex)
            {
                LogTimeoutDenyError(ex, session.SessionId);
            }

            // Edit message to show timeout
            await _botClient.EditMessageText(
                message.Chat.Id,
                message.MessageId,
                $"{message.Text}\n\n⏰ <b>Approval timed out — auto-denied</b>",
                parseMode: ParseMode.Html,
                cancellationToken: CancellationToken.None).ConfigureAwait(false);

            LogApprovalTimeout(session.SessionId);
        }
        catch (OperationCanceledException)
        {
            // Expected when approval is provided before timeout
        }
        catch (Exception ex)
        {
            LogTimeoutHandlingError(ex, session.SessionId);
        }
    }
}
