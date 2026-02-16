using Krutaka.Core;
using Telegram.Bot.Types;

namespace Krutaka.Telegram;

/// <summary>
/// Handles Telegram inline keyboard approval flow for human-in-the-loop approvals.
/// Sends approval panels with HMAC-signed callbacks and processes button presses.
/// </summary>
public interface ITelegramApprovalHandler
{
    /// <summary>
    /// Sends an approval request message with inline keyboard buttons to Telegram.
    /// </summary>
    /// <param name="chatId">The Telegram chat ID to send the approval panel to.</param>
    /// <param name="approvalEvent">The agent event requiring approval (HumanApprovalRequired, DirectoryAccessRequested, or CommandApprovalRequested).</param>
    /// <param name="session">The managed session for accessing the orchestrator.</param>
    /// <param name="userId">The Telegram user ID authorized to respond to this approval.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The sent Telegram message.</returns>
    Task<Message> SendApprovalRequestAsync(
        long chatId,
        AgentEvent approvalEvent,
        ManagedSession session,
        long userId,
        CancellationToken cancellationToken);

    /// <summary>
    /// Handles an inline keyboard callback button press.
    /// Verifies HMAC signature, checks user authorization, prevents replay attacks,
    /// and routes to the appropriate orchestrator approval method.
    /// </summary>
    /// <param name="callback">The Telegram callback query from the button press.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task HandleCallbackAsync(
        CallbackQuery callback,
        CancellationToken cancellationToken);
}
