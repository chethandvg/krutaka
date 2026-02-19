using Telegram.Bot.Types;

namespace Krutaka.Telegram;

/// <summary>
/// Routes Telegram updates to appropriate command handlers with input sanitization and admin gating.
/// </summary>
public interface ITelegramCommandRouter
{
    /// <summary>
    /// Routes a validated Telegram update to the appropriate command handler.
    /// </summary>
    /// <param name="update">The Telegram update to route.</param>
    /// <param name="authResult">The authentication result from ITelegramAuthGuard.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// A <see cref="CommandRouteResult"/> containing the parsed command, arguments,
    /// sanitized input, admin-only flag, and routing success status.
    /// </returns>
    Task<CommandRouteResult> RouteAsync(
        Update update,
        AuthResult authResult,
        CancellationToken cancellationToken);
}
