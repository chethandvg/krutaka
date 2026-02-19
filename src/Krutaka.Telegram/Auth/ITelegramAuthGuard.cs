using Telegram.Bot.Types;

namespace Krutaka.Telegram;

/// <summary>
/// Guards Telegram bot access by validating user authentication, rate limits,
/// lockout status, anti-replay, and input validation before processing updates.
/// </summary>
public interface ITelegramAuthGuard
{
    /// <summary>
    /// Validates a Telegram update against all security checks.
    /// </summary>
    /// <param name="update">The Telegram update to validate.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// An <see cref="AuthResult"/> indicating whether the update is valid.
    /// If invalid, the result contains the denial reason.
    /// Unknown users are silently dropped (no Telegram reply sent).
    /// </returns>
    Task<AuthResult> ValidateAsync(Update update, CancellationToken cancellationToken);
}
