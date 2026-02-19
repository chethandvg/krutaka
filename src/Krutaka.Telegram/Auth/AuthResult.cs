using Krutaka.Core;

namespace Krutaka.Telegram;

/// <summary>
/// Result of a Telegram authentication validation check.
/// </summary>
/// <param name="IsValid">Whether the authentication was successful.</param>
/// <param name="DeniedReason">Reason for denial (null if allowed).</param>
/// <param name="UserRole">The user's role (User or Admin).</param>
/// <param name="UserId">The Telegram user ID.</param>
/// <param name="ChatId">The Telegram chat ID.</param>
public sealed record AuthResult(
    bool IsValid,
    string? DeniedReason,
    TelegramUserRole UserRole,
    long UserId,
    long ChatId)
{
    /// <summary>
    /// Creates an invalid authentication result.
    /// </summary>
    /// <param name="reason">The reason for denial.</param>
    /// <param name="userId">The Telegram user ID (may be 0 if not available).</param>
    /// <param name="chatId">The Telegram chat ID (may be 0 if not available).</param>
    /// <returns>An invalid AuthResult with the specified denial reason.</returns>
    public static AuthResult Invalid(string reason, long userId = 0, long chatId = 0)
    {
        return new AuthResult(false, reason, TelegramUserRole.User, userId, chatId);
    }

    /// <summary>
    /// Creates a valid authentication result.
    /// </summary>
    /// <param name="userId">The Telegram user ID.</param>
    /// <param name="chatId">The Telegram chat ID.</param>
    /// <param name="role">The user's role.</param>
    /// <returns>A valid AuthResult with the specified user and role.</returns>
    public static AuthResult Valid(long userId, long chatId, TelegramUserRole role)
    {
        return new AuthResult(true, null, role, userId, chatId);
    }
}
