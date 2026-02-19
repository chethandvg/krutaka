namespace Krutaka.Core;

/// <summary>
/// Configuration for an individual Telegram user authorized to use the bot.
/// </summary>
/// <param name="UserId">The Telegram user ID (stable numeric identifier).</param>
/// <param name="Role">The user's role (default: User).</param>
/// <param name="ProjectPath">Optional per-user project directory path. If null, a default path is used.</param>
public record TelegramUserConfig(
    long UserId,
    TelegramUserRole Role = TelegramUserRole.User,
    string? ProjectPath = null);
